import subprocess
import pandas as pd
import os
import argparse
import hashlib
import glob
import shutil
import concurrent.futures
import zipfile 
from openpyxl.styles import Font




def unzip_pcap(zipped_pcap):
    """Extracts the ZIP file containing the PCAP file."""

    if not os.path.exists(zipped_pcap):
        raise FileNotFoundError(f"ZIP file not found: {zipped_pcap}")

    # Get the directory containing the zipped pcap
    extract_to = os.path.dirname(zipped_pcap)

    # Extract pcap
    with zipfile.ZipFile(zipped_pcap, 'r') as zip_ref:
        zip_ref.extractall(extract_to)

        # Get the name of the first file inside ZIP (the pcap file)
        extracted_pcap = zip_ref.namelist()[0]

    return os.path.join(extract_to, extracted_pcap)

def load_fields_from_config(config_path): 
    if not os.path.exists(config_path):
        print(f"[!] Config file not found: {config_path}")
        return None
    with open(config_path, 'r') as file:
        return [line.strip() for line in file if line.strip() and not line.startswith('#')]

# --- AUTOMATED FILE CARVING & HASHING ---
def carve_and_hash_files(pcap_file, quarantine_dir="quarantine"):
    """Extracts files from HTTP/SMB streams and calculates their SHA256 hashes safely."""
    print(f"[*] Carving HTTP/SMB objects into '{quarantine_dir}' folder...")
    os.makedirs(quarantine_dir, exist_ok=True)
    
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    
    # Run tshark silently (-q) to just export objects
    cmd = [
        tshark_path, "-r", pcap_file, "-q",
        "--export-objects", f"http,{quarantine_dir}",
        "--export-objects", f"smb,{quarantine_dir}"
    ]
    
    subprocess.run(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    
    extracted_files = []
    
    # Safely iterate through the exported files
    for root, _, files in os.walk(quarantine_dir):
        for file in files:
            filepath = os.path.join(root, file)
            
            try:
                # Read the file and calculate the hash
                with open(filepath, "rb") as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                # Rename the file to its hash to prevent Windows errors later
                safe_filename = f"{file_hash}.bin"
                safe_filepath = os.path.join(root, safe_filename)
                
                # Only rename if it hasn't been renamed already (prevents duplicate collisions)
                if not os.path.exists(safe_filepath) and filepath != safe_filepath:
                    os.rename(filepath, safe_filepath)
                else:
                    safe_filename = file
                    safe_filepath = filepath
                    
                extracted_files.append({
                    "Original Malicious Name": file,
                    "Safe Local Name": safe_filename,
                    "SHA256 Hash": file_hash,
                    "Status": "Success"
                })
                
            except Exception as e:
                # If Windows completely blocks access (Errno 22), log it and move on
                print(f"    [!] Skipping unreadable file '{file}': {e}")
                extracted_files.append({
                    "Original Malicious Name": file,
                    "Safe Local Name": "N/A",
                    "SHA256 Hash": "ERROR",
                    "Status": f"Failed to read: {e}"
                })
            
    return pd.DataFrame(extracted_files)

def extract_pcap_to_temp_csv(pcap_file, temp_csv_path, fields_list):
    """Core tshark extraction engine (Now acts as the worker for multiprocessing)."""
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe" 
    
    tshark_cmd = [
        tshark_path, "-r", pcap_file, "-T", "fields",
        "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"
    ]
    
    for field in fields_list:
        tshark_cmd.extend(["-e", field])

    with open(temp_csv_path, "w", encoding="utf-8") as temp_file:
        try:
            subprocess.run(tshark_cmd, stdout=temp_file, text=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Tshark error on {pcap_file}: {e.stderr}")
            return False

# --- MULTIPROCESSING WORKER WRAPPER ---
def process_chunk_task(chunk_file, temp_csv, fields):
    """Wrapper function to allow concurrent execution."""
    if extract_pcap_to_temp_csv(chunk_file, temp_csv, fields):
        return temp_csv
    return None

def generate_incident_summary(df):
    """Analyzes the network traffic for malicious behavior safely."""
    print("[*] Running Threat Hunting heuristics...")
    dns_anomalies, beacons, ja3_stats, cleartext_df, port_scans = pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    
    if 'dns.flags.rcode' in df.columns and 'Src IP' in df.columns:
        nxdomains = df[df['dns.flags.rcode'].astype(str).str.contains('3', na=False)]
        dns_anomalies = nxdomains.groupby('Src IP').size().reset_index(name='NXDomain_Count')
        dns_anomalies = dns_anomalies[dns_anomalies['NXDomain_Count'] > 20].sort_values(by='NXDomain_Count', ascending=False)
    
    if all(col in df.columns for col in ['Src IP', 'Dst IP', 'Dst Port', 'ip.len', 'Time']):
        df_sorted = df.sort_values(by=['Src IP', 'Dst IP', 'Time'])
        df_sorted['Time_Delta'] = df_sorted.groupby(['Src IP', 'Dst IP'])['Time'].diff().dt.total_seconds()
        
        beacon_stats = df_sorted.groupby(['Src IP', 'Dst IP', 'Dst Port', 'ip.len']).agg(
            Packet_Count=('Time', 'count'),
            Mean_Interval=('Time_Delta', 'mean'),
            StdDev_Interval=('Time_Delta', 'std')
        ).reset_index()
        
        beacons = beacon_stats[
            (beacon_stats['Packet_Count'] > 15) & 
            (beacon_stats['StdDev_Interval'] < 2.0) & 
            (beacon_stats['Mean_Interval'] > 5.0)
        ].sort_values(by='Packet_Count', ascending=False)
        
    if 'tls.handshake.ja3' in df.columns:
        ja3_data = df.dropna(subset=['tls.handshake.ja3'])
        if not ja3_data.empty:
            ja3_stats = ja3_data.groupby(['Src IP', 'tls.handshake.ja3']).size().reset_index(name='Occurrences')
            ja3_stats = ja3_stats.sort_values(by='Occurrences', ascending=False)

    if 'Dst Port' in df.columns:
        df['Dst Port_Num'] = pd.to_numeric(df['Dst Port'], errors='coerce')
        cleartext_traffic = df[df['Dst Port_Num'].isin([21, 23, 80])]
        
        if not cleartext_traffic.empty:
            cleartext_df = cleartext_traffic.groupby(['Src IP', 'Dst IP', 'Dst Port_Num', 'Protocol']).size().reset_index(name='Connection Count')
            cleartext_df = cleartext_df.sort_values(by='Connection Count', ascending=False)
            cleartext_df.rename(columns={'Dst Port_Num': 'Port'}, inplace=True)
            
    # ==========================================
    # RECONNAISSANCE & PORT SCANNING
    # ==========================================
    if 'tcp.flags.syn' in df.columns and 'Src IP' in df.columns and 'Dst Port' in df.columns:
        # Find all packets where the SYN flag is set to 1
        syn_packets = df[df['tcp.flags.syn'].astype(str).str.contains('1', na=False)]
        
        if not syn_packets.empty:
            # Group by Source IP and count how many UNIQUE ports they are targeting
            scan_stats = syn_packets.groupby('Src IP').agg(
                Total_SYN_Packets=('tcp.flags.syn', 'count'),
                Unique_Ports_Targeted=('Dst Port', 'nunique')
            ).reset_index()
            
            # Flag any IP targeting more than 20 unique ports.
            port_scans = scan_stats[scan_stats['Unique_Ports_Targeted'] > 20].sort_values(by='Unique_Ports_Targeted', ascending=False)
            
    return dns_anomalies, beacons, ja3_stats, cleartext_df, port_scans

def infer_os_from_ttl_window(df):
    """Basic OS fingerprinting using TTL value."""
    
    os_fingerprints = []

    if not all(col in df.columns for col in ['Src IP', 'TTL']):
        return pd.DataFrame()

    grouped = df.groupby('Src IP').agg({
        'TTL': 'median'
    }).reset_index()

    for _, row in grouped.iterrows():
        ttl = row['TTL']
        os_guess = "Unknown"

        # Normalize TTL (estimate original TTL)
        if ttl <= 64:
            base_ttl = 64
            os_guess = "Linux"
        elif ttl <= 128:
            base_ttl = 128
            os_guess = "Windows"
        else:
            base_ttl = 255
            os_guess = "Network Device (Cisco/Unix)"            

        os_fingerprints.append({
            "Src IP": row['Src IP'],
            "Observed TTL": ttl,
            "Estimated Base TTL": base_ttl,
            "Likely OS": os_guess
        })

    return pd.DataFrame(os_fingerprints)

def process_and_split_data(raw_dataframe, final_csv_path, summary_excel_path, carved_files_df, pcap_filename):
    """Cleans the massive combined DataFrame and generates reports."""
    print("[*] Loading and cleaning combined data with Pandas...")
    df = raw_dataframe
    
    if 'frame.time_epoch' in df.columns:
        df['Time'] = pd.to_datetime(df['frame.time_epoch'], unit='s', errors='coerce')
    if 'tcp.srcport' in df.columns and 'udp.srcport' in df.columns:
        df['Src Port'] = df['tcp.srcport'].fillna(df['udp.srcport'])
    if 'tcp.dstport' in df.columns and 'udp.dstport' in df.columns:
        df['Dst Port'] = df['tcp.dstport'].fillna(df['udp.dstport'])
    if 'http.host' in df.columns and 'tls.handshake.extensions_server_name' in df.columns:
        df['Host'] = df['http.host'].fillna(df['tls.handshake.extensions_server_name'])
        
    if 'ip.len' in df.columns:
        df['ip.len'] = pd.to_numeric(df['ip.len'], errors='coerce').fillna(0)
        
    # Normalize TCP window size 
    if 'tcp.window_size_value' in df.columns:
        df['TCP Window Size'] = df['tcp.window_size_value']
    elif 'tcp.window_size' in df.columns:
        df['TCP Window Size'] = df['tcp.window_size']
    # Rename TTL
    if 'ip.ttl' in df.columns:
        df = df.rename(columns={'ip.ttl': 'TTL'})

    rename_map = {
        'ip.src': 'Src IP', 'ip.dst': 'Dst IP',
        'eth.src': 'Src MAC', 'eth.dst': 'Dst MAC',
        '_ws.col.Protocol': 'Protocol', '_ws.col.Info': 'Info'
    }
    df = df.rename(columns=rename_map)
    
    # Unpack all 5 threat hunting dataframes
    dns_anomalies, beacons, ja3_stats, cleartext_df, port_scans = generate_incident_summary(df)
    
    print(f"[*] Saving raw data to {final_csv_path}...")
    df.to_csv(final_csv_path, index=False)
    
    os_fingerprint_df = infer_os_from_ttl_window(df)

    print(f"[*] Generating summaries & timeline dashboard to {summary_excel_path}...")
    with pd.ExcelWriter(summary_excel_path, engine='openpyxl') as writer:
        
        # ==========================================
        # CHRONOLOGICAL ATTACK TIMELINE
        # ==========================================
        timeline_events = []

        if 'Time' in df.columns and not df['Time'].isna().all():
            timeline_events.append({"Timestamp": df['Time'].min(), "Event Type": "🟢 Network Capture Started"})
            timeline_events.append({"Timestamp": df['Time'].max(), "Event Type": "🛑 Network Capture Ended"})
        
        # Cleartext Protocol Usage to Timeline
        if not cleartext_df.empty:
            first_clear = df[pd.to_numeric(df['Dst Port'], errors='coerce').isin([21, 23, 80])]['Time'].min()
            timeline_events.append({"Timestamp": first_clear, "Event Type": "⚠️ First Insecure Cleartext Transmission"})
        
        # DGA/NXDomain Activity to Timeline
        if not dns_anomalies.empty:
            bad_ips = dns_anomalies['Src IP'].tolist()
            first_dga = df[(df['Src IP'].isin(bad_ips)) & (df['dns.flags.rcode'].astype(str).str.contains('3', na=False))]['Time'].min()
            timeline_events.append({"Timestamp": first_dga, "Event Type": "🚨 First Suspicious DGA/NXDomain Activity"})

        # C2 Beaconing to Timeline 
        if not beacons.empty:
            beacon_ips = beacons['Src IP'].tolist()
            first_beacon = df[df['Src IP'].isin(beacon_ips)]['Time'].min()
            timeline_events.append({"Timestamp": first_beacon, "Event Type": "🚨 First Suspected C2 Beaconing Detected"})
            
        # Port Scanning to Timeline
        if not port_scans.empty:
            scanner_ips = port_scans['Src IP'].tolist()
            first_scan = df[(df['Src IP'].isin(scanner_ips)) & (df['tcp.flags.syn'].astype(str).str.contains('1', na=False))]['Time'].min()
            timeline_events.append({"Timestamp": first_scan, "Event Type": "🕵️ First Port Scan Sweep Detected"})
            
        timeline_df = pd.DataFrame(timeline_events).dropna().sort_values(by="Timestamp")
        timeline_df['Timestamp'] = timeline_df['Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')

        # ==========================================
        # DYNAMIC DASHBOARD GENERATION
        # ==========================================
        capture_duration = df['Time'].max() - df['Time'].min() if 'Time' in df.columns else "Unknown"
        
        # Start with the baseline metrics that apply to EVERY PCAP
        overview_data = [
            {"Metric": "PCAP File Analyzed", "Value": pcap_filename},
            {"Metric": "Total Packets Processed", "Value": f"{len(df):,}"},
            {"Metric": "Total Capture Duration", "Value": str(capture_duration)},
            {"Metric": "Unique JA3 Fingerprints", "Value": len(ja3_stats)},
            {"Metric": "Files Extracted", "Value": len(carved_files_df)}
        ]
        
        # Dynamically inject Threat Metrics ONLY if they were found
        if len(beacons) > 0: overview_data.append({"Metric": "🚨 Suspected C2 Beacons", "Value": len(beacons)})
        if len(dns_anomalies) > 0: overview_data.append({"Metric": "🚨 DNS Anomalies (DGA)", "Value": len(dns_anomalies)})
        if len(port_scans) > 0: overview_data.append({"Metric": "🕵️ Port Scans Detected", "Value": len(port_scans)})
        if len(cleartext_df) > 0: overview_data.append({"Metric": "⚠️ Cleartext Protocol Uses", "Value": len(cleartext_df)})
            
        overview_df = pd.DataFrame(overview_data)
        
        # Write Overview Table 
        overview_df.to_excel(writer, sheet_name='📊 Executive Overview', index=False, startrow=2, startcol=1)
        
        # Write Timeline Table 
        timeline_start_row = len(overview_df) + 6
        timeline_df.to_excel(writer, sheet_name='📊 Executive Overview', index=False, startrow=timeline_start_row, startcol=1)
        
        # ------------------------------------------
        # OPENPYXL STYLING
        # ------------------------------------------
        worksheet = writer.sheets['📊 Executive Overview']
        worksheet.cell(row=2, column=2, value="Incident Overview Dashboard").font = Font(size=16, bold=True)
        worksheet.cell(row=timeline_start_row, column=2, value="Chronological Attack Timeline").font = Font(size=14, bold=True)
        worksheet.column_dimensions['B'].width = 30
        worksheet.column_dimensions['C'].width = 45

        # ==========================================
        # WRITING THE STANDARD REPORT TABS
        # ==========================================
        if not port_scans.empty: port_scans.to_excel(writer, sheet_name='Recon & Scanning', index=False)
        
        if not beacons.empty: beacons.to_excel(writer, sheet_name='🚨 Suspected Beacons', index=False)
        if not dns_anomalies.empty: dns_anomalies.to_excel(writer, sheet_name='🚨 DNS Anomalies', index=False)
        if not ja3_stats.empty: ja3_stats.to_excel(writer, sheet_name='JA3 TLS Fingerprints', index=False)
        
        if not cleartext_df.empty: 
            cleartext_df.to_excel(writer, sheet_name='⚠️ Endpoints', index=False)
            
        if not carved_files_df.empty: 
            carved_files_df.to_excel(writer, sheet_name='📁 Extracted Files', index=False)

        if 'Src IP' in df.columns and 'Dst IP' in df.columns and 'ip.len' in df.columns:
            conversations = df.groupby(['Src IP', 'Dst IP']).agg(
                Packet_Count=('Src IP', 'count'), Total_Bytes=('ip.len', 'sum'),
                Start_Time=('Time', 'min'), End_Time=('Time', 'max')
            ).reset_index()
            
            raw_duration = conversations['End_Time'] - conversations['Start_Time']
            conversations['Duration (Mins)'] = (raw_duration.dt.total_seconds() / 60).round(2)
            conversations['Total_KB'] = (conversations['Total_Bytes'] / 1024).round(2)
            
            cols = ['Src IP', 'Dst IP', 'Packet_Count', 'Total_KB', 'Duration (Mins)', 'Start_Time', 'End_Time']
            conversations = conversations[cols].sort_values('Total_KB', ascending=False)
            conversations.to_excel(writer, sheet_name='Top Conversations', index=False)
                
        if 'Host' in df.columns:
            df.dropna(subset=['Host'])['Host'].value_counts().reset_index(name='Occurrence Count').rename(columns={'Host': 'Resolved Host / Domain'}).to_excel(writer, sheet_name='Resolved Hosts', index=False)

        
        if not os_fingerprint_df.empty: 
            os_fingerprint_df.to_excel(writer, sheet_name='OS Fingerprinting', index=False)
            
    print("[+] All reports generated successfully!")

# --- MAIN EXECUTION W/ MULTIPROCESSING ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PCAP Analysis and Threat Hunting Tool")
    parser.add_argument("-i", "--input", required=True, help="Path to the input PCAP file")
    parser.add_argument("-c", "--config", default="fields.txt", help="Path to tshark fields")
    parser.add_argument("-o", "--output", default="Traffic_Summaries.xlsx", help="Output Excel file")
    args = parser.parse_args()
    
    input_pcap = unzip_pcap(args.input)

    final_raw_csv = "Raw_Traffic_Data.csv"
    
    if not os.path.exists(input_pcap):
        print(f"[!] Error: The file {input_pcap} does not exist.")
        exit()

    tshark_fields = load_fields_from_config(args.config)
    if not tshark_fields: exit()
    
    # Carve and Hash Files first
    carved_files_df = carve_and_hash_files(input_pcap)
    
    # Check File Size for Chunking (Threshold: 200MB)
    file_size_mb = os.path.getsize(input_pcap) / (1024 * 1024)
    processed_csvs = []
    
    if file_size_mb > 200:
        print(f"[*] Massive file detected ({file_size_mb:.1f} MB). Engaging Editcap Chunking & Multiprocessing...")
        chunk_dir = "pcap_chunks"
        os.makedirs(chunk_dir, exist_ok=True)
        
        # Use editcap to split into chunks of 500,000 packets
        editcap_path = r"C:\Program Files\Wireshark\editcap.exe"
        chunk_base = os.path.join(chunk_dir, "chunk.pcap")
        
        print(f"[*] Splitting PCAP... (This may take a moment)")
        subprocess.run([editcap_path, "-c", "500000", input_pcap, chunk_base], check=True)
        
        chunk_files = glob.glob(os.path.join(chunk_dir, "chunk*.pcap"))
        print(f"[*] PCAP split into {len(chunk_files)} chunks. Processing simultaneously across CPU cores...")
        
        # Spin up parallel processes based on available CPU cores
        with concurrent.futures.ProcessPoolExecutor() as executor:
            futures = []
            for i, chunk in enumerate(chunk_files):
                chunk_csv = f"temp_chunk_{i}.csv"
                futures.append(executor.submit(process_chunk_task, chunk, chunk_csv, tshark_fields))
            
            # Gather completed CSVs
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result: processed_csvs.append(result)
                
    else:
        # Standard Single Process for smaller files
        print(f"[*] Standard file detected ({file_size_mb:.1f} MB). Processing single thread...")
        temp_csv = "temp_tshark_dump.csv"
        if extract_pcap_to_temp_csv(input_pcap, temp_csv, tshark_fields):
            processed_csvs.append(temp_csv)

    # Merge DataFrames and Generate Reports
    if processed_csvs:
        print(f"[*] Merging {len(processed_csvs)} data segments...")
        # Read all chunks into Pandas and concatenate them
        df_list = [pd.read_csv(csv_file, names=tshark_fields, low_memory=False, on_bad_lines='skip') for csv_file in processed_csvs]
        master_df = pd.concat(df_list, ignore_index=True)
        
        process_and_split_data(master_df, final_raw_csv, args.output, carved_files_df, input_pcap)
        
        # Cleanup temporary files and chunk directories
        for csv_file in processed_csvs:
            if os.path.exists(csv_file): os.remove(csv_file)
        if os.path.exists("pcap_chunks"):
            shutil.rmtree("pcap_chunks")