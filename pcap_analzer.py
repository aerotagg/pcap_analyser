import subprocess
import pandas as pd
import os
import argparse
import hashlib
import glob
import shutil
import concurrent.futures

def load_fields_from_config(config_path):
    if not os.path.exists(config_path):
        print(f"[!] Config file not found: {config_path}")
        return None
    with open(config_path, 'r') as file:
        return [line.strip() for line in file if line.strip() and not line.startswith('#')]

# --- FEATURE 4: AUTOMATED FILE CARVING & HASHING ---
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
                # 1. Read the file and calculate the hash
                with open(filepath, "rb") as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                # 2. Rename the file to its hash to prevent Windows errors later
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
                # If Windows completely blocks access (Errno 22), log it and move on!
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
    dns_anomalies, beacons, ja3_stats = pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    
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
        
    # --- FEATURE 2: JA3 FINGERPRINTING ---
    if 'tls.handshake.ja3' in df.columns:
        # Filter out empty JA3 strings, group them, and count
        ja3_data = df.dropna(subset=['tls.handshake.ja3'])
        if not ja3_data.empty:
            ja3_stats = ja3_data.groupby(['Src IP', 'tls.handshake.ja3']).size().reset_index(name='Occurrences')
            ja3_stats = ja3_stats.sort_values(by='Occurrences', ascending=False)
            
    return dns_anomalies, beacons, ja3_stats

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

def process_and_split_data(raw_dataframe, final_csv_path, summary_excel_path, carved_files_df):
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
    
    dns_anomalies, beacons, ja3_stats = generate_incident_summary(df)
    
    print(f"[*] Saving raw data to {final_csv_path}...")
    df.to_csv(final_csv_path, index=False)
    
    print(f"[*] Generating summaries to {summary_excel_path}...")

    os_fingerprint_df = infer_os_from_ttl_window(df)

    with pd.ExcelWriter(summary_excel_path, engine='openpyxl') as writer:
        
        # Incident Summary Tabs
        if not beacons.empty: beacons.to_excel(writer, sheet_name='🚨 Suspected Beacons', index=False)
        if not dns_anomalies.empty: dns_anomalies.to_excel(writer, sheet_name='🚨 DNS Anomalies', index=False)
        if not ja3_stats.empty: ja3_stats.to_excel(writer, sheet_name='🔍 JA3 TLS Fingerprints', index=False)
        
        # Carved Files Tab
        if not carved_files_df.empty: 
            carved_files_df.to_excel(writer, sheet_name='📁 Extracted Files', index=False)
        else:
            pd.DataFrame({'Status': ['No HTTP/SMB files extracted.']}).to_excel(writer, sheet_name='📁 Extracted Files', index=False)

        # Standard Network Context Tabs
        if 'Src IP' in df.columns:
            df['Src IP'].value_counts().reset_index(name='Packet Count').rename(columns={'Src IP': 'Source IP'}).to_excel(writer, sheet_name='Top Talkers', index=False)
            if 'Dst IP' in df.columns:
                df.groupby(['Src IP', 'Dst IP']).size().reset_index(name='Packet Count').sort_values('Packet Count', ascending=False).to_excel(writer, sheet_name='Top Conversations', index=False)
                
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
    
    input_pcap = args.input
    final_raw_csv = "Raw_Traffic_Data.csv"
    
    if not os.path.exists(input_pcap):
        print(f"[!] Error: The file {input_pcap} does not exist.")
        exit()

    tshark_fields = load_fields_from_config(args.config)
    if not tshark_fields: exit()
    
    # 1. Carve and Hash Files First
    carved_files_df = carve_and_hash_files(input_pcap)
    
    # 2. Check File Size for Chunking (Threshold: 200MB)
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
        
        # Spin up parallel processes based on your CPU cores
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

    # 3. Merge DataFrames and Generate Reports
    if processed_csvs:
        print(f"[*] Merging {len(processed_csvs)} data segments...")
        # Read all chunks into Pandas and concatenate them
        df_list = [pd.read_csv(csv_file, names=tshark_fields, low_memory=False, on_bad_lines='skip') for csv_file in processed_csvs]
        master_df = pd.concat(df_list, ignore_index=True)
        
        process_and_split_data(master_df, final_raw_csv, args.output, carved_files_df)
        
        # 4. Cleanup temporary files and chunk directories
        for csv_file in processed_csvs:
            if os.path.exists(csv_file): os.remove(csv_file)
        if os.path.exists("pcap_chunks"):
            shutil.rmtree("pcap_chunks")