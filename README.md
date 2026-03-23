# 🦈 PCAP Analyzer & Threat Hunting Toolkit

An automated, multiprocessing-enabled network traffic analysis tool built in Python. This utility leverages `tshark` and `pandas` to ingest massive PCAP files, extract critical network telemetry, and run threat-hunting heuristics to detect malware behavior like C2 beaconing and DGA (Domain Generation Algorithm) activity.

Unlike standard parsers, this tool is designed for scale and safety, featuring automated PCAP chunking for gigabyte-sized captures and defensive file carving for malicious payloads.

## ✨ Key Features

* **Advanced Threat Hunting Heuristics:**
  * **C2 Beacon Detection:** Mathematically analyzes conversation timing and packet sizes to flag highly consistent, automated beaconing behavior.
  * **DGA / DNS Anomaly Detection:** Flags internal hosts generating excessive `NXDomain` responses, a common indicator of malware searching for command-and-control servers.
* **TLS Fingerprinting (JA3):** Extracts JA3 hashes from TLS handshakes, allowing analysts to identify malicious scripts or non-standard clients hiding inside encrypted HTTPS traffic.
* **Automated & Safe File Carving:** Silently extracts files transferred over HTTP and SMB. To prevent accidental execution and bypass Windows filesystem errors with malicious URIs, extracted files are automatically hashed (SHA256) and safely renamed to their hash with a `.bin` extension.
* **Massive PCAP Handling:** Automatically detects files larger than 200MB. It utilizes Wireshark's `editcap` to split the file into smaller chunks and processes them simultaneously across multiple CPU cores using Python's `concurrent.futures`.
* **Dynamic Configuration:** `tshark` extraction fields are managed via an external `fields.txt` file, allowing users to add or remove parsed fields without editing the Python source code.

## 🛠️ Prerequisites

This tool is currently configured for **Windows** environments.

1. **Python 3.8+**
2. **Wireshark:** Must be installed in the default directory (`C:\Program Files\Wireshark\`). The script relies on `tshark.exe` and `editcap.exe`.
3. **Python Libraries:**
   ```bash
   pip install pandas openpyxl

## 🚀 Installation & Setup
Ensure you have a fields.txt file in the same directory as the script. This file dictates exactly what data tshark will extract.

*Example fields.txt:*
frame.time_epoch
eth.src
eth.dst
ip.src
ip.dst
ip.len
tcp.srcport
udp.srcport
tcp.dstport
udp.dstport
_ws.col.Protocol
http.host
tls.handshake.extensions_server_name
dns.qry.name
dns.flags.rcode
tcp.flags.syn
tcp.flags.ack
tcp.flags.reset
tls.handshake.ja3
_ws.col.Info

## 💻 Usage
Run the script from the command line, providing the target PCAP file using the -i flag.

*Basic Analysis:*
python pcap_analyzer.py -i incident_capture.pcap

*Advanced Usage (Custom Config & Output Name):*
python pcap_analyzer.py -i incident_capture.pcap -c custom_fields.txt -o Client_Report_Q3.xlsx
Command Line Arguments
-i, --input: (Required) Path to the input .pcap or .pcapng file.

-c, --config: Path to the tshark fields text file (Default: fields.txt).

-o, --output: Name of the generated Excel summary report (Default: Traffic_Summaries.xlsx).

## 📊 Understanding the Output
The tool generates three primary artifacts:
**Raw_Traffic_Data.csv:** The fully cleaned, merged, and flattened dataset containing every parsed packet. Useful for manual grep searching or ingesting into a SIEM.
**/quarantine/ Directory:** Contains any files carved from the network traffic, safely renamed to <SHA256-hash>.bin.
**Traffic_Summaries.xlsx:** A multi-tabbed Excel report designed for client presentations and quick analyst review.

*    **🚨 Suspected Beacons:** Hosts exhibiting strict, repetitive timing intervals.
*    **🚨 DNS Anomalies:** Hosts with high counts of failed DNS queries.
*    **🔍 JA3 TLS Fingerprints:** Aggregated JA3 hashes for threat intel cross-referencing.
*    **📁 Extracted Files:** A log of carved files, their original malicious names, and their safe local hashes.
*    **Top Talkers & Conversations:** Standard network baselining metrics.

## ⚠️ Quirks & Limitations
Hardcoded Paths: The script currently expects tshark.exe and editcap.exe to be located in C:\Program Files\Wireshark\. If you are running this on Linux, macOS, or a custom Windows directory, you must update the tshark_path and editcap_path variables in the code.

Malware URIs: Threat actors often use URL parameters or invalid characters in filenames (e.g., payload.exe?t=123). The script handles this defensively by catching Errno 22 (Invalid argument) exceptions, logging the failure to the Excel report, and skipping the unreadable file to prevent script crashes.

Memory Intensive: While the chunking and multiprocessing feature prevents RAM exhaustion on massive files, it is highly CPU-intensive. Running a 2GB+ PCAP will pin all available CPU cores to 100% until the chunking is complete.