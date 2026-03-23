# SIEM Tool - Security Information and Event Management

A comprehensive SIEM solution with real-time monitoring, threat detection, and beautiful dashboard.

## Features

### 📊 Dashboard
- Real-time statistics cards
- Event timeline charts
- Alert severity distribution
- Top processes monitoring
- Recent alerts table
- Active threats section

### 📝 System Logs
- Sortable columns
- Process search filtering
- Date range filtering
- Pagination
- Color-coded metrics
- Clickable event details

### 🌐 Network Logs
- Source/Destination IP filtering
- Port filtering
- Protocol filtering
- Suspicious port highlighting
- Protocol and status badges
- Network event investigation

### 🚨 Alerts
- Severity filtering
- Status filtering
- MITRE ATT&CK techniques
- Confirm/False positive actions
- Alert statistics

### 🔍 Investigation
- Full event details
- Related events timeline
- Similar alerts
- Complete command line display

### 🛡️ Detection Rules
- **Brute Force Detection** - SSH, RDP, FTP, Web
- **Malware IOCs** - Ransomware, Trojans, RATs, Cryptominers
- **Suspicious Processes** - Temp directories, high resource usage
- **Suspicious PowerShell** - Encoded commands, download strings
- **Port Scan Detection** - Nmap patterns, SYN scans
- **Malicious IP Detection** - 9+ known malicious IPs
- **Tool Detection** - Nmap, Hydra
- **EICAR Test** - Security testing

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Quick Install

**Linux/Mac:**
```bash
chmod +x install.sh
./install.sh