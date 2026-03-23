import json
import os
import time
import random
import datetime
import psutil
import socket
import ipaddress
from pathlib import Path
from datetime import datetime as dt
import threading

# Try to import Windows Event Log modules (will work only on Windows)
try:
    import win32evtlog
    import win32evtlogutil
    import win32security
    import pywintypes
    WINDOWS_EVTLOG_AVAILABLE = True
except ImportError:
    WINDOWS_EVTLOG_AVAILABLE = False
    print("⚠️  pywin32 not installed. Windows Event Log monitoring disabled.")
    print("   To enable real Windows log monitoring: pip install pywin32")

class SystemCollector:
    def __init__(self):
        # Get the directory where this script is located
        self.base_dir = Path(__file__).parent.parent
        self.logs_dir = self.base_dir / 'Logs'
        self.telemetry_file = self.logs_dir / 'telemetry.json'
        self.network_file = self.logs_dir / 'network.json'
        self.auth_file = self.logs_dir / 'auth.json'
        
        # Create Logs directory if it doesn't exist
        self.logs_dir.mkdir(exist_ok=True)
        
        # Initialize JSON files if they don't exist
        self.init_json_files()
        
        # Event ID counter (will be loaded from files)
        self.event_id = self.get_max_event_id()
        
        # Track real-time brute force attempts
        self.real_time_attempts = {}
        
        # Sample processes for telemetry generation (fallback when no real data)
        self.processes = [
            {"name": "explorer.exe", "cpu": [2, 15], "mem": [50, 200], "cmd": "C:\\Windows\\explorer.exe"},
            {"name": "chrome.exe", "cpu": [5, 30], "mem": [150, 500], "cmd": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
            {"name": "svchost.exe", "cpu": [0, 10], "mem": [20, 150], "cmd": "C:\\Windows\\System32\\svchost.exe -k netsvcs"},
            {"name": "powershell.exe", "cpu": [1, 25], "mem": [50, 300], "cmd": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
            {"name": "cmd.exe", "cpu": [0, 5], "mem": [10, 50], "cmd": "C:\\Windows\\System32\\cmd.exe"},
            {"name": "winlogon.exe", "cpu": [0, 2], "mem": [20, 80], "cmd": "C:\\Windows\\System32\\winlogon.exe"},
            {"name": "lsass.exe", "cpu": [0, 3], "mem": [30, 120], "cmd": "C:\\Windows\\System32\\lsass.exe"},
            {"name": "services.exe", "cpu": [0, 1], "mem": [10, 40], "cmd": "C:\\Windows\\System32\\services.exe"},
            {"name": "python.exe", "cpu": [1, 20], "mem": [40, 200], "cmd": "C:\\Python39\\python.exe script.py"},
            {"name": "java.exe", "cpu": [2, 35], "mem": [100, 800], "cmd": "C:\\Program Files\\Java\\jdk-17\\bin\\java.exe -jar app.jar"},
        ]
        
        # Sample network connections (fallback)
        self.dest_ips = [
            "8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1", "172.217.168.46",
            "185.130.5.133", "45.155.205.233", "94.102.61.78", "185.222.210.177"
        ]
        
        self.protocols = ["TCP", "UDP", "ICMP"]
        self.statuses = ["Established", "Listening", "Closed", "Failed", "Time_wait"]
        
        # Sample auth events (fallback)
        self.usernames = ["admin", "user1", "administrator", "john.doe", "jane.smith"]
        self.auth_statuses = ["Success", "Failure"]
        
        # Known network interfaces for real connection monitoring
        self.local_ips = self.get_local_ips()
        
        print(f"✅ Collector initialized. Logs directory: {self.logs_dir}")
        if WINDOWS_EVTLOG_AVAILABLE:
            print("✅ Windows Event Log monitoring ENABLED")
        else:
            print("⚠️  Windows Event Log monitoring DISABLED (using simulated data)")
        print(f"   Local IPs: {', '.join(self.local_ips)}")
        
    def get_local_ips(self):
        """Get list of local IP addresses"""
        ips = []
        try:
            hostname = socket.gethostname()
            ips = [socket.gethostbyname(hostname)]
            # Add all local IPs
            for ip in socket.gethostbyname_ex(hostname)[2]:
                if ip not in ips:
                    ips.append(ip)
        except:
            pass
        return ips or ["127.0.0.1"]
    
    def init_json_files(self):
        """Initialize JSON files with empty arrays if they don't exist"""
        for file_path in [self.telemetry_file, self.network_file, self.auth_file]:
            if not file_path.exists():
                with open(file_path, 'w') as f:
                    json.dump([], f)
                    print(f"   Created: {file_path.name}")
    
    def get_max_event_id(self):
        """Get the maximum event ID from existing logs"""
        max_id = 0
        for file_path in [self.telemetry_file, self.network_file, self.auth_file]:
            try:
                if file_path.exists():
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        if data:
                            max_id = max(max_id, max([e.get('id', 0) for e in data]))
            except:
                pass
        return max_id + 1
    
    def read_windows_security_events(self):
        """Read real Windows Security Event Logs for failed logins"""
        if not WINDOWS_EVTLOG_AVAILABLE:
            return []
        
        failed_events = []
        try:
            server = 'localhost'
            log_type = 'Security'
            hand = win32evtlog.OpenEventLog(server, log_type)
            
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in events:
                # Event IDs for failed logins
                # 4625 = Failed logon
                # 4648 = Logon attempt with explicit credentials
                if event.EventID in [4625, 4648]:
                    # Parse event data
                    event_data = {}
                    for str_data in event.StringInserts:
                        if 'Source Network Address' in str_data:
                            event_data['source_ip'] = str_data.split(':')[-1].strip()
                        elif 'Account Name' in str_data:
                            event_data['username'] = str_data.split(':')[-1].strip()
                        elif 'Logon Type' in str_data:
                            event_data['logon_type'] = str_data.split(':')[-1].strip()
                    
                    # Skip localhost attempts
                    source_ip = event_data.get('source_ip', '')
                    if source_ip in self.local_ips or source_ip == '-':
                        continue
                    
                    failed_events.append({
                        'id': self.event_id,
                        'timestamp': dt.fromtimestamp(event.TimeGenerated.timestamp()).isoformat(),
                        'source_ip': source_ip or 'Unknown',
                        'username': event_data.get('username', 'Unknown'),
                        'status': 'Failure',
                        'logon_type': int(event_data.get('logon_type', 3)),
                        'process_name': 'winlogon.exe',
                        'failure_reason': 'Bad password',
                        'event_id': event.EventID
                    })
                    self.event_id += 1
            
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            print(f"   ⚠️  Error reading Windows Event Log: {e}")
        
        return failed_events
    
    def read_windows_network_connections(self):
        """Read real network connections using netstat"""
        connections = []
        try:
            # Use netstat to get active connections
            import subprocess
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'TCP' in line or 'UDP' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        protocol = parts[0]
                        local_addr = parts[1]
                        foreign_addr = parts[2]
                        state = parts[3] if len(parts) > 3 else 'ESTABLISHED'
                        
                        # Parse local and foreign addresses
                        local_ip, local_port = local_addr.rsplit(':', 1)
                        foreign_ip, foreign_port = foreign_addr.rsplit(':', 1)
                        
                        # Skip local connections
                        if foreign_ip in self.local_ips or foreign_ip == '0.0.0.0':
                            continue
                        
                        connections.append({
                            'id': self.event_id,
                            'timestamp': dt.now().isoformat(),
                            'source_ip': local_ip,
                            'source_port': int(local_port),
                            'destination_ip': foreign_ip,
                            'destination_port': int(foreign_port),
                            'protocol': protocol,
                            'status': state,
                            'process_name': 'unknown',
                            'bytes_sent': 0,
                            'bytes_received': 0
                        })
                        self.event_id += 1
                        
        except Exception as e:
            print(f"   ⚠️  Error reading network connections: {e}")
        
        return connections
    
    def generate_telemetry(self):
        """Generate telemetry data (fallback when no real data)"""
        num_processes = random.randint(3, 6)
        selected_processes = random.sample(self.processes, min(num_processes, len(self.processes)))
        
        telemetry_entries = []
        for process in selected_processes:
            cpu_usage = random.uniform(process["cpu"][0], process["cpu"][1])
            memory_usage = random.uniform(process["mem"][0], process["mem"][1])
            
            entry = {
                "id": self.event_id,
                "timestamp": dt.now().isoformat(),
                "process_name": process["name"],
                "pid": random.randint(1000, 50000),
                "cpu_percent": round(cpu_usage, 2),
                "memory_mb": round(memory_usage, 2),
                "command_line": process["cmd"],
                "user": random.choice(["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "user"]),
                "status": "Running"
            }
            telemetry_entries.append(entry)
            self.event_id += 1
            
        return telemetry_entries
    
    def generate_network_logs(self):
        """Generate network logs (fallback when no real data)"""
        num_connections = random.randint(5, 10)
        network_entries = []
        
        for _ in range(num_connections):
            src_ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
            src_port = random.randint(1024, 65535)
            dest_ip = random.choice(self.dest_ips)
            dest_port = random.choice([80, 443, 22, 23, 3389, 445] + [random.randint(1024, 65535) for _ in range(3)])
            protocol = random.choice(self.protocols)
            status = random.choice(self.statuses)
            
            entry = {
                "id": self.event_id,
                "timestamp": dt.now().isoformat(),
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dest_ip,
                "destination_port": dest_port,
                "protocol": protocol,
                "status": status,
                "process_name": random.choice(["chrome.exe", "firefox.exe", "svchost.exe"]),
                "bytes_sent": random.randint(0, 1000000),
                "bytes_received": random.randint(0, 1000000)
            }
            network_entries.append(entry)
            self.event_id += 1
            
        return network_entries
    
    def generate_auth_logs(self):
        """Generate authentication logs (fallback when no real data)"""
        num_auth_events = random.randint(3, 8)
        auth_entries = []
        
        # Generate failed login bursts for brute force simulation (10% chance)
        failed_burst = random.random() < 0.1
        
        if failed_burst:
            burst_ip = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
            num_failures = random.randint(5, 12)
            
            for _ in range(num_failures):
                entry = {
                    "id": self.event_id,
                    "timestamp": dt.now().isoformat(),
                    "source_ip": burst_ip,
                    "username": random.choice(self.usernames),
                    "status": "Failure",
                    "logon_type": random.choice([2, 3, 4, 5, 8, 10]),
                    "process_name": random.choice(["winlogon.exe", "lsass.exe"]),
                    "failure_reason": random.choice(["Bad password", "Unknown user"])
                }
                auth_entries.append(entry)
                self.event_id += 1
        else:
            # Normal auth events
            for _ in range(num_auth_events):
                status = random.choices(self.auth_statuses, weights=[0.7, 0.3])[0]
                
                entry = {
                    "id": self.event_id,
                    "timestamp": dt.now().isoformat(),
                    "source_ip": f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
                    "username": random.choice(self.usernames),
                    "status": status,
                    "logon_type": random.choice([2, 3, 4, 5, 8, 10]),
                    "process_name": random.choice(["winlogon.exe", "lsass.exe"]),
                    "failure_reason": "Bad password" if status == "Failure" else ""
                }
                auth_entries.append(entry)
                self.event_id += 1
                
        return auth_entries
    
    def write_to_json(self, file_path, new_entries, max_entries=1000):
        """Write entries to JSON file with size limit"""
        try:
            # Read existing entries
            if file_path.exists():
                with open(file_path, 'r') as f:
                    existing_entries = json.load(f)
            else:
                existing_entries = []
            
            # Add new entries at the beginning
            all_entries = new_entries + existing_entries
            
            # Limit the number of entries
            if len(all_entries) > max_entries:
                all_entries = all_entries[:max_entries]
            
            # Write back to file
            with open(file_path, 'w') as f:
                json.dump(all_entries, f)
                
        except Exception as e:
            print(f"   ❌ Error writing to {file_path.name}: {e}")
    
    def collect(self):
        """Main collection function"""
        try:
            print(f"[{dt.now().strftime('%H:%M:%S')}] Collecting...", end=" ")
            
            # Try to get real Windows Event Logs
            real_auth_events = []
            if WINDOWS_EVTLOG_AVAILABLE:
                real_auth_events = self.read_windows_security_events()
            
            # Try to get real network connections
            real_network_events = []
            if WINDOWS_EVTLOG_AVAILABLE:
                real_network_events = self.read_windows_network_connections()
            
            # Use real data if available, otherwise generate simulated data
            if real_auth_events:
                auth_entries = real_auth_events
                print(f"[Real Auth: {len(auth_entries)}]", end=" ")
            else:
                auth_entries = self.generate_auth_logs()
                print(f"[Sim Auth: {len(auth_entries)}]", end=" ")
            
            if real_network_events:
                network_entries = real_network_events
                print(f"[Real Net: {len(network_entries)}]", end=" ")
            else:
                network_entries = self.generate_network_logs()
                print(f"[Sim Net: {len(network_entries)}]", end=" ")
            
            # Always generate telemetry (no real source for this)
            telemetry_entries = self.generate_telemetry()
            
            # Write to files
            self.write_to_json(self.auth_file, auth_entries, max_entries=1000)
            self.write_to_json(self.network_file, network_entries, max_entries=1000)
            self.write_to_json(self.telemetry_file, telemetry_entries, max_entries=1000)
            
            total = len(telemetry_entries) + len(network_entries) + len(auth_entries)
            print(f"Total: {total}")
            
        except Exception as e:
            print(f"❌ Error during collection: {e}")
    
    def run_continuous(self, interval=5):
        """Run collector continuously"""
        print("\n" + "="*50)
        print("SIEM Data Collector Started")
        print("="*50)
        print(f"Collecting data every {interval} seconds")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                self.collect()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n\nCollector stopped by user")
        except Exception as e:
            print(f"\nFatal error: {e}")

if __name__ == "__main__":
    collector = SystemCollector()
    collector.run_continuous(interval=5)

def start_collection():
    collector = SystemCollector()
    collector.run_continuous(interval=5)
