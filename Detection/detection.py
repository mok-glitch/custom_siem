import json
import time
import re
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
import uuid

class DetectionEngine:
    def __init__(self):
        # Get paths
        self.base_dir = Path(__file__).parent.parent
        self.logs_dir = self.base_dir / 'Logs'
        
        # Input files
        self.telemetry_file = self.logs_dir / 'telemetry.json'
        self.network_file = self.logs_dir / 'network.json'
        self.auth_file = self.logs_dir / 'auth.json'
        
        # Output file
        self.alerts_file = self.logs_dir / 'alerts.json'
        
        # Track processed events
        self.processed_events = set()
        
        # Malicious IPs (known C2, etc.)
        self.malicious_ips = {
            "185.130.5.133", "45.155.205.233", "94.102.61.78", "185.222.210.177",
            "91.219.237.101", "185.141.27.238", "46.166.142.234"
        }
        
        # Malware signatures
        self.malware_signatures = {
            'ransomware': ['wannacry.exe', 'ryuk.exe', 'locky.exe'],
            'cryptominers': ['xmrig.exe', 'minerd.exe'],
            'password_dumpers': ['mimikatz.exe', 'procdump.exe'],
            'hacking_tools': ['hydra.exe', 'nmap.exe', 'nc.exe', 'netcat.exe']
        }
        
        # PowerShell suspicious patterns
        self.powershell_patterns = [
            r'-EncodedCommand',
            r'-ExecutionPolicy\s+Bypass',
            r'DownloadString',
            r'Invoke-WebRequest'
        ]
        
        # Track attempts
        self.failed_logins = defaultdict(list)
        self.connection_attempts = defaultdict(list)
        
        # Track real-time brute force
        self.bruteforce_thresholds = {
            'ssh': {'port': 22, 'threshold': 5, 'time_window': 300},
            'telnet': {'port': 23, 'threshold': 5, 'time_window': 300},
            'rdp': {'port': 3389, 'threshold': 5, 'time_window': 300},
            'ftp': {'port': 21, 'threshold': 5, 'time_window': 300},
            'http': {'port': 80, 'threshold': 10, 'time_window': 300},
            'https': {'port': 443, 'threshold': 10, 'time_window': 300}
        }
        
        # Initialize
        self.init_alerts_file()
        print(f"✅ Detection Engine initialized")
        
    def init_alerts_file(self):
        """Initialize alerts.json"""
        try:
            self.logs_dir.mkdir(exist_ok=True)
            if not self.alerts_file.exists():
                with open(self.alerts_file, 'w') as f:
                    json.dump([], f)
                print(f"   Created alerts.json")
        except Exception as e:
            print(f"   ❌ Error creating alerts.json: {e}")
    
    def load_json_file(self, file_path):
        """Load JSON file safely"""
        try:
            if file_path.exists() and file_path.stat().st_size > 0:
                with open(file_path, 'r') as f:
                    return json.load(f)
            return []
        except:
            return []
    
    def save_alert(self, title, severity, description, details, mitre_techniques=None):
        """Save alert without duplicates"""
        try:
            # Create unique key
            alert_key = f"{title}_{details.get('source_ip', '')}_{details.get('process_name', '')}"
            
            if alert_key in self.processed_events:
                return False
            
            # Create alert
            alert = {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now().isoformat(),
                'title': title,
                'severity': severity,
                'description': description,
                'details': details,
                'status': 'Open',
                'mitre_techniques': mitre_techniques or []
            }
            
            # Load existing alerts
            alerts = self.load_json_file(self.alerts_file)
            
            # Check for recent duplicate
            alert_time = datetime.fromisoformat(alert['timestamp'])
            for existing in alerts[:50]:
                try:
                    existing_time = datetime.fromisoformat(existing.get('timestamp', ''))
                    if abs((alert_time - existing_time).total_seconds()) < 300:
                        if existing.get('title') == title:
                            return False
                except:
                    pass
            
            # Add and save
            alerts.insert(0, alert)
            if len(alerts) > 500:
                alerts = alerts[:500]
            
            with open(self.alerts_file, 'w') as f:
                json.dump(alerts, f)
            
            self.processed_events.add(alert_key)
            print(f"   🚨 [{severity}] {title}")
            return True
            
        except Exception as e:
            print(f"   ❌ Error saving alert: {e}")
            return False
    
    def detect_brute_force_from_auth(self):
        """Detect brute force attacks from auth logs"""
        try:
            auth_logs = self.load_json_file(self.auth_file)
            now = datetime.now()
            
            # Clean old entries
            for ip in list(self.failed_logins.keys()):
                self.failed_logins[ip] = [
                    e for e in self.failed_logins[ip]
                    if (now - e['timestamp']).total_seconds() < 300
                ]
                if not self.failed_logins[ip]:
                    del self.failed_logins[ip]
            
            # Process auth logs
            for log in auth_logs[:200]:  # Last 200 entries
                if log.get('status') == 'Failure':
                    try:
                        source_ip = log.get('source_ip')
                        if source_ip:
                            self.failed_logins[source_ip].append({
                                'timestamp': datetime.fromisoformat(log['timestamp']),
                                'username': log.get('username'),
                                'logon_type': log.get('logon_type')
                            })
                    except:
                        pass
            
            # Check for brute force
            for ip, attempts in self.failed_logins.items():
                if len(attempts) >= 5:
                    # Determine attack type based on logon type
                    logon_types = set([a.get('logon_type') for a in attempts])
                    attack_type = "Generic"
                    if 10 in logon_types:  # Remote Interactive (RDP)
                        attack_type = "RDP"
                    elif 3 in logon_types:  # Network (SMB, etc.)
                        attack_type = "Network"
                    elif 2 in logon_types:  # Interactive (Console)
                        attack_type = "Interactive"
                    
                    self.save_alert(
                        title=f'{attack_type} Brute Force Attack Detected',
                        severity='High',
                        description=f'Multiple login failures from {ip} ({len(attempts)} attempts in 5 minutes)',
                        details={
                            'source_ip': ip,
                            'attempts': len(attempts),
                            'usernames': list(set([a.get('username') for a in attempts]))[:10],
                            'logon_types': list(logon_types),
                            'type': attack_type
                        },
                        mitre_techniques=['T1110']
                    )
        except Exception as e:
            pass
    
    def detect_brute_force_from_network(self):
        """Detect brute force attacks from network connections (real-time)"""
        try:
            network_logs = self.load_json_file(self.network_file)
            now = datetime.now()
            
            # Track connections per IP and port
            network_attempts = defaultdict(list)
            
            for log in network_logs[:200]:
                if log.get('status') == 'Failed' or log.get('status') == 'Time_wait':
                    source_ip = log.get('source_ip')
                    dest_port = log.get('destination_port')
                    if source_ip and dest_port:
                        network_attempts[(source_ip, dest_port)].append({
                            'timestamp': datetime.fromisoformat(log['timestamp']),
                            'dest_ip': log.get('destination_ip')
                        })
            
            # Check against thresholds
            for (ip, port), attempts in network_attempts.items():
                # Clean old attempts
                recent_attempts = [
                    a for a in attempts
                    if (now - a['timestamp']).total_seconds() < 300
                ]
                
                # Determine service type
                service = None
                for svc, config in self.bruteforce_thresholds.items():
                    if config['port'] == port:
                        service = svc
                        break
                
                if service and len(recent_attempts) >= self.bruteforce_thresholds[service]['threshold']:
                    self.save_alert(
                        title=f'{service.upper()} Brute Force Attack Detected',
                        severity='High',
                        description=f'Network-level {service.upper()} brute force from {ip} ({len(recent_attempts)} connection attempts)',
                        details={
                            'source_ip': ip,
                            'destination_port': port,
                            'protocol': service.upper(),
                            'attempts': len(recent_attempts),
                            'time_window': '5 minutes'
                        },
                        mitre_techniques=['T1110']
                    )
        except Exception as e:
            pass
    
    def detect_malware_iocs(self):
        """Detect malware indicators from telemetry logs"""
        try:
            telemetry = self.load_json_file(self.telemetry_file)
            
            for event in telemetry[:200]:  # Limit to last 200
                process = event.get('process_name', '').lower()
                cmd = event.get('command_line', '').lower()
                
                # Check for hacking tools (hydra, nmap, etc.)
                for tool in self.malware_signatures['hacking_tools']:
                    if tool in process or tool in cmd:
                        tool_name = tool.replace('.exe', '').upper()
                        self.save_alert(
                            title=f'{tool_name} Hacking Tool Detected',
                            severity='High',
                            description=f'Hacking tool {tool_name} detected running on system',
                            details={
                                'process_name': event.get('process_name'),
                                'pid': event.get('pid'),
                                'command_line': event.get('command_line', '')[:200],
                                'user': event.get('user')
                            },
                            mitre_techniques=['T1588']
                        )
                        break
                
                # Check malware signatures
                for malware_type, signatures in self.malware_signatures.items():
                    if malware_type == 'hacking_tools':
                        continue
                    for sig in signatures:
                        if sig in process or sig in cmd:
                            self.save_alert(
                                title=f'{malware_type.title()} Detected',
                                severity='Critical' if malware_type == 'ransomware' else 'High',
                                description=f'Malware detected: {sig}',
                                details={'process_name': event.get('process_name'), 'pid': event.get('pid')},
                                mitre_techniques=['T1486']
                            )
                            break
        except Exception as e:
            pass
    
    def detect_suspicious_powershell(self):
        """Detect suspicious PowerShell"""
        try:
            telemetry = self.load_json_file(self.telemetry_file)
            
            for event in telemetry[:200]:
                if 'powershell' in event.get('process_name', '').lower():
                    cmd = event.get('command_line', '').lower()
                    for pattern in self.powershell_patterns:
                        if re.search(pattern, cmd, re.IGNORECASE):
                            self.save_alert(
                                title='Suspicious PowerShell Command',
                                severity='High',
                                description='PowerShell with suspicious parameters detected',
                                details={
                                    'process_name': event.get('process_name'),
                                    'command': cmd[:100],
                                    'user': event.get('user')
                                },
                                mitre_techniques=['T1059.001']
                            )
                            break
        except Exception as e:
            pass
    
    def detect_port_scan(self):
        """Detect port scanning activity"""
        try:
            network_logs = self.load_json_file(self.network_file)
            now = datetime.now()
            
            # Clean old entries
            for ip in list(self.connection_attempts.keys()):
                self.connection_attempts[ip] = [
                    e for e in self.connection_attempts[ip]
                    if (now - e['timestamp']).total_seconds() < 120
                ]
                if not self.connection_attempts[ip]:
                    del self.connection_attempts[ip]
            
            # Process network logs
            for log in network_logs[:200]:
                if log.get('status') == 'Failed':
                    source_ip = log.get('source_ip')
                    if source_ip:
                        try:
                            self.connection_attempts[source_ip].append({
                                'timestamp': datetime.fromisoformat(log['timestamp']),
                                'port': log.get('destination_port')
                            })
                        except:
                            pass
            
            # Check for port scans
            for ip, attempts in self.connection_attempts.items():
                if len(attempts) >= 8:
                    unique_ports = len(set([a['port'] for a in attempts]))
                    if unique_ports >= 5:
                        self.save_alert(
                            title='Port Scan Detected',
                            severity='Medium',
                            description=f'Port scan from {ip} ({unique_ports} unique ports)',
                            details={
                                'source_ip': ip,
                                'ports_scanned': unique_ports,
                                'total_attempts': len(attempts)
                            },
                            mitre_techniques=['T1046']
                        )
        except Exception as e:
            pass
    
    def detect_malicious_ip_connections(self):
        """Detect connections to malicious IPs"""
        try:
            network_logs = self.load_json_file(self.network_file)
            
            for log in network_logs[:200]:
                dest_ip = log.get('destination_ip')
                if dest_ip in self.malicious_ips:
                    self.save_alert(
                        title='Connection to Malicious IP',
                        severity='Critical',
                        description=f'Connection to known malicious IP: {dest_ip}',
                        details={
                            'source_ip': log.get('source_ip'),
                            'destination_ip': dest_ip,
                            'port': log.get('destination_port'),
                            'process': log.get('process_name')
                        },
                        mitre_techniques=['T1071']
                    )
        except Exception as e:
            pass
    
    def run_detection(self):
        """Run all detection rules"""
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning for threats...", end=" ")
            
            self.detect_brute_force_from_auth()
            self.detect_brute_force_from_network()
            self.detect_malware_iocs()
            self.detect_suspicious_powershell()
            self.detect_port_scan()
            self.detect_malicious_ip_connections()
            
            print(f"Done ({len(self.processed_events)} alerts total)")
            
        except Exception as e:
            print(f"Error: {e}")
    
    def run_continuous(self, interval=10):
        """Run detection continuously"""
        print("\n" + "="*50)
        print("SIEM Detection Engine Started")
        print("="*50)
        print(f"Scanning every {interval} seconds")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                self.run_detection()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n\nDetection engine stopped")
        except Exception as e:
            print(f"\nFatal error: {e}")

if __name__ == "__main__":
    detector = DetectionEngine()
    detector.run_continuous(interval=10)

def run_detection():
    detector = DetectionEngine()
    detector.run_continuous(interval=10)
