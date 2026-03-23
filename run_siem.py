#!/usr/bin/env python3
"""
SIEM Tool Master Launcher
This script starts all SIEM components in the correct order:
1. Collector (data collection)
2. Detection Engine (threat detection)
3. Dashboard (web interface)
"""

import subprocess
import sys
import os
import time
import signal
import atexit
from pathlib import Path

class SIEMLauncher:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.processes = []
        self.running = True
        
        # Define paths to each component
        self.collector_path = self.base_dir / 'Collector' / 'collector.py'
        self.detection_path = self.base_dir / 'Detection' / 'detection.py'
        self.dashboard_path = self.base_dir / 'Dashboard' / 'app.py'
        
        # Check if files exist
        self.check_files()
    
    def check_files(self):
        """Check if all required files exist"""
        missing_files = []
        
        if not self.collector_path.exists():
            missing_files.append(f"Collector/collector.py")
        
        if not self.detection_path.exists():
            missing_files.append(f"Detection/detection.py")
        
        if not self.dashboard_path.exists():
            missing_files.append(f"Dashboard/app.py")
        
        if missing_files:
            print("❌ ERROR: Missing required files:")
            for file in missing_files:
                print(f"   - {file}")
            print("\nPlease ensure all files are in the correct locations.")
            sys.exit(1)
        
        print("✅ All required files found")
    
    def print_banner(self):
        """Print SIEM banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███████╗██╗███████╗███╗   ███╗                             ║
║   ██╔════╝██║██╔════╝████╗ ████║                             ║
║   ███████╗██║█████╗  ██╔████╔██║                             ║
║   ╚════██║██║██╔══╝  ██║╚██╔╝██║                             ║
║   ███████║██║███████╗██║ ╚═╝ ██║                             ║
║   ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝                             ║
║                                                               ║
║   Security Information and Event Management Tool             ║
║                                                               ║
║   Components:                                                ║
║   • Data Collector (Telemetry, Network, Auth)                ║
║   • Detection Engine (Threat Analysis)                       ║
║   • Dashboard (Web Interface)                                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def start_component(self, name, command, cwd):
        """Start a component and return the process"""
        print(f"\n🚀 Starting {name}...")
        try:
            # Start process
            process = subprocess.Popen(
                command,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Store process
            self.processes.append({
                'name': name,
                'process': process,
                'cwd': cwd
            })
            
            print(f"   ✅ {name} started with PID: {process.pid}")
            
            # Give it a moment to start
            time.sleep(2)
            
            return process
            
        except Exception as e:
            print(f"   ❌ Failed to start {name}: {e}")
            return None
    
    def start_collector(self):
        """Start the data collector"""
        return self.start_component(
            "Data Collector",
            [sys.executable, str(self.collector_path)],
            self.base_dir / 'Collector'
        )
    
    def start_detection(self):
        """Start the detection engine"""
        return self.start_component(
            "Detection Engine",
            [sys.executable, str(self.detection_path)],
            self.base_dir / 'Detection'
        )
    
    def start_dashboard(self):
        """Start the dashboard web server"""
        return self.start_component(
            "Dashboard",
            [sys.executable, str(self.dashboard_path)],
            self.base_dir / 'Dashboard'
        )
    
    def cleanup(self):
        """Clean up all processes"""
        print("\n🛑 Stopping all components...")
        
        for proc_info in self.processes:
            name = proc_info['name']
            process = proc_info['process']
            
            try:
                if process.poll() is None:
                    print(f"   Stopping {name} (PID: {process.pid})...")
                    process.terminate()
                    
                    # Wait for process to terminate
                    try:
                        process.wait(timeout=5)
                        print(f"   ✅ {name} stopped")
                    except subprocess.TimeoutExpired:
                        print(f"   ⚠️ {name} didn't stop, forcing...")
                        process.kill()
                        process.wait()
                        print(f"   ✅ {name} force killed")
                else:
                    print(f"   ℹ️ {name} already stopped")
                    
            except Exception as e:
                print(f"   ❌ Error stopping {name}: {e}")
        
        print("\n✅ All components stopped")
    
    def monitor_processes(self):
        """Monitor processes and restart if needed"""
        while self.running:
            for proc_info in self.processes:
                name = proc_info['name']
                process = proc_info['process']
                
                # Check if process is still running
                if process.poll() is not None:
                    print(f"\n⚠️ {name} stopped unexpectedly (exit code: {process.returncode})")
                    
                    # Restart the component
                    if name == "Data Collector":
                        print(f"🔄 Restarting {name}...")
                        new_process = self.start_collector()
                        if new_process:
                            proc_info['process'] = new_process
                    
                    elif name == "Detection Engine":
                        print(f"🔄 Restarting {name}...")
                        new_process = self.start_detection()
                        if new_process:
                            proc_info['process'] = new_process
                    
                    elif name == "Dashboard":
                        print(f"🔄 Restarting {name}...")
                        new_process = self.start_dashboard()
                        if new_process:
                            proc_info['process'] = new_process
            
            # Wait before checking again
            time.sleep(5)
    
    def show_instructions(self):
        """Show instructions for accessing the dashboard"""
        print("\n" + "="*60)
        print("🎉 SIEM Tool is now running!")
        print("="*60)
        print("\n📊 Dashboard Access:")
        print("   • URL: http://localhost:5000")
        print("   • Username: admin")
        print("   • Password: admin123")
        print("\n📝 Log Files Location:")
        print(f"   • Logs Directory: {self.base_dir / 'Logs'}")
        print("   • telemetry.json - System process logs")
        print("   • network.json - Network connection logs")
        print("   • auth.json - Authentication logs")
        print("   • alerts.json - Security alerts")
        print("\n⚙️  Components:")
        print("   • Data Collector - Runs every 5 seconds")
        print("   • Detection Engine - Runs every 10 seconds")
        print("   • Dashboard - Auto-refreshes every 10 seconds")
        print("\n💡 Tips:")
        print("   • Press Ctrl+C to stop all components")
        print("   • Dashboard auto-refreshes every 10 seconds")
        print("   • Alerts are automatically generated based on detection rules")
        print("\n" + "="*60)
    
    def run(self):
        """Main run method"""
        # Print banner
        self.print_banner()
        
        # Register cleanup handler
        atexit.register(self.cleanup)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Start components in order
        print("\n🔧 Initializing SIEM Components...")
        print("-" * 40)
        
        # Start collector first
        collector = self.start_collector()
        if not collector:
            print("\n❌ Failed to start collector. Exiting.")
            return
        
        # Wait a bit for collector to initialize
        time.sleep(3)
        
        # Start detection engine
        detection = self.start_detection()
        if not detection:
            print("\n❌ Failed to start detection engine. Exiting.")
            return
        
        # Wait a bit for detection to initialize
        time.sleep(3)
        
        # Start dashboard
        dashboard = self.start_dashboard()
        if not dashboard:
            print("\n❌ Failed to start dashboard. Exiting.")
            return
        
        # Wait for dashboard to be ready
        time.sleep(3)
        
        # Show instructions
        self.show_instructions()
        
        # Monitor processes
        try:
            self.monitor_processes()
        except KeyboardInterrupt:
            print("\n\n🛑 Received interrupt signal. Shutting down...")
        finally:
            self.cleanup()
    
    def signal_handler(self, signum, frame):
        """Handle termination signals"""
        print("\n\n⚠️ Shutdown signal received...")
        self.running = False
        self.cleanup()
        sys.exit(0)

if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        sys.exit(1)
    
    # Check for required packages
    required_packages = ['flask', 'flask-session', 'pandas', 'psutil']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Missing required packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\n📦 Install with:")
        print(f"   pip install {' '.join(missing_packages)}")
        sys.exit(1)
    
    # Run the launcher
    launcher = SIEMLauncher()
    launcher.run()