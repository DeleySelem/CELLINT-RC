#!/usr/bin/env python3
# =====================================================================
# PROJECT: CELLINT-RC - CELL INTELLIGENCE RECONNAISSANCE CONSOLE
# MODULE: COMPREHENSIVE DEVICE ANALYSIS & TRACKING
# VERSION: 2.1
# From: D373Y 5373M / @eval
# =====================================================================

import os
import sys
import json                                                                import re
import binascii
import hashlib                                                             import random
import subprocess
import time
import threading
import socket
from datetime import datetime
from collections import OrderedDict
from typing import List, Dict, Any

# =====================================================================
# CONFIGURATION                                                            # =====================================================================
DEVICE_DB_FILE = "devices.json"
GPS_MODES = ['gps', 'network', 'fused', 'passive']
TERMUX_LOCATION_CMD = "termux-location"
TERMUX_WIFI_CMD = "termux-wifi-connectioninfo"
TERMUX_CELLINFO_CMD = "termux-telephony-cellinfo"
TERMUX_DEVICEINFO_CMD = "termux-telephony-deviceinfo"
LOG_FILE = "rigint_operations.log"
REFRESH_RATE = 2  # Seconds between live updates
MAX_CALCULATIONS = 100  # Maximum IMSI/IMEI calculations

# =====================================================================
# ENHANCED COLOR SYSTEM WITH BLUE AND ORANGE
# =====================================================================
class Colors:
    # ANSI escape codes
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'
    ORANGE = '\033[38;5;208m'
    DARK_BLUE = '\033[38;5;27m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

    # Heatmap colors with professional palette
    HEATMAP = [
        '\033[48;5;196m',  # Weak signal (red)
        '\033[48;5;202m',
        '\033[48;5;208m',
        '\033[48;5;214m',
        '\033[48;5;220m',
        '\033[48;5;226m',
        '\033[48;5;190m',  # Medium signal (yellow)
        '\033[48;5;154m',
        '\033[48;5;118m',
        '\033[48;5;82m',
        '\033[48;5;46m',   # Strong signal (green)
        '\033[48;5;40m',
        '\033[48;5;34m',
        '\033[48;5;28m',
        '\033[48;5;22m'
    ]

    @staticmethod
    def colorize(text: str, color: str) -> str:
        return f"{color}{text}{Colors.ENDC}"

    @staticmethod
    def heatmap_value(value: float, min_val: float, max_val: float) -> int:
        """Convert value to heatmap index based on range"""
        if value < min_val:
            return 0
        if value > max_val:
            return len(Colors.HEATMAP) - 1

        ratio = (value - min_val) / (max_val - min_val)
        return min(int(ratio * (len(Colors.HEATMAP) - 1)), len(Colors.HEATMAP) - 1)

    @staticmethod
    def value_color(value, min_val, max_val):
        """Apply heatmap color to any value"""
        index = Colors.heatmap_value(value, min_val, max_val)
        return f"{Colors.HEATMAP[index]}{value}{Colors.ENDC}"

    @staticmethod
    def signal_bar(value: int, width: int = 10) -> str:
        """Create visual signal strength bar with heatmap colors"""
        # Value range: -140 (weak) to -50 (strong) for RSRP
        min_val, max_val = -140, -50
        index = Colors.heatmap_value(value, min_val, max_val)
        bar = "■" * (index + 1)
        return f"{Colors.HEATMAP[index]}{bar}{Colors.ENDC}"

# =====================================================================
# LOGGING SYSTEM WITH TIMESTAMPS
# =====================================================================
class Logger:
    @staticmethod
    def log(message: str, level: str = "INFO"):
        """Log operations with timestamp and color coding"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        level_colors = {
            "INFO": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "DEBUG": Colors.CYAN
        }
        color = level_colors.get(level, Colors.ENDC)
        log_entry = f"[{timestamp}] {Colors.colorize(level, color)}: {message}"

        # Print to console
        print(log_entry)

        # Save to log file
        with open(LOG_FILE, "a") as log_file:
            log_file.write(f"[{timestamp}] {level}: {message}\n")

# =====================================================================
# DATA ANALYSIS ENGINE
# =====================================================================
class DataAnalyzer:
    @staticmethod
    def parse_report_file(file_path: str) -> Dict[str, Any]:
        """Parse Network Cell Info Lite report files"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
        except FileNotFoundError:
            Logger.log(f"File not found: {file_path}", "ERROR")
            return {}
        except Exception as e:
            Logger.log(f"Error reading file: {str(e)}", "ERROR")
            return {}

        return DataAnalyzer.parse_report_content(content)

    @staticmethod
    def parse_report_content(content: str) -> Dict[str, Any]:
        """Extract structured data from report content"""
        report_data = {
            "device_info": {},
            "permissions": {},
            "sim_info": {},
            "wifi_info": {"networks": []},
            "cell_info": {},
            "timestamp": datetime.now().isoformat()
        }

        # Extract device information
        device_match = re.search(r"Device:\s*(.+?)\s*-\s*(.+)", content)
        if device_match:
            report_data["device_info"]["model"] = device_match.group(1)
            report_data["device_info"]["hardware"] = device_match.group(2)

        # Extract Android version
        android_match = re.search(r"Android:\s*(.+?)\s*\(", content)
        if android_match:
            report_data["device_info"]["android_version"] = android_match.group(1)

        # Extract permissions
        perm_keys = [
            "location_enabled", "course_location", "fine_location",
            "background_location", "phone_state", "write_access", "wifi_state"
        ]
        perm_patterns = [
            r"Is Location Enabled\s*:\s*(\w+)",
            r"Course Location access\s*:\s*(\w+)",
            r"Fine Location access\s*:\s*(\w+)",
            r"Background Location access\s*:\s*(\w+)",
            r"Phone State access\s*:\s*(\w+)",
            r"Write access\s*:\s*(\w+)",
            r"WiFi State access\s*:\s*(\w+)"
        ]

        for key, pattern in zip(perm_keys, perm_patterns):
            match = re.search(pattern, content)
            if match:
                report_data["permissions"][key] = match.group(1).lower() == "true"

        # Extract SIM information
        sim_match = re.search(r"SIM\(tm\):\s*(\w+),\s*(\d+),", content)
        if sim_match:
            report_data["sim_info"]["operator"] = sim_match.group(1)
            report_data["sim_info"]["mccmnc"] = sim_match.group(2)

        # Extract WiFi networks
        wifi_sections = re.findall(r"SSID:\s*(.+?)\n.+?RSSI:\s*(-?\d+).+?channel:\s*(\d+)", content, re.DOTALL)
        for ssid, rssi, channel in wifi_sections:
            report_data["wifi_info"]["networks"].append({
                "ssid": ssid,
                "rssi": int(rssi),
                "channel": int(channel)
            })

        # Extract cell information
        cell_match = re.search(r"-- getCellLocation\s*=\s*(.+)", content)
        if cell_match:
            report_data["cell_info"]["location"] = cell_match.group(1)

        # Extract LTE parameters
        lte_params = re.findall(r"(\w+)\s*:\s*(-?\d+)", content)
        for param, value in lte_params:
            if param.lower() in ['mcc', 'mnc', 'tac', 'pci', 'rsrp', 'rsrq', 'rssnr', 'band', 'cid', 'nid', 'asu', 'power']:
                report_data["cell_info"][param.lower()] = int(value)

        return report_data

    @staticmethod
    def calculate_possible_imsis(device_data: Dict[str, Any], count=10) -> List[str]:
        """Generate possible IMSI numbers using available device data"""
        Logger.log(f"Calculating {count} possible IMSIs", "DEBUG")
        possible_imsis = []

        # Extract base components
        mcc = device_data.get('mcc', '310')
        mnc = device_data.get('mnc', '260')
        tac = device_data.get('tac', '0000')
        pci = str(device_data.get('pci', '0'))
        ci = str(device_data.get('ci', '0'))

        # Generate using multiple algorithms
        for i in range(min(count, MAX_CALCULATIONS)):
            # Method 1: Hash-based generation
            hash_str = f"{mcc}{mnc}{tac}{pci}{ci}{i}".encode()
            sha_imsi = mcc + mnc + hashlib.sha256(hash_str).hexdigest()[:10]

            # Method 2: Mathematical transformation
            math_imsi = mcc + mnc + str(int(tac) * int(pci) * int(ci) % 1000000000).zfill(10)

            # Method 3: Random-based with structure
            rand_imsi = mcc + mnc + ''.join(str(random.randint(0, 9)) for _ in range(10))

            possible_imsis.extend([sha_imsi, math_imsi, rand_imsi])

        # Remove duplicates
        return list(set(possible_imsis))[:count]

    @staticmethod
    def calculate_possible_imeis(count=10) -> List[str]:
        """Generate valid IMEI numbers that pass Luhn check"""
        Logger.log(f"Calculating {count} possible IMEIs", "DEBUG")
        imeis = []
        tac_db = ['35', '01', '86']  # Common TACs (Type Allocation Codes)

        for _ in range(min(count, MAX_CALCULATIONS)):
            # Select random TAC
            tac = random.choice(tac_db)

            # Generate random 12-digit serial number
            serial = ''.join(str(random.randint(0, 9)) for _ in range(12))

            # Generate without check digit
            base_imei = tac + serial

            # Calculate Luhn check digit
            total = 0
            for i, digit in enumerate(base_imei):
                d = int(digit)
                if i % 2 == 0:
                    d *= 2
                    if d > 9:
                        d -= 9
                total += d

            check_digit = (10 - (total % 10)) % 10
            imeis.append(base_imei + str(check_digit))

        return imeis

    @staticmethod
    def extract_gps_data(provider: str = 'gps') -> Dict[str, Any]:
        """Get GPS data using specified provider mode"""
        try:
            Logger.log(f"Collecting location data using {provider} provider", "INFO")
            result = subprocess.run([TERMUX_LOCATION_CMD, "-p", provider],
                                   capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception as e:
            Logger.log(f"GPS error: {str(e)}", "ERROR")
        return {}

    @staticmethod
    def get_ip_address():
        """Get IP address for unrooted Android in Termux using Termux commands"""
        # Try WiFi first
        try:
            result = subprocess.run([TERMUX_WIFI_CMD],
                                   capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                wifi_data = json.loads(result.stdout)
                return wifi_data.get("ip", "N/A")
        except:
            pass

        # Try cellular data
        try:
            result = subprocess.run([TERMUX_DEVICEINFO_CMD],
                                   capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                device_data = json.loads(result.stdout)
                return device_data.get("data_ip", "N/A")
        except:
            pass

        # Fallback to socket method (only for WiFi)
        try:
            # Create a temporary socket to get the IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
            return ip_address
        except:
            return "N/A"

# =====================================================================
# DEVICE MANAGEMENT SYSTEM
# =====================================================================
class Device:
    def __init__(self, device_type: str, data: Dict[str, Any] = None):
        self.id = binascii.hexlify(os.urandom(4)).decode()
        self.device_type = device_type
        self.data = data or {}
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.times_seen = 1
        self.location_history = []
        Logger.log(f"Created new device: {self.id} ({device_type})", "INFO")

    def update(self, new_data: Dict[str, Any]):
        for key, value in new_data.items():
            self.data[key] = value
        self.last_seen = datetime.now()
        self.times_seen += 1
        Logger.log(f"Updated device {self.id}", "DEBUG")

    def add_location(self, location: Dict[str, Any]):
        timestamp = datetime.now()
        self.location_history.append({
            "timestamp": timestamp.isoformat(),
            "location": location
        })
        self.data['last_location'] = location
        Logger.log(f"Added location to device {self.id} at {timestamp}", "INFO")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "device_type": self.device_type,
            "data": self.data,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "times_seen": self.times_seen,
            "location_history": self.location_history
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        device = cls(data['device_type'], data['data'])
        device.id = data['id']
        device.first_seen = datetime.fromisoformat(data['first_seen'])
        device.last_seen = datetime.fromisoformat(data['last_seen'])
        device.times_seen = data['times_seen']
        device.location_history = data.get('location_history', [])
        Logger.log(f"Loaded device from storage: {device.id}", "DEBUG")
        return device

    def calculate_imsis(self, count=10) -> List[str]:
        Logger.log(f"Calculating IMSIs for device {self.id}", "INFO")
        return DataAnalyzer.calculate_possible_imsis(self.data, min(count, MAX_CALCULATIONS))

    def calculate_imeis(self, count=10) -> List[str]:
        Logger.log(f"Calculating IMEIs for device {self.id}", "INFO")
        return DataAnalyzer.calculate_possible_imeis(min(count, MAX_CALCULATIONS))

    def compact_display(self) -> str:
        """Generate compact heatmapped display string for live view"""
        output = []

        # Device type and ID
        output.append(f"{Colors.BOLD}{self.device_type.upper()}{Colors.ENDC} {Colors.CYAN}{self.id[:6]}{Colors.ENDC}")

        # Cell information
        if 'mcc' in self.data or 'mnc' in self.data:
            cell_info = f"MCC: {self.data.get('mcc', 'N/A')} "
            cell_info += f"MNC: {self.data.get('mnc', 'N/A')} "
            cell_info += f"TAC: {self.data.get('tac', 'N/A')} "

            if 'rsrp' in self.data:
                rsrp = self.data['rsrp']
                cell_info += f"RSRP: {Colors.signal_bar(rsrp)} "

            if 'pci' in self.data:
                cell_info += f"PCI: {self.data['pci']}"

            output.append(cell_info)

        # Location information
        if 'last_location' in self.data:
            loc = self.data['last_location']
            loc_info = f"LOC: {loc.get('latitude', 'N/A')},{loc.get('longitude', 'N/A')} "
            loc_info += f"±{loc.get('accuracy', 'N/A')}m"
            output.append(loc_info)

        # WiFi information
        if 'wifi_info' in self.data and self.data['wifi_info'].get('networks'):
            wifi_info = "WiFi: "
            for i, net in enumerate(self.data['wifi_info']['networks']):
                if i > 0:
                    wifi_info += " | "
                wifi_info += f"{net.get('ssid', 'Unknown')[:10]} "
                wifi_info += f"{Colors.signal_bar(net.get('rssi', -100))}"
            output.append(wifi_info)

        return " | ".join(output)

class DeviceManager:
    def __init__(self):
        self.devices = OrderedDict()
        self.load_devices()
        Logger.log("Device manager initialized", "INFO")

    def add_device(self, device: Device):
        if device.id in self.devices:
            existing = self.devices[device.id]
            existing.update(device.data)
            Logger.log(f"Updated existing device: {device.id}", "DEBUG")
        else:
            self.devices[device.id] = device
            Logger.log(f"Added new device: {device.id}", "INFO")
        self.save_devices()

    def get_device(self, device_id: str) -> Device:
        return self.devices.get(device_id)

    def save_devices(self):
        devices_data = [device.to_dict() for device in self.devices.values()]
        with open(DEVICE_DB_FILE, 'w') as f:
            json.dump(devices_data, f, indent=2)
        Logger.log(f"Saved {len(devices_data)} devices to {DEVICE_DB_FILE}", "INFO")

    def load_devices(self):
        if os.path.exists(DEVICE_DB_FILE):
            try:
                with open(DEVICE_DB_FILE) as f:
                    devices_data = json.load(f)
                    for data in devices_data:
                        device = Device.from_dict(data)
                        self.devices[device.id] = device
                Logger.log(f"Loaded {len(devices_data)} devices from storage", "INFO")
            except Exception as e:
                Logger.log(f"Error loading devices: {str(e)}", "ERROR")

    def list_devices(self, device_type: str = None) -> List[Device]:
        if device_type:
            return [d for d in self.devices.values() if d.device_type == device_type]
        return list(self.devices.values())

# Initialize device manager
DEVICE_MANAGER = DeviceManager()

# =====================================================================
# CONTINUOUS MONITORING ENGINE
# =====================================================================
class DataMonitor:
    def __init__(self, console):
        self.console = console
        self.running = False
        self.thread = None
        self.last_data = None
        self.target_device = None

    def start(self, device_id=None):
        """Start continuous monitoring in background thread"""
        if self.running:
            return

        self.running = True
        self.target_device = device_id
        self.thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.thread.start()
        Logger.log(f"Continuous monitoring started for device: {device_id or 'ALL'}", "INFO")

    def stop(self):
        """Stop continuous monitoring"""
        self.running = False
        if self.thread:
            self.thread.join()
        Logger.log("Continuous monitoring stopped", "INFO")

    def monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Collect cell data
                cell_data = self.get_cell_data()
                cell_device = Device("cell_tower", cell_data)

                # Collect location data only for target device
                location = {}
                if not self.target_device or self.target_device == "phone":
                    location = DataAnalyzer.extract_gps_data(self.console.location_provider)

                # Update display
           #     os.system('clear')
                print(f"{Colors.BOLD}{Colors.DARK_BLUE}=== LIVE MONITORING MODE (CTRL+C to exit) ==={Colors.ENDC}")
                print(cell_device.compact_display())

                if location:
                    phone_device = Device("phone", {"status": "active"})
                    phone_device.add_location(location)
                    print(phone_device.compact_display())
                    if not self.target_device or self.target_device == "phone":
                        DEVICE_MANAGER.add_device(phone_device)

                # Add cell tower to device manager
                DEVICE_MANAGER.add_device(cell_device)

                # Save last data for compact display
                self.last_data = (cell_device, phone_device) if location else (cell_device,)

                time.sleep(REFRESH_RATE)
            except Exception as e:
                Logger.log(f"Monitoring error: {str(e)}", "ERROR")
                time.sleep(1)

    def get_cell_data(self) -> dict:
        """Collect real-time cell data"""
        try:
            cell_info = subprocess.check_output([TERMUX_CELLINFO_CMD], text=True)
            cell_data = json.loads(cell_info)
            if cell_data:
                serving_cell = cell_data[0]
                cell_type = 'lte' if 'lte' in serving_cell else 'nr'
                return serving_cell.get(cell_type, {})
        except Exception as e:
            Logger.log(f"Cell data error: {str(e)}", "ERROR")
        return {}

# =====================================================================
# COMMAND INTERPRETER WITH ENHANCED FEATURES
# =====================================================================
class AdvancedConsole:
    def __init__(self):
        self.location_provider = 'gps'
        self.monitor = DataMonitor(self)
        self.verbose_level = 0  # 0: Minimal, 1: Standard, 2: Detailed, 3: Debug
        self.start()
        Logger.log("Console initialized", "INFO")

    def start(self):
        os.system('clear')
        banner = f"\n{Colors.BOLD}{Colors.DARK_BLUE}{'='*60}"
        banner += f"\nCELLINT-RC v.2.1 CELL INTELLIGENCE RECONNAISSANCE CONSOLE"
        banner += f"\n========= Track Device Info and Identification =========="
        banner += f"\nFrom: D373Y 5373M / @eval"
        banner += f"\n{'='*60}"
        banner += f"\nDEVICE DB: {Colors.ORANGE}{DEVICE_DB_FILE}{Colors.DARK_BLUE}"
        banner += f"\nGPS MODE: {Colors.ORANGE}{self.location_provider.upper()}"
        banner += f"\nLOG FILE: {Colors.ORANGE}{LOG_FILE}{Colors.DARK_BLUE}"
        banner += f"\nVERBOSE LEVEL: {Colors.ORANGE}{self.verbose_level}{Colors.DARK_BLUE}"
        banner += f"\n{'='*60}{Colors.ENDC}"
        print(banner)

        while True:
            try:
                cmd = input(f"{Colors.GREEN}>>> {Colors.ENDC}").strip()
                self.parse_command(cmd)
            except KeyboardInterrupt:
                if self.monitor.running:
                    self.monitor.stop()
                    print(f"{Colors.YELLOW}\n[!] Exited live monitoring mode{Colors.ENDC}")
                else:
                    print(f"{Colors.YELLOW}\n[!] Type 'exit' to quit{Colors.ENDC}")
            except Exception as e:
                Logger.log(f"Command error: {str(e)}", "ERROR")

    def parse_command(self, cmd: str):
        if not cmd:
            return

        # Log the command with timestamp
        Logger.log(f"Command executed: {cmd}", "DEBUG")

        parts = cmd.split()
        command = parts[0].lower()
        args = parts[1:]

        if command == "help":
            self.show_help()
        elif command == "exit":
            print(f"{Colors.GREEN}[+] Terminating session{Colors.ENDC}")
            sys.exit(0)
        elif command == "load":
            self.handle_load_command(args)
        elif command == "save":
            DEVICE_MANAGER.save_devices()
            print(f"{Colors.GREEN}[+] Saved data to {DEVICE_DB_FILE}{Colors.ENDC}")
        elif command == "list":
            self.handle_list_command(args)
        elif command == "show":
            self.handle_show_command(args)
        elif command == "calculate":
            self.handle_calculate_command(args)
        elif command == "gps":
            self.handle_gps_command(args)
        elif command == "scan":
            self.handle_scan_command(args)
        elif command == "track":
            self.handle_track_command(args)
        elif command == "export":
            self.handle_export_command(args)
        elif command == "log":
            self.handle_log_command(args)
        elif command == "import":
            self.handle_import_command(args)
        elif command == "live":
            self.handle_live_command(args)
        elif command == "verbose":
            self.handle_verbose_command(args)
        else:
            print(f"{Colors.RED}Unknown command: {command}{Colors.ENDC}")

    def show_help(self):
        print(f"\n{Colors.DARK_BLUE}{Colors.BOLD}COMMAND REFERENCE:{Colors.ENDC}")
        print(f"{Colors.GREEN}  help                      Show this help")
        print(f"  exit                      Exit the application")
        print(f"  load [file]               Reload devices from JSON file(s)")
        print(f"  save                      Save devices to {DEVICE_DB_FILE}")
        print(f"  list devices              List all devices")
        print(f"  show <id>                 Show device details")
        print(f"  calculate imsi <id> [count]  Calculate possible IMSIs (max {MAX_CALCULATIONS})")
        print(f"  calculate imei <id> [count]  Calculate possible IMEIs (max {MAX_CALCULATIONS})")
        print(f"  gps <mode>                Set GPS provider mode ({', '.join(GPS_MODES)})")
        print(f"  scan cell                 Perform cell tower scan")
        print(f"  track device              Track current device location")
        print(f"  import <file>             Import data from Network Cell Info Lite report")
        print(f"  live [device_id]          Enter live monitoring mode for specific device")
        print(f"  export <id>               Export device data to JSON file")
        print(f"  log [clear]               View or clear operation logs")
        print(f"  verbose <level>           Set verbosity level (0-3)")
        print(f"{Colors.ENDC}")

    def handle_load_command(self, args):
        if args:
            for file_path in args:
                if os.path.exists(file_path) and file_path.endswith('.json'):
                    try:
                        with open(file_path) as f:
                            devices_data = json.load(f)
                            for data in devices_data:
                                device = Device.from_dict(data)
                                DEVICE_MANAGER.add_device(device)
                        print(f"{Colors.GREEN}[+] Loaded devices from {file_path}{Colors.ENDC}")
                    except Exception as e:
                        print(f"{Colors.RED}Error loading {file_path}: {str(e)}{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}Invalid file: {file_path}{Colors.ENDC}")
        else:
            DEVICE_MANAGER.load_devices()
            print(f"{Colors.GREEN}[+] Reloaded data from {DEVICE_DB_FILE}{Colors.ENDC}")

    def handle_list_command(self, args):
        if not args or args[0] != "devices":
            return

        devices = DEVICE_MANAGER.list_devices()
        if not devices:
            print(f"{Colors.YELLOW}  No devices found{Colors.ENDC}")
            return

        print(f"\n{Colors.DARK_BLUE}DEVICES:{Colors.ENDC}")
        print(f"{Colors.BOLD}ID       TYPE          LAST SEEN{Colors.ENDC}")
        for device in devices:
            print(f"{Colors.GREEN}{device.id[:8]}{Colors.ENDC} {Colors.CYAN}{device.device_type:12}{Colors.ENDC} {device.last_seen.strftime('%Y-%m-%d %H:%M')}")

    def handle_show_command(self, args):
        if not args:
            print(f"{Colors.YELLOW}Please specify device ID{Colors.ENDC}")
            return

        device = DEVICE_MANAGER.get_device(args[0])
        if not device:
            print(f"{Colors.RED}Device not found{Colors.ENDC}")
            return

        if device.device_type == "report":
            self.display_report(device)
        else:
            self.display_device_details(device)

    def display_device_details(self, device: Device):
        print(f"\n{Colors.DARK_BLUE}DEVICE DETAILS: {device.id}{Colors.ENDC}")
        print(f"{Colors.BLUE}{'='*60}{Colors.ENDC}")
        print(f"{Colors.BOLD}Type:{Colors.ENDC} {Colors.CYAN}{device.device_type}{Colors.ENDC}")
        print(f"{Colors.BOLD}First Seen:{Colors.ENDC} {device.first_seen}")
        print(f"{Colors.BOLD}Last Seen:{Colors.ENDC} {device.last_seen}")
        print(f"{Colors.BOLD}Times Seen:{Colors.ENDC} {Colors.YELLOW}{device.times_seen}{Colors.ENDC}")

        # Add IP address
        ip_address = DataAnalyzer.get_ip_address()
        print(f"{Colors.BOLD}IP Address:{Colors.ENDC} {Colors.ORANGE}{ip_address}{Colors.ENDC}")

        print(f"\n{Colors.BOLD}NETWORK PARAMETERS:{Colors.ENDC}")
        params = [
            ('mcc', 'MCC', -100, 1000),
            ('mnc', 'MNC', -100, 1000),
            ('tac', 'TAC', -100, 10000),
            ('pci', 'PCI', -100, 1000),
            ('rsrp', 'RSRP', -140, -50),
            ('rsrq', 'RSRQ', -20, -3),
            ('rssnr', 'RSSNR', -10, 30),
            ('band', 'Band', 0, 100),
            ('cid', 'CID', 0, 268435455),
            ('nid', 'NID', 0, 65535),
            ('asu', 'ASU', 0, 97),
            ('power', 'Power', -50, 50)
        ]

        for key, name, min_val, max_val in params:
            if key in device.data:
                value = device.data[key]
                colorized = Colors.value_color(value, min_val, max_val)
                print(f"  {Colors.BOLD}{name}:{Colors.ENDC} {colorized}")

        if device.location_history:
            detail_level = min(self.verbose_level, 3)
            print(f"\n{Colors.BOLD}LOCATION HISTORY ({len(device.location_history)} points):{Colors.ENDC}")
            for i, loc in enumerate(device.location_history[-detail_level*3:], 1):
                print(f"  {Colors.YELLOW}{i}. {loc['timestamp']}{Colors.ENDC}")
                if detail_level > 0:
                    for k, v in loc['location'].items():
                        print(f"      {Colors.BOLD}{k}:{Colors.ENDC} {Colors.CYAN}{v}{Colors.ENDC}")

    def display_report(self, device: Device):
        """Compact display for report-type devices"""
        data = device.data
        print(f"\n{Colors.DARK_BLUE}REPORT ANALYSIS: {device.id}{Colors.ENDC}")
        print(f"{Colors.BLUE}{'='*60}{Colors.ENDC}")

        # Device information
        if 'device_info' in data:
            dev_info = data['device_info']
            print(f"{Colors.BOLD}Device:{Colors.ENDC} {Colors.CYAN}{dev_info.get('model', 'N/A')} - {dev_info.get('hardware', 'N/A')}{Colors.ENDC}")
            print(f"{Colors.BOLD}Android:{Colors.ENDC} {Colors.CYAN}{dev_info.get('android_version', 'N/A')}{Colors.ENDC}")

        # Cell information
        if 'cell_info' in data:
            cell_info = data['cell_info']
            print(f"{Colors.BOLD}Cell Location:{Colors.ENDC} {Colors.CYAN}{cell_info.get('location', 'N/A')}{Colors.ENDC}")

            # Detailed cell parameters
            params = [
                ('mcc', 'MCC', -100, 1000),
                ('mnc', 'MNC', -100, 1000),
                ('tac', 'TAC', -100, 10000),
                ('pci', 'PCI', -100, 1000),
                ('rsrp', 'RSRP', -140, -50),
                ('rsrq', 'RSRQ', -20, -3),
                ('rssnr', 'RSSNR', -10, 30),
                ('band', 'Band', 0, 100),
                ('cid', 'CID', 0, 268435455),
                ('nid', 'NID', 0, 65535),
                ('asu', 'ASU', 0, 97),
                ('power', 'Power', -50, 50)
            ]

            for key, name, min_val, max_val in params:
                if key in cell_info:
                    value = cell_info[key]
                    colorized = Colors.value_color(value, min_val, max_val)
                    print(f"  {Colors.BOLD}{name}:{Colors.ENDC} {colorized}")

        # SIM information
        if 'sim_info' in data:
            sim_info = data['sim_info']
            print(f"{Colors.BOLD}Operator:{Colors.ENDC} {Colors.CYAN}{sim_info.get('operator', 'N/A')} ({sim_info.get('mccmnc', 'N/A')}){Colors.ENDC}")

        # WiFi networks
        if 'wifi_info' in data and data['wifi_info'].get('networks'):
            print(f"\n{Colors.BOLD}WiFi Networks:{Colors.ENDC}")
            for network in data['wifi_info']['networks']:
                ssid = network.get('ssid', 'Unknown')
                rssi = network.get('rssi', 0)
                channel = network.get('channel', 0)
                print(f"  {ssid[:20]:<20} {Colors.signal_bar(rssi)} {rssi} dBm (Ch {channel})")

    def handle_calculate_command(self, args):
        if len(args) < 2:
            print(f"{Colors.YELLOW}Usage: calculate <imsi|imei> <device_id> [count]{Colors.ENDC}")
            return

        device_id = args[1]
        count = 10
        if len(args) > 2:
            try:
                count = int(args[2])
                count = min(count, MAX_CALCULATIONS)
            except ValueError:
                print(f"{Colors.RED}Invalid count value{Colors.ENDC}")
                return

        device = DEVICE_MANAGER.get_device(device_id)
        if not device:
            print(f"{Colors.RED}Device not found{Colors.ENDC}")
            return

        if args[0] == "imsi":
            imsis = device.calculate_imsis(count)
            print(f"\n{Colors.DARK_BLUE}POSSIBLE IMSIs FOR DEVICE {device_id}:{Colors.ENDC}")
            for imsi in imsis:
                print(f"  {Colors.GREEN}{imsi}{Colors.ENDC}")

        elif args[0] == "imei":
            imeis = device.calculate_imeis(count)
            print(f"\n{Colors.DARK_BLUE}POSSIBLE IMEIs FOR DEVICE {device_id}:{Colors.ENDC}")
            for imei in imeis:
                print(f"  {Colors.GREEN}{imei}{Colors.ENDC}")
        else:
            print(f"{Colors.RED}Invalid calculation type. Use 'imsi' or 'imei'{Colors.ENDC}")

    def handle_gps_command(self, args):
        if not args:
            print(f"{Colors.DARK_BLUE}Current GPS provider: {Colors.ORANGE}{self.location_provider}{Colors.ENDC}")
            return

        if args[0] in GPS_MODES:
            self.location_provider = args[0]
            print(f"{Colors.GREEN}GPS provider set to: {Colors.ORANGE}{self.location_provider}{Colors.ENDC}")
        else:
            print(f"{Colors.RED}Invalid GPS mode. Available modes: {', '.join(GPS_MODES)}{Colors.ENDC}")

    def handle_scan_command(self, args):
        if not args or args[0] != "cell":
            return

        # Real cell data collection
        print(f"\n{Colors.DARK_BLUE}[+] PERFORMING CELL TOWER SCAN{Colors.ENDC}")
        try:
            cell_info = subprocess.check_output([TERMUX_CELLINFO_CMD], text=True)
            cell_data = json.loads(cell_info)

            if cell_data:
                # Process serving cell (first in list)
                serving_cell = cell_data[0]
                cell_type = 'lte' if 'lte' in serving_cell else 'nr'
                cell_info = serving_cell.get(cell_type, {})

                # Add IP address
                cell_info['ip'] = DataAnalyzer.get_ip_address()

                device = Device("cell_tower", cell_info)
                DEVICE_MANAGER.add_device(device)

                print(f"{Colors.GREEN}Discovered cell tower: {device.id}{Colors.ENDC}")
                print(f"  {Colors.BOLD}MCC:{Colors.ENDC} {Colors.CYAN}{cell_info.get('mcc', 'N/A')}{Colors.ENDC}")
                print(f"  {Colors.BOLD}MNC:{Colors.ENDC} {Colors.CYAN}{cell_info.get('mnc', 'N/A')}{Colors.ENDC}")
                print(f"  {Colors.BOLD}TAC:{Colors.ENDC} {Colors.CYAN}{cell_info.get('tac', 'N/A')}{Colors.ENDC}")
                print(f"  {Colors.BOLD}PCI:{Colors.ENDC} {Colors.CYAN}{cell_info.get('pci', 'N/A')}{Colors.ENDC}")
                print(f"  {Colors.BOLD}RSRP:{Colors.ENDC} {Colors.signal_bar(cell_info.get('rsrp', 0))}")
                print(f"  {Colors.BOLD}IP:{Colors.ENDC} {Colors.ORANGE}{cell_info.get('ip', 'N/A')}{Colors.ENDC}")
            else:
                print(f"{Colors.RED}No cell data available{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}Cell scan failed: {str(e)}{Colors.ENDC}")

    def handle_track_command(self, args):
        if not args or args[0] != "device":
            return

        print(f"\n{Colors.DARK_BLUE}[+] TRACKING DEVICE LOCATION{Colors.ENDC}")
        location = DataAnalyzer.extract_gps_data(self.location_provider)
        if not location:
            print(f"{Colors.RED}Location tracking failed{Colors.ENDC}")
            return

        # Add IP address
        location['ip'] = DataAnalyzer.get_ip_address()

        device = Device("phone", {"status": "active"})
        device.add_location(location)
        DEVICE_MANAGER.add_device(device)

        print(f"{Colors.GREEN}Tracked device: {device.id}{Colors.ENDC}")
        print(f"  {Colors.BOLD}Latitude:{Colors.ENDC}  {Colors.CYAN}{location.get('latitude', 'N/A')}{Colors.ENDC}")
        print(f"  {Colors.BOLD}Longitude:{Colors.ENDC} {Colors.CYAN}{location.get('longitude', 'N/A')}{Colors.ENDC}")
        print(f"  {Colors.BOLD}Accuracy:{Colors.ENDC}  {Colors.CYAN}{location.get('accuracy', 'N/A')}m{Colors.ENDC}")
        print(f"  {Colors.BOLD}IP:{Colors.ENDC} {Colors.ORANGE}{location.get('ip', 'N/A')}{Colors.ENDC}")

    def handle_export_command(self, args):
        if len(args) < 1:
            print(f"{Colors.YELLOW}Usage: export <device_id> [filename]{Colors.ENDC}")
            return

        device_id = args[0]
        filename = f"{device_id}.json" if len(args) < 2 else args[1]

        device = DEVICE_MANAGER.get_device(device_id)
        if not device:
            print(f"{Colors.RED}Device not found{Colors.ENDC}")
            return

        try:
            with open(filename, 'w') as f:
                json.dump(device.to_dict(), f, indent=2)
            print(f"{Colors.GREEN}Exported device data to {filename}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}Export failed: {str(e)}{Colors.ENDC}")

    def handle_log_command(self, args):
        if args and args[0] == "clear":
            open(LOG_FILE, 'w').close()
            print(f"{Colors.GREEN}Log file cleared{Colors.ENDC}")
            return

        print(f"\n{Colors.DARK_BLUE}OPERATION LOGS:{Colors.ENDC}")
        try:
            with open(LOG_FILE, 'r') as log_file:
                for line in log_file:
                    if "ERROR" in line:
                        print(f"{Colors.RED}{line.strip()}{Colors.ENDC}")
                    elif "WARNING" in line:
                        print(f"{Colors.YELLOW}{line.strip()}{Colors.ENDC}")
                    elif "DEBUG" in line:
                        print(f"{Colors.CYAN}{line.strip()}{Colors.ENDC}")
                    else:
                        print(f"{Colors.GREEN}{line.strip()}{Colors.ENDC}")
        except FileNotFoundError:
            print(f"{Colors.YELLOW}No log file found{Colors.ENDC}")

    def handle_import_command(self, args):
        if not args:
            print(f"{Colors.YELLOW}Usage: import <filename>{Colors.ENDC}")
            return

        file_path = args[0]
        if not os.path.exists(file_path):
            print(f"{Colors.RED}File not found: {file_path}{Colors.ENDC}")
            return

        report_data = DataAnalyzer.parse_report_file(file_path)
        if not report_data:
            print(f"{Colors.RED}Failed to parse report file{Colors.ENDC}")
            return

        device = Device("report", report_data)
        DEVICE_MANAGER.add_device(device)
        print(f"{Colors.GREEN}Imported report data: {device.id}{Colors.ENDC}")
        self.display_report(device)

    def handle_live_command(self, args):
        """Enter live monitoring mode"""
        device_id = args[0] if args else None
        print(f"{Colors.DARK_BLUE}[+] ENTERING LIVE MONITORING MODE{Colors.ENDC}")
        if device_id:
            print(f"{Colors.DARK_BLUE}Tracking device: {Colors.ORANGE}{device_id}{Colors.ENDC}")
        print(f"{Colors.YELLOW}Press CTRL+C to exit{Colors.ENDC}")
        self.monitor.start(device_id)

    def handle_verbose_command(self, args):
        if not args:
            print(f"{Colors.DARK_BLUE}Current verbosity level: {Colors.ORANGE}{self.verbose_level}{Colors.ENDC}")
            print(f"{Colors.CYAN}0: Minimal output")
            print(f"1: Comprehensive instructions and main parameters")
            print(f"2: Detailed info from all parameters")
            print(f"3: Debug info + timestamps{Colors.ENDC}")
            return

        try:
            level = int(args[0])
            if 0 <= level <= 3:
                self.verbose_level = level
                print(f"{Colors.GREEN}Verbosity level set to: {Colors.ORANGE}{level}{Colors.ENDC}")
            else:
                print(f"{Colors.RED}Verbosity level must be between 0 and 3{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.RED}Invalid verbosity level{Colors.ENDC}")

# =====================================================================
# MAIN EXECUTION
# =====================================================================
if __name__ == "__main__":
    # Initialize device database if needed
    if not os.path.exists(DEVICE_DB_FILE):
        print(f"{Colors.DARK_BLUE}[+] Initializing device database{Colors.ENDC}")
        with open(DEVICE_DB_FILE, 'w') as f:
            json.dump([], f)

    # Initialize logger
    Logger.log("CELLINT-RC session started", "INFO")

    console = AdvancedConsole()
