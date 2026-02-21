import os
from utils import run_command, print_status, print_mitre_box

def scan_ports(alive_file, output_dir):
    print_mitre_box("port_scan")
    print_status("Phase 3: Port Scanning...")
    
    ports_file = os.path.join(output_dir, "open_ports.txt")
    run_command(f"naabu -list {alive_file} -top-ports 100 -o {ports_file} -silent")

    if os.path.exists(ports_file):
        with open(ports_file) as f: 
            count = len(f.readlines())
        print_status(f"Found {count} open ports.", "success")
        return ports_file, count
    else:
        print_status("No open ports found.", "error")
        return None, 0