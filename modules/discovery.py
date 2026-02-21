import os
import sys
from utils import run_command, print_status, print_mitre_box

def check_live_hosts(subdomain_file, output_dir):
    print_mitre_box("live_discovery")
    print_status("Phase 2: Live Host Detection...")
    
    alive_file = os.path.join(output_dir, "alive.txt")
    run_command(f"cat {subdomain_file} | httpx -silent -o {alive_file}")
    
    if os.path.exists(alive_file):
        with open(alive_file) as f: 
            count = len(f.readlines())
        print_status(f"Found {count} live hosts.", "success")
        return alive_file, count
    else:
        print_status("No live hosts. Exiting.", "error")
        sys.exit()