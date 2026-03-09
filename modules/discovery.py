import os
import sys
from utils import run_command, print_status, print_mitre_box

def check_live_hosts(subdomain_file, output_dir):
    print_mitre_box("live_discovery")
    print_status("Phase 2: Live Host Detection...")
    
    alive_file = os.path.join(output_dir, "alive.txt")
    
    # Using the -l flag instead of piping cat for better subprocess stability
    run_command(f"httpx -l {subdomain_file} -silent -o {alive_file}")
    
    # Check if the file exists and is not empty
    if os.path.exists(alive_file) and os.path.getsize(alive_file) > 0:
        with open(alive_file) as f: 
            count = len(f.readlines())
        print_status(f"Found {count} live hosts.", "success")
        return alive_file, count
    else:
        print_status("No live hosts. Handing control back to main to halt.", "error")
        # Return 0 so recon_x.py can log the fatal error and exit gracefully
        return None, 0