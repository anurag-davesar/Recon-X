import os
from utils import run_command, print_status, print_mitre_box

def scan_ports(alive_file, output_dir):
    print_mitre_box("port_scan")
    print_status("Phase 3: Port Scanning...")
    
    # --- SANITIZATION STEP ---
    # Naabu hates 'http://' prefixes. Let's strip them.
    sanitized_file = os.path.join(output_dir, "naabu_targets.txt")
    with open(alive_file, "r") as f:
        targets = f.read().replace("http://", "").replace("https://", "").splitlines()
    
    # Write the clean domains/IPs to a temporary file
    with open(sanitized_file, "w") as f:
        for t in set(targets): # set() removes duplicates
            f.write(t.strip() + "\n")
    # -------------------------

    ports_file = os.path.join(output_dir, "open_ports.txt")
    
    # We now feed the 'sanitized_file' to Naabu instead of 'alive_file'
    run_command(f"naabu -list {sanitized_file} -top-ports 100 -s c -rate 1000 -o {ports_file} -silent")

    if os.path.exists(ports_file) and os.path.getsize(ports_file) > 0:
        with open(ports_file) as f: 
            count = len(f.readlines())
        print_status(f"Found {count} open ports.", "success")
        return ports_file, count
    else:
        print_status("No open ports found.", "error")
        return None, 0