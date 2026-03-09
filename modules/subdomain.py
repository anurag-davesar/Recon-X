import os
import sys
from utils import run_command, print_status, print_mitre_box

def enum_subdomains(target, output_dir):
    print_mitre_box("subdomain_enum")
    print_status("Phase 1: Subdomain Enumeration...")
    
    sub_file = os.path.join(output_dir, "subdomains.txt")
    run_command(f"subfinder -d {target} -o {sub_file} -silent")

    # Check if the file exists and is not empty
    if os.path.exists(sub_file) and os.path.getsize(sub_file) > 0:
        with open(sub_file) as f: 
            count = len(f.readlines())
        print_status(f"Found {count} subdomains.", "success")
        return sub_file, count
    else:
        print_status("No subdomains found. Handing control back to main for fallback.", "error")
        # Return 0 so recon_x.py can trigger the Root Domain Fallback
        return None, 0