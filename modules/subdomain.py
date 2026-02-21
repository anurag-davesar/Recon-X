import os
import sys
from utils import run_command, print_status, print_mitre_box

def enum_subdomains(target, output_dir):
    print_mitre_box("subdomain_enum")
    print_status("Phase 1: Subdomain Enumeration...")
    
    sub_file = os.path.join(output_dir, "subdomains.txt")
    run_command(f"subfinder -d {target} -o {sub_file} -silent")

    if os.path.exists(sub_file):
        with open(sub_file) as f: 
            count = len(f.readlines())
        print_status(f"Found {count} subdomains.", "success")
        return sub_file, count
    else:
        print_status("No subdomains found. Exiting.", "error")
        sys.exit()