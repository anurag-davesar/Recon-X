import argparse
import os
import json
import datetime
from colorama import init
from config import Colors, MITRE_MAPPING
from modules import subdomain, discovery, portscan, visual, vuln

init(autoreset=True)

final_report = {
    "target": "",
    "timestamp": str(datetime.datetime.now()),
    "steps": [],
    "confirmed_cves": []
}

def append_to_report(master_file, section_title, source_file=None, data_list=None):
    """
    Reads a source file (or list) and appends it to the Master Report.
    """
    with open(master_file, "a") as f:
        # Write Section Header
        f.write(f"\n{'='*60}\n")
        f.write(f"PHASE: {section_title}\n")
        f.write(f"{'='*60}\n")
        
        # Option A: Read from a file (e.g. subdomains.txt)
        if source_file and os.path.exists(source_file):
            with open(source_file, "r") as source:
                content = source.read()
                f.write(content if content else "No results found.\n")
                f.write("\n")
        
        # Option B: Write from a list (e.g. CVE data)
        elif data_list:
            for item in data_list:
                f.write(f"{str(item)}\n")
            f.write("\n")
        else:
            f.write("No data found.\n")

def main():
    parser = argparse.ArgumentParser(description="Recon-X: Modular Reconnaissance Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    parser.add_argument("--cve", help="Sniper Mode: Hunt for specific CVE")
    args = parser.parse_args()

    target = args.domain
    final_report["target"] = target
    output_dir = os.path.join(args.output, target)
    if not os.path.exists(output_dir): os.makedirs(output_dir)

    # --- DEFINE MASTER REPORT NAME ---
    # Example: output/tesla.com/tesla.com_FULL_REPORT.txt
    master_report = os.path.join(output_dir, f"{target}_FULL_REPORT.txt")

    # Clear previous report if it exists
    with open(master_report, "w") as f:
        f.write(f"RECON-X REPORT FOR: {target}\n")
        f.write(f"Generated: {datetime.datetime.now()}\n")
        f.write("="*60 + "\n\n")

    print(f"\n{Colors.CYAN}RECON-X v7.0 (Single Report Edition)\nTarget: {target}{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Master Report will be saved to: {master_report}{Colors.RESET}")

    # --- Phase 1: Subdomains ---
    sub_file, sub_count = subdomain.enum_subdomains(target, output_dir)
    # Append to Master Report
    append_to_report(master_report, "1. SUBDOMAIN ENUMERATION", source_file=sub_file)

    # --- Phase 2: Live Discovery ---
    alive_file, live_count = discovery.check_live_hosts(sub_file, output_dir)
    append_to_report(master_report, "2. LIVE HOSTS", source_file=alive_file)

    # --- Sniper Mode Check ---
    if args.cve:
        # Note: You'd need to modify the sniper function to return data to write it here
        # For now, we just skip it to keep things simple.
        vuln.run_cve_scan(args.cve.upper(), alive_file, output_dir)

    # --- Phase 3: Port Scan ---
    ports_file, port_count = portscan.scan_ports(alive_file, output_dir)
    if ports_file:
        append_to_report(master_report, "3. OPEN PORTS", source_file=ports_file)

        # --- Phase 4: Visuals ---
        screen_dir, png_count = visual.capture_screenshots(ports_file, output_dir)
        # We can't write images to text, so we write the location
        with open(master_report, "a") as f:
            f.write(f"\n{'='*60}\nPHASE: 4. VISUAL RECON\n{'='*60}\n")
            f.write(f"Screenshots saved in directory: {screen_dir}\n")
            f.write(f"Total Screenshots: {png_count}\n\n")

        # --- Phase 5 & 6: Vuln Scan ---
        urls_file = os.path.join(output_dir, "final_urls.txt")
        if os.path.exists(urls_file):
            cves = vuln.run_general_scan(urls_file, output_dir)
            
            # Format CVEs nicely for the text report
            formatted_cves = []
            if cves:
                for c in cves:
                    formatted_cves.append(f"[CRITICAL] {c['cve_id']} at {c['host']}")
            
            append_to_report(master_report, "5. VULNERABILITY SCAN (CVEs)", data_list=formatted_cves)

    print(f"\n{Colors.GREEN}[+] FULL REPORT GENERATED: {master_report}{Colors.RESET}")

if __name__ == "__main__":
    main()