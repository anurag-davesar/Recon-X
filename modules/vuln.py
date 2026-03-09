import os
import sys
import json
from utils import run_command, print_status, print_mitre_box, Colors

def extract_cve_data(json_file):
    """Parses Nuclei JSON output to extract clean CVE details."""
    cves_found = []
    if os.path.exists(json_file):
        with open(json_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    info = entry.get('info', {})
                    cve_id = info.get('classification', {}).get('cve-id')
                    
                    if not cve_id and "cve" in info.get('tags', []):
                         if entry.get('template-id', '').startswith('CVE-'):
                             cve_id = entry.get('template-id')

                    if cve_id:
                        cve_data = {
                            "cve_id": cve_id.upper(),
                            "severity": info.get('severity', 'unknown'),
                            "host": entry.get('host'),
                            "link": f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}"
                        }
                        if cve_data not in cves_found:
                            cves_found.append(cve_data)
                except Exception: 
                    # Catching Exception rather than a bare except allows Ctrl+C to work
                    continue 
    return cves_found

def run_cve_scan(target_cve, alive_file, output_dir):
    """Sniper Mode: Specific CVE Hunt"""
    print_mitre_box("cve_hunting")
    print_status(f"⚠️  SNIPER MODE ENGAGED: Hunting for {target_cve} ONLY", "warning")
    
    vuln_file = os.path.join(output_dir, f"{target_cve}_results.json")
    cmd_nuclei = f"nuclei -l {alive_file} -id {target_cve} -json-export {vuln_file} -silent"
    run_command(cmd_nuclei)
    
    cves = extract_cve_data(vuln_file)
    if cves:
        print_status(f"CRITICAL: Found {len(cves)} instances of {target_cve}!", "error")
        for c in cves:
            print(f"    > {c['host']}")
    else:
        print_status(f"Target appears safe from {target_cve}.", "success")
        
    # Returning data instead of sys.exit() so the General can finish the job
    return cves 

def run_general_scan(urls_file, output_dir):
    """General Vulnerability Scan"""
    print_mitre_box("vuln_scan")
    print_status("Phase 5: Vulnerability Scanning (Nuclei)...")
    
    raw_vuln_file = os.path.join(output_dir, "nuclei_raw.json")
    cmd_nuclei = f"nuclei -l {urls_file} -s critical,high -json-export {raw_vuln_file} -silent"
    run_command(cmd_nuclei)
    
    print_status("Phase 6: Generating CVE Report...", "info")
    cve_list = extract_cve_data(raw_vuln_file)
    
    if cve_list:
        print(f"\n{Colors.RED}🚨 CONFIRMED CVEs DETECTED 🚨{Colors.RESET}")
        for cve in cve_list:
            print(f"{cve['cve_id']:<20} | {cve['severity']:<10} | {cve['host']}")
            
        with open(os.path.join(output_dir, "CVE_REPORT.txt"), "w") as f:
            f.write("Recon-X CVE Report\n" + "="*50 + "\n")
            for cve in cve_list:
                f.write(f"ID: {cve['cve_id']} | Host: {cve['host']}\n")
    else:
        print_status("No CVEs identified.", "success")
        
    return cve_list