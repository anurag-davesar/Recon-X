# config.py
from colorama import Fore, Style

# MITRE ATT&CK Mappings
MITRE_MAPPING = {
    "subdomain_enum": {"id": "T1596.001", "name": "Search Open Technical Databases: DNS/Passive DNS"},
    "live_discovery": {"id": "T1595.002", "name": "Active Scanning: Vulnerability Scanning (Live Check)"},
    "port_scan":      {"id": "T1046",     "name": "Network Service Discovery"},
    "visual_recon":   {"id": "T1594",     "name": "Search Victim-Owned Websites"},
    "vuln_scan":      {"id": "T1595.002", "name": "Active Scanning: Vulnerability Scanning (Nuclei)"},
    "cve_hunting":    {"id": "T1595",     "name": "Active Scanning: Target-Specific CVE Hunting"}
}

# Colors
class Colors:
    BLUE = Fore.BLUE
    GREEN = Fore.GREEN
    RED = Fore.RED
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    RESET = Style.RESET_ALL
    BRIGHT = Style.BRIGHT
    NORMAL = Style.NORMAL