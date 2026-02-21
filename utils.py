# utils.py
import subprocess
from config import MITRE_MAPPING, Colors

def run_command(command):
    """Runs a shell command safely."""
    try:
        result = subprocess.run(
            command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return result.stdout
    except subprocess.CalledProcessError:
        return None

def print_status(message, level="info"):
    if level == "info":
        print(f"{Colors.BLUE}[*]{Colors.RESET} {message}")
    elif level == "success":
        print(f"{Colors.GREEN}[+]{Colors.RESET} {message}")
    elif level == "error":
        print(f"{Colors.RED}[-]{Colors.RESET} {message}")
    elif level == "warning":
        print(f"{Colors.YELLOW}[!]{Colors.RESET} {message}")

def print_mitre_box(phase_key):
    tactic = MITRE_MAPPING.get(phase_key, {})
    if tactic:
        print(f"\n{Colors.MAGENTA}┌── [ MITRE ATT&CK MAPPING ] ──────────────────────────────────")
        print(f"│ ID:          {Colors.BRIGHT}{tactic['id']}{Colors.NORMAL}")
        print(f"│ Technique:   {tactic['name']}")
        print(f"└──────────────────────────────────────────────────────────────{Colors.RESET}\n")