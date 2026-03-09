import subprocess
import shutil
import sys
from config import MITRE_MAPPING, Colors

def is_tool_installed(binary):
    """Checks if a tool exists in the system PATH."""
    return shutil.which(binary) is not None

def run_command(command):
    """Runs a shell command safely after verifying the tool exists."""
    # Extract the first word of the command (the binary name)
    binary = command.split()[0]

    # Pre-flight check
    if not is_tool_installed(binary):
        print(f"{Colors.RED}[ERROR] Tool '{binary}' is not installed or not in PATH.{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Please install it via: go install github.com/projectdiscovery/{binary}/v2/cmd/{binary}@latest{Colors.RESET}")
        return None

    try:
        # We use shell=True to support pipes and redirects within the command string
        result = subprocess.run(
            command, 
            shell=True, 
            check=True, 
            text=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        # Log the actual error from the tool for debugging
        if e.stderr:
            print(f"{Colors.RED}[DEBUG] {binary} Error: {e.stderr.strip()}{Colors.RESET}")
        return None

def print_status(message, level="info"):
    # ... (rest of your existing print_status code)
    if level == "info":
        print(f"{Colors.BLUE}[*]{Colors.RESET} {message}")
    elif level == "success":
        print(f"{Colors.GREEN}[+]{Colors.RESET} {message}")
    elif level == "error":
        print(f"{Colors.RED}[-]{Colors.RESET} {message}")
    elif level == "warning":
        print(f"{Colors.YELLOW}[!]{Colors.RESET} {message}")

def print_mitre_box(phase_key):
    # ... (rest of your existing print_mitre_box code)
    tactic = MITRE_MAPPING.get(phase_key, {})
    if tactic:
        print(f"\n{Colors.MAGENTA}┌── [ MITRE ATT&CK MAPPING ] ──────────────────────────────────")
        print(f"│ ID:          {Colors.BRIGHT}{tactic['id']}{Colors.NORMAL}")
        print(f"│ Technique:   {tactic['name']}")
        print(f"└──────────────────────────────────────────────────────────────{Colors.RESET}\n")