import os
from utils import run_command, print_status, print_mitre_box

def capture_screenshots(ports_file, output_dir):
    print_mitre_box("visual_recon")
    print_status("Phase 4: Visual Recon...")
    
    screenshot_dir = os.path.join(output_dir, "screenshots")
    if not os.path.exists(screenshot_dir):
        os.makedirs(screenshot_dir)

    urls_file = os.path.join(output_dir, "final_urls.txt")
    
    # Convert ports to URLs
    run_command(f"cat {ports_file} | httpx -silent -o {urls_file}")
    
    if os.path.exists(urls_file):
        run_command(f"gowitness scan file -f {urls_file} --screenshot-path {screenshot_dir} --threads 4")
        
        png_count = len([n for n in os.listdir(screenshot_dir) if n.endswith(".png")])
        print_status(f"Captured {png_count} screenshots.", "success")
        return screenshot_dir, png_count
    
    return None, 0