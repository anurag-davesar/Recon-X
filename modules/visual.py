import os
from utils import run_command, print_status, print_mitre_box


def capture_screenshots(ports_file, output_dir):
    print_mitre_box("visual_recon")
    print_status("Phase 4: Visual Recon...")
    
    screenshot_dir = os.path.join(output_dir, "screenshots")
    if not os.path.exists(screenshot_dir):
        os.makedirs(screenshot_dir)

    urls_file = os.path.join(output_dir, "final_urls.txt")
    
    # Swapped 'cat |' for the much safer '-l' list flag
    run_command(f"httpx -l {ports_file} -silent -o {urls_file}")
    
    
    if os.path.exists(urls_file) and os.path.getsize(urls_file) > 0:
        # We add 'scan file' and force the format to 'png' to match our counter
        run_command(f"gowitness scan file -f {urls_file} --screenshot-path {screenshot_dir} --screenshot-format png --threads 4")
        
        if os.path.exists(screenshot_dir):
            png_count = len([n for n in os.listdir(screenshot_dir) if n.endswith(".png")])
            # Check for jpegs too just in case
            jpeg_count = len([n for n in os.listdir(screenshot_dir) if n.endswith(".jpeg") or n.endswith(".jpg")])
            
            total_count = png_count + jpeg_count
            print_status(f"Captured {total_count} screenshots.", "success")
            return screenshot_dir, total_count
    
    print_status("No active HTTP/HTTPS URLs found from open ports.", "error")
    return None, 0