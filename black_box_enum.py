#!/usr/bin/env python3
# ============================================================
#   blackbox_enum.py — Black Box Enumeration Tool
# ============================================================

import argparse
import subprocess
import re
import os
import ftplib
from datetime import datetime


# ── BANNER ──────────────────────────────────────────────────
 
BANNER = r"""
██████╗ ██╗      █████╗  ██████╗██╗  ██╗██████╗  ██████╗ ██╗  ██╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗╚██╗██╔╝
██████╔╝██║     ███████║██║     █████╔╝ ██████╔╝██║   ██║ ╚███╔╝ 
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██╗██║   ██║ ██╔██╗ 
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██████╔╝╚██████╔╝██╔╝ ██╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝
        Black Box Enumeration Tool v1.0 — For authorized use only
"""

# ── COLORS ──────────────────────────────────────────────────
 
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def info(msg):    print(f"{CYAN}[*] {msg}")
def success(msg): print(f"{GREEN}[+] {msg}")
def warning(msg): print(f"{YELLOW}[!] {msg}")
def error(msg):   print(f"{RED}[-] {msg}")

# ── UTILS ───────────────────────────────────────────────────
 
def run_cmd(cmd):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=120
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        warning(f"Command timed out: {cmd}")
        return ""
    except Exception as e:
        error(f"Command failed: {e}")
        return ""
 
def check_tool(tool):
    """Check if a tool is installed."""
    result = subprocess.run(f"which {tool}", shell=True, capture_output=True)
    return result.returncode == 0
 
def ensure_output_dir(path):
    """Create output directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)

def clean_version(version_str):
    """
    Extract just the product name and version number.
    e.g. "OpenSSH 5.3 (protocol 2.0)"  -> "OpenSSH 5.3"
         "Apache httpd 2.2.15 (CentOS)" -> "Apache httpd 2.2.15"
         "Asterisk Call Manager 1.3"     -> "Asterisk Call Manager 1.3"
    """
    if not version_str:
        return ""
 
    # Match everything up to and including the first version number (x.x or x.x.x)
    match = re.match(r"^(.*?\d+\.\d+[\.\d]*)", version_str)
    if match:
        return match.group(1).strip()
 
    # Fallback: return first 3 words if no version number pattern found
    words = version_str.split()
    return " ".join(words[:3])

def run_cmd_searchsploit(cmd):
    """
    Run searchsploit specifically — combines stdout + stderr
    because searchsploit writes its table to stderr, not stdout.
    """
    try:
        result = subprocess.run(
    		["searchsploit"] + cmd.split(),
    		stdout=subprocess.PIPE,
    		stderr=subprocess.PIPE,
    		text=True
)
        # Combine both streams so we never miss output
        combined = (result.stdout + result.stderr).strip()
        return combined
        
    except subprocess.TimeoutExpired:
        warning(f"Command timed out: {cmd}")
        return ""
    except Exception as e:
        error(f"Command failed: {e}")
        return ""
    
def run_cmd_ftp(cmd):
    """
    Run searchsploit specifically — combines stdout + stderr
    because searchsploit writes its table to stderr, not stdout.
    """
    try:
        result = subprocess.run(
    		["searchsploit"] + cmd.split(),
    		stdout=subprocess.PIPE,
    		stderr=subprocess.PIPE,
    		text=True
)
        # Combine both streams so we never miss output
        combined = (result.stdout + result.stderr).strip()
        return combined
        
    except subprocess.TimeoutExpired:
        warning(f"Command timed out: {cmd}")
        return ""
    except Exception as e:
        error(f"Command failed: {e}")
        return ""

# ── PARSE OUTPUT ───────────────────────────────────────
 
def parse_nmap(raw):
    """Extract only the port table from nmap output."""
    lines  = raw.splitlines()
    result = []
    services = []
 
    for line in lines:
        stripped = line.strip()
 
        # Keep the PORT header line
        if stripped.startswith("PORT") and "STATE" in stripped:
            result.append(line)
            continue
 
        # Keep only lines that start with a port number e.g. 22/tcp
        if "/" in stripped and len(stripped) > 0:
            first_token = stripped.split()[0] if stripped.split() else ""
            if "/" in first_token and (
                first_token.endswith("tcp") or first_token.endswith("udp")
            ):
                result.append(line)

                parts = stripped.split()
                port = parts[0] if len(parts) > 0 else ""
                service = parts[2] if len(parts) > 2 else ""
                version = " ".join(parts[3:]) if len(parts) > 3 else ""

                clean_ver = clean_version(version)

                services.append({
                    "port"    : port,
                    "service" : service,
                    "version" : clean_ver
                })
    
    cleaned = "\n".join(result) if result else "No open ports found."
    return cleaned, services

# ── REPORTER ────────────────────────────────────────────────

def save_report(target, nmap_output, exploit_findings, dir_findings, output_dir):
    """Save results """

    ensure_output_dir(output_dir)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
    filename    = os.path.join(output_dir, f"{safe_target}.txt")
 
    report = {
        "target"    : target,
        "timestamp" : timestamp,
        "results"   : nmap_output
    }
 
    with open(filename, "w") as f:
        f.write("\n" + "=" * 60 + "\n")
        f.write("\tBLACK BOX ENUMERATION REPORT\n")
        f.write("=" * 60 + "\n" + "\n")

        #==========================================================
        # Network Scanning Reports
        # =========================================================
        f.write(f"  Target    : {target}\n")
        f.write(f"  Date/Time : {timestamp}\n")
        f.write("\n" + "=" * 60 + "\n")

        f.write("[PORT SCAN — NMAP]\n")
        f.write("-" * 60 + "\n")
        if nmap_output:
            f.write(str(nmap_output) + "\n")
        else:
            f.write("No results.\n")
        f.write("\n")

        #==========================================================
        # searchsloitReports
        # =========================================================
        f.write("[SEARCHSPLOIT — EXPLOIT FINDINGS]\n")
        f.write("-" * 60 + "\n")
        if exploit_findings:
            for service_key, output in exploit_findings.items():
                f.write(f"\n{service_key}\n")
                f.write("-" * 60 + "\n")
                f.write(output + "\n")
        else:
            f.write("  No exploits found for discovered services.\n")
        f.write("\n")

        #==========================================================
        # Directory Port Researching
        # =========================================================
        f.write("Web Directory Brute Forcing\n")
        f.write("\n"+ "-" * 60 + "\n")
        if dir_findings:
            for service_key, output in dir_findings.items():
                f.write(f"\nPort: {service_key}\n")
                f.write("-" * 60 + "\n")
                f.write(output + "\n")
        else:
            f.write("No directory found for discovered services.\n")
        f.write("\n")

        f.write("=" * 60 + "\n")
        f.write("  END OF REPORT\n")
        f.write("=" * 60 + "\n")
 
    success(f"Report saved → {filename}")

# ── MODULE 1: PORT SCAN ─────────────────────────────────────
 
def port_scan(target):
    """Run nmap port scan against target."""
   
    print(f"\n {RESET} NETWORK ENUMERATION")
    print("-" * 60 + "\n")
    info(f"Starting port scan on {target} ... \n")
 
    if not check_tool("nmap"):
        warning("nmap not found — skipping port scan. Install with: sudo apt install nmap")
        return {"error": "nmap not installed"}
 
    output = run_cmd(f"nmap -Pn -n {target} -sC -sV -p- --open")
 
    if not output:
        return {"error": "No output from nmap"}
 
    cleaned, services = parse_nmap(output)

    print(f"{RESET} {cleaned} \n")
    success("Port scan complete.")

    return cleaned, services

# ── MODULE 2: searchsploit ──────────────────────────────────

def run_searchsploit(services):
    """
    Run searchsploit using cleaned version string only.
    Only saves results where exploits were found.
    """

    print("\n" + "=" * 60 + "\n")
    print(f"{RESET} Vulnerability Service Version SEARCH")
    print("=" * 60 + "\n")
    info("Starting searchsploit on discovered services ...")
 
    if not check_tool("searchsploit"):
        warning("searchsploit not found — skipping. Install: sudo apt install exploitdb")
        return {}
 
    findings = {}
    # searched  = set()
 
    for s in services:
        version = s["version"].strip()
        port    = s["port"].strip()
 
        # Skip if no version to search
        if not version or version.lower() == "tcpwrapped":
            continue
 
        # Search by version only e.g. "OpenSSH 5.3"
        info(f"Searching exploits for: {version}")
        output = run_cmd_searchsploit(version)
 
        if not output:
            warning(f"Empty output for: {version}")
            continue
 	
 	# Skip if no exploits found
        if "Exploits: No Results" in output and "Shellcodes: No Results" in output:
            warning(f"Couldn't find any exploit for {version}! \n")
            continue
            
        print(f"{RESET} {output}")
        key = f"{port} — {version}"
        findings[key] = output
        success(f"Exploits found for {version}!\n")
        
 
    if not findings:
        warning("No exploits found for any discovered service.\n")
 
    return findings

# ── MODULE 3: FTP Enumeration ─────────────────────────────────────
 
def ftp_enum(target, services):
    """
    FTP enumeration — tries anonymous login by default.
    If connected:
      - Lists all files
      - Downloads all files (mget *)
      - Tests upload permission
    """
   
    print(f"\n {RESET} FTP ENUMERATION")
    print("-" * 60 + "\n")

    ftp_finding={}

    for s in services:
        service = s["service"]. strip()
        port    = s["port"].strip().split("/")[0]
        int_port = int(port)

        if service in ("ftp", "ftps", "tftp", "ftp-data"):
            info(f"FOUND ftp service on {port} - Attempting Anonymous Login \n")
            info(f"Connecting to FTP {target}:{port} as anonymous")

            try:
                # ==================== Connect and Login =======================
                ftp = ftplib.FTP()
                ftp.connect(target, int_port, timeout=10)
                ftp.login("anonymous", "anonymous")
                success(f"Login successful as anonymous!")
                ftp_finding[f"{port} - login"] = f"Login successful as anonymous"

                # ===================== List File ==============================
                info(f"Listing Files")
                files = ftp.nlst()
                if files:
                    success(f"Found {len(files)} file(s): ")
                    for f in files:
                        print(f"{RESET} {f}")
                    ftp_finding[f"{port} — listing"] = "\n".join(files)
                else:
                    warning("Directory is empty.")

                # ── STEP 3: Download all files (mget *) ────
                info("Downloading all files ...")
                download_dir = f"ftp_loot/{target}_{port}"
                os.makedirs(download_dir, exist_ok=True)

                downloaded = []
                for filename in files:
                    try:
                        local_path = os.path.join(download_dir, filename)
                        with open(local_path, "wb") as lf:
                            ftp.retrbinary(f"RETR {filename}", lf.write)
                        downloaded.append(filename)
                        success(f"Downloaded → {local_path}")
                    except Exception:
                        warning(f"Could not download {filename} — skipping.")

                ftp_finding[f"{port} — downloaded"] = "\n".join(downloaded) if downloaded else "Nothing downloaded."

                # ── STEP 4: Test upload ─────────────────────
                info("Testing upload permission ...")
                test_file = "test.txt"
                with open(test_file, "w") as tf:
                    tf.write("upload test - blackbox_enum\n")

                try:
                    with open(test_file, "rb") as tf:
                        ftp.storbinary(f"STOR {test_file}", tf)
                    success("Upload SUCCESSFUL — FTP is writable!")
                    ftp_finding[f"{port} — upload"] = "WRITABLE — upload succeeded."
                except Exception:
                    warning("Upload failed — FTP is read-only.")
                    ftp_finding[f"{port} — upload"] = "Read-only — upload failed."

                os.remove(test_file)
                ftp.quit()

            except ftplib.error_perm as e:
                warning(f"Login failed: {e}")
                ftp_finding[f"{port} — login"] = f"Login failed: {e}"
            except Exception as e:
                error(f"FTP connection error: {e}")

        return ftp_finding
            
        #     if not check_tool("ftp"):
        #         warning("ftp not found — skipping port scan. Install with: sudo apt install ftp")
        #         return {"error": "ftp not installed"}
    
        #     output = run_cmd(f"ftp $ip")

        #     print(f"{RESET} {output}")

        #     if not output:
        #         return {"error": "No output from gobuster"}
            
        #     key = f"{port}"
        #     ftp_finding[key] = output
        #     success(f"Hidden Directory found for {port}!\n")

        # else:
        #     continue

    # return ftp_finding

# ── MODULE 4: Web Directory BruteForcing ─────────────────────────────────────
 
def directory_bruteforcing(target, services):
    """Run directory brute forcing against target."""
   
    print(f"\n {RESET} Web Directory Brute Forcing")
    print("-" * 60 + "\n")

    dir_finding={}

    for s in services:
        service = s["service"]. strip()
        port    = s["port"].strip().split("/")[0]

        if service in ("http", "https", "http-alt", "http-proxy", "http-mgmt") or "http" in service or "ssl" in service:
            info(f"Starting web directory bruteforcing on {port} ... \n")
            
            if not check_tool("gobuster"):
                warning("nmap not found — skipping port scan. Install with: sudo apt install gobuster")
                return {"error": "gobuster not installed"}
    
            output = run_cmd(f"gobuster dir -u http://{target}:{port} -w /usr/share/wordlists/dirb/common.txt -t 42")

            print(f"{RESET} {output}")

            if not output:
                return {"error": "No output from gobuster"}
            
            key = f"{port}"
            dir_finding[key] = output
            success(f"Hidden Directory found for {port}!\n")

        else:
            continue

    return dir_finding

# ── MAIN ────────────────────────────────────────────────────
def main():
    
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Automated Black box Enumeration Tool"
    )
    parser.add_argument("-t", "--target", required=True, help="Target domain or IP (e.g. example.com or 127.0.0.1 )")
    parser.add_argument("-o", "--output", default="results", help="Output file (default: results)")

    args = parser.parse_args()
 
    # target  = args.target
    # results = {}

    print("=" * 60)
    print(f"{BOLD}Target  :{RESET} {args.target}")
    print(f"{BOLD}Output  :{RESET} {args.output}")
    print("=" * 60)

    # Execute Network Scanning
    nmap_results, services = port_scan(args.target)

    # Execute version vulnerability search
    searchsploit_results= {}
    searchsploit_results = run_searchsploit(services)

    # FTP enumeration
    ftp_results = {}
    ftp_results = ftp_enum(args.target, services)

    # Directory Brute Forcing
    dir_search_results = directory_bruteforcing(args.target, services)

    print("-" * 60)
    save_report(args.target, nmap_results, searchsploit_results, dir_search_results, args.output)


if __name__ == "__main__":
    main()
