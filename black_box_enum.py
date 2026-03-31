#!/usr/bin/env python3
# ============================================================
#   blackbox_enum.py — Black Box Enumeration Tool
# ============================================================

import argparse
import subprocess
import re
import os
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
                version = " ".join(parts[3:]) if len(parts) > 3 else ""

                clean_ver = clean_version(version)

                services.append({
                    "port"    : port,
                    "version" : clean_ver
                })
    
    cleaned = "\n".join(result) if result else "No open ports found."
    return cleaned, services

# ── REPORTER ────────────────────────────────────────────────

def save_report(target, nmap_output, exploit_findings, output_dir):
    """Save results """

    ensure_output_dir(output_dir)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
    filename    = os.path.join(output_dir, f"scan_{safe_target}_{timestamp}.json")
 
    report = {
        "target"    : target,
        "timestamp" : timestamp,
        "results"   : nmap_output
    }
 
    with open(filename, "w") as f:
        f.write("\n" + "=" * 60 + "\n")
        f.write("       BLACK BOX ENUMERATION REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"  Target    : {target}\n")
        f.write(f"  Date/Time : {timestamp}\n")
        f.write("=" * 60 + "\n\n")

        f.write("[PORT SCAN — NMAP]\n")
        f.write("-" * 60 + "\n")
        if nmap_output:
            f.write(str(nmap_output) + "\n")
        else:
            f.write("No results.\n")
        f.write("\n")

        # Searchsploit results
        f.write("[SEARCHSPLOIT — EXPLOIT FINDINGS]\n")
        f.write("-" * 60 + "\n")
        if exploit_findings:
            for service_key, output in exploit_findings.items():
                f.write(f"\n  >> {service_key}\n")
                f.write("  " + "-" * 40 + "\n")
                f.write(output + "\n")
        else:
            f.write("  No exploits found for discovered services.\n")
        f.write("\n")

        f.write("=" * 60 + "\n")
        f.write("  END OF REPORT\n")
        f.write("=" * 60 + "\n")
 
    success(f"Report saved → {filename}")

# ── MODULE 1: PORT SCAN ─────────────────────────────────────
 
def port_scan(target):
    """Run nmap port scan against target."""
    print("\n" + "=" * 60 + "\n")
    print(f"{RESET} NETWORK ENUMERATION")
    print("=" * 60 + "\n")
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

# ── MODULE 2: searchsploit ─────────────────────────────────────

def run_searchsploit(services):
    """
    Run searchsploit using cleaned version string only.
    Only saves results where exploits were found.
    """

    print("\n" + "=" * 60 + "\n")
    print(f"{RESET} VULNERABILITY SEARCH")
    print("=" * 60 + "\n")
    info("Starting searchsploit on discovered services ...")
 
    if not check_tool("searchsploit"):
        warning("searchsploit not found — skipping. Install: sudo apt install exploitdb")
        return {}
 
    findings = {}
 
    for s in services:
        version = s["version"].strip()
        port    = s["port"].strip()
 
        # Skip if no version to search
        if not version or version.lower() == "tcpwrapped":
            continue
 
        # Search by version only e.g. "OpenSSH 5.3"
        info(f"Searching exploits for: {version}")
        output = run_cmd(f"searchsploit {version}")
 
        # Skip if no results
        if not output or "No Results" in output or "Exploits: No Results" in output:
            continue
 
        # key = f"{port} — {version}"
        # findings[key] = output
        success(f"Exploits found for {version}!")
        print(output)
 
    if not findings:
        warning("No exploits found for any discovered service.")
 
    return findings

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

    nmap_results, services = port_scan(args.target)

    searchsploit_results= {}
    searchsploit_results = run_searchsploit(services)

    print("-" * 60)
    save_report(args.target, nmap_results, searchsploit_results, args.output)


if __name__ == "__main__":
    main()