#!/usr/bin/env python3
# ============================================================
#   blackbox_enum.py — Black Box Enumeration Tool
# ============================================================

import argparse
import subprocess
import json
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

def info(msg):    print(f"{CYAN}[*]{RESET} {msg}")
def success(msg): print(f"{GREEN}[+]{RESET} {msg}")
def warning(msg): print(f"{YELLOW}[!]{RESET} {msg}")
def error(msg):   print(f"{RED}[-]{RESET} {msg}")

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

# ── REPORTER ────────────────────────────────────────────────
def save_report(target, results, output_dir):
    """Save results to a JSON file."""
    ensure_output_dir(output_dir)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
    filename    = os.path.join(output_dir, f"scan_{safe_target}_{timestamp}.json")
 
    report = {
        "target"    : target,
        "timestamp" : timestamp,
        "results"   : results
    }
 
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
 
    success(f"Report saved → {filename}")

# ── MODULE 1: PORT SCAN ─────────────────────────────────────
 
def port_scan(target):
    """Run nmap port scan against target."""
    info(f"Starting port scan on {target} ...")
 
    if not check_tool("nmap"):
        warning("nmap not found — skipping port scan. Install with: sudo apt install nmap")
        return {"error": "nmap not installed"}
 
    output = run_cmd(f"nmap -Pn -n {target} -sC -sV -p- --open")
 
    if not output:
        return {"error": "No output from nmap"}
 
    success("Port scan complete.")
    print(output)
    return {"raw": output}

# ── MAIN ────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Automated Black box Enumeration Tool"
    )
    parser.add_argument("-t", "--target", required=True, help="Target domain or IP (e.g. example.com or 127.0.0.1 )")
    parser.add_argument("-o", "--output", default="results", help="Output file (default: results)")

    args = parser.parse_args()
 
    target  = args.target
    results = {}

    print(f"{BOLD}Target  :{RESET} {args.target}")
    print(f"{BOLD}Output  :{RESET} {args.output}")
    print("-" * 60)

    results = port_scan(args.target)

    print("-" * 60)
    save_report(target, results, args.output)


if __name__ == "__main__":
    main()