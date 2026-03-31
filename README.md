BlackBox Enum is a Python-based reconnaissance tool designed to automate 
the enumeration phase of black box penetration testing. It integrates 
common security tools — including nmap, ffuf, and nuclei — into a single 
streamlined script, enabling faster and more consistent recon workflows.

Built for security professionals, bug bounty hunters, and students looking 
to sharpen their offensive security skills.

Features:
- Port scanning via nmap
- Subdomain enumeration
- Directory fuzzing via ffuf
- HTTP probing and tech stack detection
- Vulnerability scanning via nuclei
- JSON report output

Usage:
  python3 blackbox_enum.py -t <target> -m ports subdomains http

Disclaimer: This tool is intended for authorized testing only. 
Always obtain proper permission before scanning any target.