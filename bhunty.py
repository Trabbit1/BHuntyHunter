#!/usr/bin/env python3
import os
import re
import sys
import subprocess
import urllib.parse
from pathlib import Path

def usage():
    print(r"""
    ____  __  __            __
   / __ )/ / / /_  ______  / /___  __
  / __  / /_/ / / / / __ \/ __/ / / /
 / /_/ / __  / /_/ / / / / /_/ /_/ /
/_____/_/ /_/\__,_/_/ /_/\__/\__, /
                            /____/

  BHunty 1.2 by Trabbit0ne
  ----------------------------------------
  Automated recon script: subdomains + Wayback URLs + optional sensitive keyword scan and parameter extraction.

  USAGE:
    python3 bhunty.py <domain or URL> [option(s)]

  OPTIONS:
    --sensitive    Scan Wayback URLs for sensitive keywords
    --param        Extract URLs with GET parameters

  OUTPUT:
    - results/<domain>/subdomains.txt
    - results/<domain>/waybackurls.txt
    - results/<domain>/sensitive.txt (if --sensitive)
    - results/<domain>/params.txt (if --param)
    """)

def extract_domain(input_url):
    try:
        parsed = urllib.parse.urlparse(input_url)
        if parsed.netloc:
            return parsed.netloc
        elif parsed.path:
            return parsed.path
        else:
            raise ValueError
    except Exception:
        print(f"[!] Invalid domain or URL: {input_url}")
        sys.exit(1)

def run_cmd(command, silent=False):
    try:
        if silent:
            return subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL).decode().splitlines()
        else:
            return subprocess.check_output(command, shell=True).decode().splitlines()
    except subprocess.CalledProcessError:
        return []

def print_banner():
    print(r"""
    ____  __  __            __
   / __ )/ / / /_  ______  / /___  __
  / __  / /_/ / / / / __ \/ __/ / / /
 / /_/ / __  / /_/ / / / / /_/ /_/ /
/_____/_/ /_/\__,_/_/ /_/\__/\__, /
                            /____/
""")

def draw_box(msg):
    try:
        from wcwidth import wcswidth
        width = wcswidth(msg)
    except ImportError:
        width = len(msg)
    width += 2
    print('+' + '-' * width + '+')
    print(f'| {msg} |')
    print('+' + '-' * width + '+')

def find_subdomains(domain, outdir):
    print("[*] Finding subdomains...")
    subs = set()

    subs.update(run_cmd(f"subfinder -all -silent -d {domain}", silent=True))
    subs.update([s for s in run_cmd(f"assetfinder --subs-only {domain}", silent=True) if domain in s])

    if not subs:
        print("[-] No subdomains found. Exiting.")
        sys.exit(1)

    subs_file = outdir / "subdomains.txt"
    subs_file.write_text('\n'.join(sorted(subs)))

    msg = f"✅  Found {len(subs)} subdomain{'s' if len(subs)!=1 else ''} for {domain}"
    draw_box(msg)
    return list(subs)

def fetch_waybackurls(subdomains, outdir):
    print("[*] Fetching Wayback URLs...")
    all_urls = []

    for i, sub in enumerate(subdomains, 1):
        print(f"  \U0001F310 {sub} [{i}/{len(subdomains)}]")
        try:
            urls = run_cmd(f"timeout 50s waybackurls https://{sub}", silent=True)
            all_urls.extend(urls)
        except Exception:
            continue

    # Deduplicate and write once
    wayback_file = outdir / "waybackurls.txt"
    unique_urls = sorted(set(all_urls))
    wayback_file.write_text('\n'.join(unique_urls))
    return wayback_file

def scan_sensitive(wayback_file, outdir):
    keywords = [
        "admin", "_next", "jwt", "login", "passwd", "password", "secret", "api", "key", "config",
        "debug", "token", "backup", "dump", "db", "sql", "shell", "root", "ssh", "env", "vault",
        "staging", "dev", "wp-admin", "wp-json", "cdn", "assets.", "wp-login.php",
        "credentials", "auth", "oauth", "session", "cookie", "access", "csrf", "xss", "adminpanel",
        "private", "secretkey", "apikey", "user", "users", "login.php", "register", "config.php",
        "config.yaml", "config.json", "backup.sql", "dump.sql", "database", "databases",
        "privatekey", "id_rsa", "id_dsa", "ssh_key", "token.json", "env.local", "env.production",
        "dev.local", "test", "uat", "passwords", "pass", "hash", "hashes", "encrypted", "decrypt",
        "api_token", "api_keys", "aws", "azure", "gcp", "s3", "credentials.json", "secret.json",
        "secret.key", "web.config", "htpasswd", "htaccess", "robots.txt", "error.log", "logs",
        "logs.txt", "debug.log", "config.bak", "backup.zip", "backup.tar", "dump.tar.gz"
    ]
    hits = []

    with open(wayback_file, 'r') as infile:
        for line in infile:
            line = line.strip()
            if any(k in line.lower() for k in keywords):
                hits.append(line)

    sensitive_file = outdir / "sensitive.txt"
    sensitive_file.write_text('\n'.join(sorted(set(hits))))
    print(f"\n\U0001F50D Found {len(hits)} potentially sensitive URL{'s' if len(hits)!=1 else ''}.")
    print(f" - Sensitive matches saved to: {sensitive_file}")

def extract_params(wayback_file, outdir):
    print("[*] Extracting URLs with parameters...")
    hits = []

    with open(wayback_file, 'r') as infile:
        for line in infile:
            line = line.strip()
            if '?' in line and '=' in line:
                hits.append(line)

    param_file = outdir / "params.txt"
    param_file.write_text('\n'.join(sorted(set(hits))))
    print(f"\U0001F50D Found {len(hits)} URLs with parameters.")
    print(f" - Parameterized URLs saved to: {param_file}")

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        usage()
        return

    input_url = sys.argv[1]
    domain = extract_domain(input_url)
    outdir = Path("results") / domain

    # Check if folder exists and is not empty
    if outdir.exists() and any(outdir.iterdir()):
        answer = input(f"[!] The folder '{outdir}' already exists and is not empty. Are you sure you want to scan again? [y/N]: ").strip().lower()
        if answer != 'y':
            print("[*] Scan aborted by user.")
            return

    outdir.mkdir(parents=True, exist_ok=True)

    print_banner()
    subdomains = find_subdomains(domain, outdir)
    wayback_file = fetch_waybackurls(subdomains, outdir)
    print(f"\n[✓] Saved:\n - Subdomains: {outdir}/subdomains.txt\n - WaybackURLs: {wayback_file}")

    # CLI flags
    scan_sensitive_flag = '--sensitive' in sys.argv
    extract_param_flag = '--param' in sys.argv

    if scan_sensitive_flag:
        scan_sensitive(wayback_file, outdir)
    if extract_param_flag:
        extract_params(wayback_file, outdir)

if __name__ == '__main__':
    main()
