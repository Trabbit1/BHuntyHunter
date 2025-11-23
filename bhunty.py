#!/usr/bin/env python3
import os
import re
import sys
import subprocess
import urllib.parse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

def usage():
    print(r"""
    ____  __  __            __
   / __ )/ / / /_  ______  / /___  __
  / __  / /_/ / / / / __ \/ __/ / / /
 / /_/ / __  / /_/ / / / / /_/ /_/ /
/_____/_/ /_/\__,_/_/ /_/\__/\__, /
                            /____/

  BHunty 1.3 by Trabbit0ne (Python Edition)
  ----------------------------------------
  Automated recon script: subdomains + Wayback URLs + optional sensitive keyword scan and parameter extraction.

  USAGE:
    python3 bhunty.py <domain or URL> [options]

  OPTIONS:
    --sensitive     Scan Wayback URLs for sensitive keywords
    --param         Extract URLs with GET parameters
    --force         Skip overwrite prompt for existing result folders

  OUTPUT:
    - results/<domain>/subdomains.txt
    - results/<domain>/waybackurls.txt
    - results/<domain>/sensitive.txt (if --sensitive)
    - results/<domain>/params.txt (if --param)
    """)

def extract_domain(input_url):
    # Normalize
    if "://" not in input_url:
        input_url = "http://" + input_url

    parsed = urllib.parse.urlparse(input_url)
    domain = parsed.netloc.split(":")[0].strip()

    if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
        print(f"[!] Invalid domain or URL: {input_url}")
        sys.exit(1)

    return domain

def run_cmd(command, silent=False):
    try:
        if silent:
            out = subprocess.check_output(
                command,
                shell=True,
                stderr=subprocess.DEVNULL
            )
        else:
            out = subprocess.check_output(command, shell=True)

        return out.decode().splitlines()

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

    print("+" + "-" * (width + 2) + "+")
    print(f"| {msg} |")
    print("+" + "-" * (width + 2) + "+")

def find_subdomains(domain, outdir):
    print("[*] Finding subdomains...")
    subs = set()

    subs.update(run_cmd(f"subfinder -all -silent -d {domain}", silent=True))
    subs.update([s for s in run_cmd(f"assetfinder --subs-only {domain}", silent=True) if domain in s])

    if not subs:
        print("[-] No subdomains found.")
        sys.exit(1)

    subs_file = outdir / "subdomains.txt"
    subs_file.write_text("\n".join(sorted(subs)))

    draw_box(f"✅  Found {len(subs)} subdomain{'s' if len(subs)!=1 else ''} for {domain}")
    return sorted(subs)

def get_wayback(sub):
    return run_cmd(f"timeout 50s waybackurls https://{sub}", silent=True)

def fetch_waybackurls(subdomains, outdir):
    print("[*] Fetching Wayback URLs...")

    all_urls = []

    with ThreadPoolExecutor(max_workers=20) as pool:
        for i, result in enumerate(pool.map(get_wayback, subdomains), 1):
            print(f"  🌐 {subdomains[i-1]} [{i}/{len(subdomains)}]")
            all_urls.extend(result)

    unique = sorted(set(all_urls))
    wayback_file = outdir / "waybackurls.txt"
    wayback_file.write_text("\n".join(unique))

    return wayback_file

def scan_sensitive(wayback_file, outdir):
    keywords = [
        "admin", "_next", "jwt", "login", "passwd", "password", "secret",
        "api", "key", "config", "debug", "token", "backup", "dump", "db",
        "sql", "shell", "env", "vault", "staging", "dev", "wp-admin",
        "wp-json", "cdn", "credentials", "oauth", "cookie", "private",
        "apikey", "register", "config.php", "backup.sql", "dump.sql",
        "database", "privatekey", "id_rsa", "ssh", "token.json",
        "credentials.json", "secret.json", "web.config", "error.log"
    ]

    hits = []

    with open(wayback_file, "r") as f:
        for line in f:
            url = line.strip().lower()
            if any(k in url for k in keywords):
                hits.append(line.strip())

    outfile = outdir / "sensitive.txt"
    outfile.write_text("\n".join(sorted(set(hits))))

    print(f"\n🔍 Found {len(hits)} potentially sensitive URLs.")
    print(f" - Saved to: {outfile}")

def extract_params(wayback_file, outdir):
    print("[*] Extracting URLs with parameters...")

    results = []

    with open(wayback_file, "r") as f:
        for line in f:
            url = line.strip()
            if "?" in url and "=" in url:
                results.append(url)

    outfile = outdir / "params.txt"
    outfile.write_text("\n".join(sorted(set(results))))

    print(f"🔍 Found {len(results)} parameterized URLs.")
    print(f" - Saved to: {outfile}")

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        usage()
        return

    input_url = sys.argv[1]
    domain = extract_domain(input_url)
    outdir = Path("results") / domain

    force = "--force" in sys.argv

    # Safety check for existing folders
    if outdir.exists() and any(outdir.iterdir()) and not force:
        ans = input(f"[!] Folder '{outdir}' exists. Rescan? [y/N]: ").strip().lower()
        if ans != "y":
            print("[*] Scan aborted.")
            return

    outdir.mkdir(parents=True, exist_ok=True)

    print_banner()

    subdomains = find_subdomains(domain, outdir)
    wayback_file = fetch_waybackurls(subdomains, outdir)

    print(f"\n[✓] Saved:")
    print(f" - Subdomains: {outdir}/subdomains.txt")
    print(f" - Wayback URLs: {wayback_file}")

    if "--sensitive" in sys.argv:
        scan_sensitive(wayback_file, outdir)

    if "--param" in sys.argv:
        extract_params(wayback_file, outdir)

if __name__ == "__main__":
    main()
