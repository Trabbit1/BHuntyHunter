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

  BHunty 1.1 by Trabbit0ne (Python Edition)
  ----------------------------------------
  Automated recon script: subdomains + Wayback URLs + optional sensitive keyword scan.

  USAGE:
    python3 bhunty.py <domain or URL>

  OUTPUT:
    - results/<domain>/subdomains.txt
    - results/<domain>/waybackurls.txt
    - results/<domain>/sensitive.txt (optional)
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

    subs_file = outdir / "subdomains.txt"
    subs_file.write_text('\n'.join(sorted(subs)))

    if not subs:
        print("[-] No subdomains found. Exiting.")
        sys.exit(1)

    msg = f"✅  Found {len(subs)} subdomain{'s' if len(subs)!=1 else ''} for {domain}"
    draw_box(msg)
    return list(subs)

def fetch_waybackurls(subdomains, outdir):
    print("[*] Fetching Wayback URLs...")
    wayback_file = outdir / "waybackurls.txt"
    with open(wayback_file, 'w') as f:
        for i, sub in enumerate(subdomains, 1):
            print(f"  \U0001F310 {sub} [{i}/{len(subdomains)}]")
            try:
                urls = run_cmd(f"timeout 50s waybackurls https://{sub}", silent=True)
                for url in urls:
                    f.write(url + '\n')
            except Exception:
                pass
    os.system(f"sort -u {wayback_file} -o {wayback_file}")
    return wayback_file

def scan_sensitive(wayback_file, outdir):
    keywords = [
        "admin", "_next", "jwt", "login", "passwd", "password", "secret", "api", "key", "config",
        "debug", "token", "backup", "dump", "db", "sql", "shell", "root", "ssh", "env", "vault",
        "staging", "dev", "wp-admin", "wp-json", "cdn", "assets."
    ]
    pattern = re.compile('|'.join(keywords), re.IGNORECASE)

    sensitive_file = outdir / "sensitive.txt"
    hits = []

    with open(wayback_file, 'r') as infile:
        for line in infile:
            if pattern.search(line):
                hits.append(line.strip())

    sensitive_file.write_text('\n'.join(sorted(set(hits))))
    print(f"\n\U0001F50D Found {len(hits)} potentially sensitive URL{'s' if len(hits)!=1 else ''}.")
    print(f" - Sensitive matches saved to: {sensitive_file}")

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        usage()
        return

    print_banner()

    input_url = sys.argv[1]
    domain = extract_domain(input_url)

    outdir = Path("results") / domain
    outdir.mkdir(parents=True, exist_ok=True)

    subdomains = find_subdomains(domain, outdir)
    wayback_file = fetch_waybackurls(subdomains, outdir)

    print(f"\n[✓] Saved:\n - Subdomains: {outdir}/subdomains.txt\n - WaybackURLs: {wayback_file}")

    try:
        choice = input("\n[?] Scan waybackurls.txt for sensitive keywords? [y/N]: ").strip().lower()
        if choice == 'y':
            scan_sensitive(wayback_file, outdir)
        else:
            print("[-] Skipping sensitive scan.")
    except KeyboardInterrupt:
        print("\n[-] Interrupted. Exiting.")

if __name__ == '__main__':
    main()
