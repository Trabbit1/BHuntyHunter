#!/bin/bash

# Usage/help function
usage() {
    cat <<EOF

    ____  __  __            __
   / __ )/ / / /_  ______  / /___  __
  / __  / /_/ / / / / __ \/ __/ / / /
 / /_/ / __  / /_/ / / / / /_/ /_/ /
/_____/_/ /_/\__,_/_/ /_/\__/\__, /
                            /____/

  BHunty 1.1 by Trabbit0ne
  ------------------------
  Automated recon script: subdomains + Wayback URLs + optional sensitive keyword scan.

  USAGE:
    ./bhunty.sh [domain or URL]

  EXAMPLES:
    ./bhunty.sh example.com
    ./bhunty.sh https://sub.domain.com/page
    ./bhunty.sh               # Prompts you to enter domain interactively

  OPTIONS:
    -h, --help      Show this help message and exit

  OUTPUT:
    - results/<domain>/subdomains.txt     (Subfinder + Assetfinder merged)
    - results/<domain>/waybackurls.txt    (Wayback Machine URLs)
    - results/<domain>/sensitive.txt      (Optional sensitive keyword matches)

EOF
}

# Reject unknown flags, allow only -h/--help or domain/url
if [[ $# -eq 0 ]]; then
    :
elif [[ "$1" == "-h" || "$1" == "--help" ]]; then
    usage
    exit 0
elif [[ "$1" == -* ]]; then
    echo "❌ Unknown option: $1"
    echo "Run with -h or --help for usage."
    exit 1
fi

# Extract and validate domain from URL or raw input
extract_domain() {
    local input="$1"
    local host=""

    if [[ "$input" =~ ^https?:// ]]; then
        host="${input#*://}"
        host="${host%%/*}"
    else
        host="$input"
    fi

    if [[ ! "$host" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo "❌ Invalid domain or URL format: $input"
        exit 1
    fi

    host="${host%.}"
    if [[ -z "$host" ]]; then
        echo "❌ Invalid domain or URL format: $input"
        exit 1
    fi

    echo "$host"
}

clear
cat << "EOF"
    ____  __  __            __
   / __ )/ / / /_  ______  / /___  __
  / __  / /_/ / / / / __ \/ __/ / / /
 / /_/ / __  / /_/ / / / / /_/ /_/ /
/_____/_/ /_/\__,_/_/ /_/\__/\__, /
                            /____/

EOF

# Prompt input if no argument
if [[ -n "$1" ]]; then
    raw_input="$1"
else
    read -rp "(Domain or URL): " raw_input
fi

domain=$(extract_domain "$raw_input")

# Output setup
outdir="results/$domain"
mkdir -p "$outdir"
subs_file="$outdir/subdomains.txt"
wayback_file="$outdir/waybackurls.txt"
> "$subs_file"
> "$wayback_file"

echo "[*] Finding subdomains..."

# Subfinder
subfinder -all -silent -d "$domain" > "$outdir/_subs_subfinder.txt"

# Assetfinder
assetfinder --subs-only "$domain" | grep -i "$domain" > "$outdir/_subs_assetfinder.txt"

# Merge and deduplicate
cat "$outdir"/_subs_*.txt | sort -u > "$subs_file"
rm "$outdir"/_subs_*.txt 2>/dev/null

if [[ ! -s "$subs_file" ]]; then
    echo "[-] No subdomains found. Exiting."
    exit 1
fi

count_subs=$(wc -l < "$subs_file" | tr -d ' ')
msg="✅  Found $count_subs subdomain$( [[ $count_subs -ne 1 ]] && echo s ) for $domain"

# Use Python wcwidth if available
if command -v python3 >/dev/null; then
    display_width=$(python3 -c "import sys; from wcwidth import wcswidth; print(wcswidth(sys.argv[1]))" "$msg")
else
    display_width=${#msg}
fi
[[ -z "$display_width" || "$display_width" -lt 1 ]] && display_width=${#msg}
width=$(( display_width + 2 ))

printf '+%*s+\n' "$width" '' | tr ' ' '-'
printf '| %s |\n' "$msg"
printf '+%*s+\n' "$width" '' | tr ' ' '-'

echo
echo "[*] Fetching waybackurls for all subdomains..."

total=$(wc -l < "$subs_file" | tr -d ' ')
count=0

while IFS= read -r sub; do
    ((count++))
    echo "  🌐 $sub [$count/$total]"
    timeout 50s waybackurls "https://$sub" >> "$wayback_file" 2>/dev/null
done < "$subs_file"

sort -u "$wayback_file" -o "$wayback_file"

echo -e "\n[✓] Saved:"
echo " - Subdomains: $subs_file"
echo " - WaybackURLs: $wayback_file"

read -rp $'\n[?] Scan waybackurls.txt for sensitive keywords? [y/N]: ' do_scan
if [[ "$do_scan" =~ ^[Yy]$ ]]; then
    echo "[*] Scanning for sensitive keywords..."

    keywords=(
        admin login passwd password secret api key config debug token
        backup dump db sql shell root ssh env vault staging dev
        wp-admin wp-json cdn assets. _next
    )

    sensitive_file="$outdir/sensitive.txt"
    > "$sensitive_file"

    grep -iE "$(IFS='|'; echo "${keywords[*]}")" "$wayback_file" > "$sensitive_file"
    sort -u "$sensitive_file" -o "$sensitive_file"

    hits=$(wc -l < "$sensitive_file" | tr -d ' ')
    echo -e "\n🔍 Found $hits potentially sensitive URL$( [[ $hits -ne 1 ]] && echo s )."
    echo " - Sensitive matches saved to: $sensitive_file"
else
    echo "[-] Skipping sensitive scan."
fi
