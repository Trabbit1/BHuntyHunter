#!/bin/bash

clear

cat << "EOF"
888 88b, 888 888 8888 8888 Y88b Y88 88P'888'Y88 Y88b Y8P
888 88P' 888 888 8888 8888  Y88b Y8 P'  888  'Y  Y88b Y   BHunty 1.1
888 8K   8888888 8888 8888 b Y88b Y     888       Y88b    Trabbit0ne
888 88b, 888 888 8888 8888 8b Y88b      888        888
888 88P' 888 888 'Y88 88P' 88b Y88b     888        888

EOF

if [[ -n "$1" ]]; then
    domain="$1"
else
    read -rp "(Domain): " domain
fi

# Output directory
outdir="results/$domain"
mkdir -p "$outdir"

subs_file="$outdir/subdomains.txt"
wayback_file="$outdir/waybackurls.txt"

# Clean up old results
> "$subs_file"
> "$wayback_file"

echo "[*] Finding subdomains..."
output=$(subfinder -silent -d "$domain")
cat <<< "$output" > "$subs_file"

count_subs=$(wc -l < "$subs_file" | tr -d ' ')
msg="✅  Found $count_subs subdomain$( [[ $count_subs -ne 1 ]] && echo s ) for $domain"

# Use Python to get display width of the message
display_width=$(python3 -c "import sys; from wcwidth import wcswidth; print(wcswidth(sys.argv[1]))" "$msg")
# fallback
if [[ -z "$display_width" || "$display_width" -lt 1 ]]; then
  display_width=${#msg}
fi

width=$(( display_width + 2 ))

# Print box
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

###########################################
# ➕ Ask if user wants to scan for sensitive stuff
###########################################

read -rp $'\n[?] Scan waybackurls.txt for sensitive keywords? [y/N]: ' do_scan
if [[ "$do_scan" =~ ^[Yy]$ ]]; then
    echo "[*] Scanning for sensitive keywords..."

    keywords=(
        admin
        login
        passwd
        password
        secret
        api
        key
        config
        debug
        token
        backup
        dump
        db
        sql
        shell
        root
        ssh
        env
        vault
        staging
        dev
        wp-admin
        wp-json
        cdn
        assets.
        _next
    )

    sensitive_file="$outdir/sensitive.txt"
    > "$sensitive_file"

    for keyword in "${keywords[@]}"; do
        grep -i "$keyword" "$wayback_file" >> "$sensitive_file"
    done

    sort -u "$sensitive_file" -o "$sensitive_file"

    hits=$(wc -l < "$sensitive_file" | tr -d ' ')
    echo -e "\n🔍 Found $hits potentially sensitive URL$( [[ $hits -ne 1 ]] && echo s )."
    echo " - Sensitive matches saved to: $sensitive_file"
else
    echo "[-] Skipping sensitive scan."
fi
