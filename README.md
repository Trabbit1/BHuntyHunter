<p align="center">
  <img src="https://i.ibb.co/fYzjxr4N/output-onlinepngtools-2.png" alt="BHunty Logo" width="500"/>
</p>

# BHunty [NEW UPDATE: 1.2]

**BHunty 1.2** is a Python-based bug bounty reconnaissance toolkit by [Trabbit0ne](https://trabbit.glitch.me).  
It automates **subdomain enumeration**, **Wayback Machine URL collection**, and optional **sensitive keyword scanning** for juicy recon findings.

## ⚙️ Requirements

- Python 3.6+
- External tools required:
  - `subfinder`
  - `assetfinder`
  - `waybackurls`
- Optional:
  - [`wcwidth`](https://pypi.org/project/wcwidth/) (`pip install wcwidth`) — for proper message box width rendering

---

## 📦 Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/Trabbit1/BHunty
   cd BHunty
   ```

2. (Optional) Install the `wcwidth` module:
   ```bash
   pip3 install -r requirements.txt
   ```

3. Make sure the required binaries (`subfinder`, `assetfinder`, `waybackurls`) are in your `$PATH`.

---

## 🧪 Usage

```bash
python3 bhunty.py <domain or URL> [option(s)]
```

You can also pass a full URL (e.g., `https://sub.example.com/page`) — BHunty will extract the domain automatically.

You’ll be prompted whether you want to scan the archive URLs for sensitive keywords.

---
## 💡 Useful Usage Examples
#### Auto XSS
```bash
domain="domain.com"; yes y | bhunty "$domain" --param; clear; cat "results/$domain/params.txt" | dalfox pipe
```
#### Sensitive Access
```bash
domain="domain.com"; yes y | bhunty "$domain" --sensitive; clear; cat "results/$domain/sensitive.txt" | httpx -silent -sc
```
#### Auto 403 Discovery
```bash
domain="domain.com"; yes y | bhunty "$domain"; clear; cat "results/$domain/waybackurls.txt" | httpx -silent -mc 403
```
#### JWT Extractor
```bash
domain="domain.com"; yes y | bhunty "$domain"; clear; cat "results/$domain/waybackurls.txt" | grep -Eo 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
```
---


## 📁 Output Structure

```
results/
└── example.com/
    ├── subdomains.txt       # Enumerated subdomains
    ├── waybackurls.txt      # URLs pulled from the Wayback Machine
    ├── params.txt           # (Optional) Parameters in URLs
    └── sensitive.txt        # (Optional) Matched keywords in URLs
```

---

## 📂 Project Structure

```
BHunty/
  ├── bhunty.py
  └── README.md
```

---

## 🧑‍💻 Author

Made by [Trabbit0ne](https://trabbit.glitch.me)
