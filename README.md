<p align="center">
  <img src="https://i.ibb.co/rGHnVhCQ/bhunty-logo-removebg-preview.png" alt="BHunty Logo" width="500"/>
</p>

# BHunty [NEW UPDATE: 1.2]

**BHunty 1.2** is a Python-based bug bounty reconnaissance toolkit by [Trabbit0ne](https://trabbit.glitch.me).  
It automates **subdomain enumeration**, **Wayback Machine URL collection**, and optional **sensitive keyword scanning** for juicy recon findings.

---

## 🚀 Features

- 🔍 Subdomain enumeration using **Subfinder** and **Assetfinder**
- 📜 Archive URL collection via the **Wayback Machine**
- 🧠 Optional keyword scanning for common sensitive patterns (e.g., `password`, `token`, `jwt`, `wp-admin`, etc.)
- 📁 Clean output structure with result persistence
- ✅ Cross-platform compatible & easy to extend

---

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
   pip install wcwidth
   ```

3. Make sure the required binaries (`subfinder`, `assetfinder`, `waybackurls`) are in your `$PATH`.

---

## 🧪 Usage

```bash
python3 bhunty.py example.com
```

You can also pass a full URL (e.g., `https://sub.example.com/page`) — BHunty will extract the domain automatically.

You’ll be prompted whether you want to scan the archive URLs for sensitive keywords.

---

## 📁 Output Structure

```
results/
└── example.com/
    ├── subdomains.txt       # Enumerated subdomains
    ├── waybackurls.txt      # URLs pulled from the Wayback Machine
    └── sensitive.txt        # (Optional) Matched keywords in URLs
```

---

## 🔑 Keywords Scanned (Optional)

BHunty can optionally grep for common sensitive patterns like:

- `admin`, `login`, `password`, `secret`
- `token`, `api`, `jwt`, `config`, `env`
- `wp-admin`, `db`, `root`, `debug`
- and more…

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
