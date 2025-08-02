<p align="center">
  <img src="https://i.ibb.co/rGHnVhCQ/bhunty-logo-removebg-preview.png" alt="BHunty Logo" width="500"/>
</p>

A modular and efficient Bash-based framework for web application reconnaissance, designed to streamline subdomain discovery, URL harvesting, and sensitive keyword scanning.

## 🚀 Features

- **Subdomain Enumeration**: Leverages `subfinder` to quickly identify active subdomains for a given target.
- **Wayback Machine URL Harvesting**: Gathers historical URLs from the Wayback Machine for all discovered subdomains using `waybackurls`.
- **Sensitive Keyword Scanning**: Automatically scans collected URLs for common sensitive indicators like `admin`, `password`, `api`, `token`, and more.
- **Structured Output**: Organizes all reconnaissance data into a dedicated `results/$domain/` directory for easy review and further analysis.
- **User-Friendly Interface**: Interactive prompts and clear output messages guide the user through the process.

## 🛠️ Installation

BHunty relies on a few external tools. Make sure you have them installed and accessible in your `PATH`.

### Clone the Repository

```bash
git clone https://github.com/Trabbit0ne/BHunty.git
cd BHunty
```
## Install Dependencies
subfinder: A fast subdomain enumeration tool
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```
wcwidth (Python module): Used for accurate display width calculation in the terminal
```bash
pip3 install wcwidth
```
## ⚡ Usage
Run BHunty from your terminal. You can provide the target domain as an argument or enter it when prompted.
```bash
./bhunty.sh [domain.com]
```
Or
```bash
./bhunty.sh
```
## Example
```bash
./bhunty.sh example.com
```
Or, run without an argument and enter the domain when prompted:
```bash
./bhunty.sh
```
```makefile
(Domain): example.com
```
The script will then:

1. Find subdomains.

2. Fetch Wayback URLs for each subdomain.

3. Ask if you want to perform a sensitive keyword scan.

## 📂 Output Structure
All results are saved within a results/ directory, organized by the target domain:
```graphql
results/
└── example.com/
    ├── subdomains.txt      # List of discovered subdomains
    ├── waybackurls.txt     # Unique URLs from Wayback Machine
    └── sensitive.txt       # (If scanned) URLs containing sensitive keywords
```
## 🔍 Sensitive Keyword Scanning
When prompted, you can choose to scan the `waybackurls.txt` file for a predefined list of sensitive keywords. This helps in quickly identifying potentially vulnerable or misconfigured endpoints that might expose sensitive information.

The keywords include, but are not limited to:
`admin`, `login`, `password`, `secret`, `api`, `token`, `config`, `debug`, `backup`, `dump`, `sql`, `shell`, `root`, `ssh`, `env`, `vault`, `staging`, `dev`, `wp-admin`, `wp-json`, `cdn`, `assets.`, `_next.`
## 🤝 Contributing
Contributions are welcome! If you have suggestions for improvements, new features, or bug fixes, feel free to open an issue or submit a pull request.
## 👤 Author
### Émile "trabbit" Durand
* GitHub: [github.com/Trabbit0ne](https://github.com/Trabbit0ne)
* Portfolio: [trabbit.glitch.me](https://trabbit.glitch.me)
* Medium Blog: [emiledurand.medium.com](https://emiledurand.medium.com)
* YouTube: [@TrabbitOne](https://youtube.com/@TrabbitOne)
