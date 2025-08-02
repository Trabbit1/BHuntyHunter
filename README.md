<p align="center">
  <img src="https://i.ibb.co/rGHnVhCQ/bhunty-logo-removebg-preview.png" alt="BHunty Logo" width="500"/>
</p>

BHunty is a powerful Bash + Go-based bug bounty reconnaissance toolkit. It automates subdomain enumeration, archives discovery, and scans for sensitive keywords.

## 🚀 Features

- Subdomain enumeration using Subfinder
- Archive URL discovery with Wayback Machine
- Keyword scanning for juicy info like passwords, tokens, etc.
- Easy-to-read output formatting
- Clean file structure with result persistence

## 📦 Installation

Make sure you have [Go](https://go.dev/dl/) installed (version 1.18+ recommended).

Install BHunty CLI tool directly using:

```bash
go install github.com/Trabbit1/BHunty/cmd/bhunty@latest
```

This will install the `bhunty` binary in your `$GOPATH/bin` (or `$HOME/go/bin` by default).

Make sure that your Go bin path is in your `PATH` environment variable to run `bhunty` from anywhere:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

## 🧪 Usage

```bash
bhunty example.com
```

Results are saved in:

```
results/
  └── example.com/
      ├── subdomains.txt
      └── waybackurls.txt
```

## 🎯 Optional Scanning

BHunty can optionally scan archive URLs for sensitive keywords like:

- password
- token
- wp-admin
- api_key
- upload

## 📁 Project Structure

```
BHunty/
├── cmd/
│   └── bhunty/
│       └── main.go
├── go.mod
└── README.md
```

## 📜 License

MIT License
