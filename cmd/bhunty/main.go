package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func usage() {
	fmt.Println(`

    ____  __  __            __
   / __ )/ / / /_  ______  / /___  __
  / __  / /_/ / / / / __ \/ __/ / / /
 / /_/ / __  / /_/ / / / / /_/ /_/ /
/_____/_/ /_/\__,_/_/ /_/\__/_\__, /
                            /____/

  BHunty 1.1 by Trabbit0ne
  ------------------------
  Automated recon script: subdomains + Wayback URLs + optional sensitive keyword scan.

  USAGE:
    ./bhunty [domain or URL]

  EXAMPLES:
    ./bhunty example.com
    ./bhunty https://sub.domain.com/page
    ./bhunty               # Prompts you to enter domain interactively

  OPTIONS:
    -h, --help      Show this help message and exit

  OUTPUT:
    - results/<domain>/subdomains.txt     (Subfinder output)
    - results/<domain>/waybackurls.txt    (Wayback Machine URLs)
    - results/<domain>/sensitive.txt      (Optional sensitive keyword matches)
`)
}

func extractDomain(input string) string {
	var domain string
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		domain = strings.Split(strings.Split(input, "//")[1], "/")[0]
	} else {
		domain = input
	}

	matched, _ := regexp.MatchString(`^[a-zA-Z0-9.-]+$`, domain)
	if !matched {
		log.Fatalf("❌ Invalid domain or URL format: %s", input)
	}
	return strings.TrimSuffix(domain, ".")
}

func runCmd(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("❌ Error running %s: %v", name, err)
	}
	return string(out)
}

func writeLines(lines []string, filepath string) {
	f, err := os.Create(filepath)
	if err != nil {
		log.Fatalf("❌ Unable to write file: %v", err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, line := range lines {
		writer.WriteString(line + "\n")
	}
	writer.Flush()
}

func dedupLines(lines []string) []string {
	seen := make(map[string]struct{})
	var unique []string
	for _, line := range lines {
		if _, exists := seen[line]; line != "" && !exists {
			seen[line] = struct{}{}
			unique = append(unique, line)
		}
	}
	sort.Strings(unique)
	return unique
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		usage()
		return
	}

	fmt.Println(`
    ____  __  __            __
   / __ )/ / / /_  ______  / /___  __
  / __  / /_/ / / / / __ \/ __/ / / /
 / /_/ / __  / /_/ / / / / /_/ /_/ /
/_____/_/ /_/\__,_/_/ /_/\__/_\__, /
                            /____/
`)

	var rawInput string
	if len(os.Args) > 1 {
		rawInput = os.Args[1]
	} else {
		fmt.Print("(Domain or URL): ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		rawInput = scanner.Text()
	}

	domain := extractDomain(rawInput)
	outdir := filepath.Join("results", domain)
	os.MkdirAll(outdir, 0755)
	subsFile := filepath.Join(outdir, "subdomains.txt")
	waybackFile := filepath.Join(outdir, "waybackurls.txt")

	fmt.Println("[*] Finding subdomains...")
	output := runCmd("subfinder", "-silent", "-d", domain)
	subs := strings.Split(strings.TrimSpace(output), "\n")
	writeLines(subs, subsFile)

	if len(subs) == 0 {
		fmt.Println("[-] No subdomains found. Exiting.")
		return
	}

	fmt.Printf("+------------------------------+\n")
	fmt.Printf("| ✅  Found %d subdomains |\n", len(subs))
	fmt.Printf("+------------------------------+\n")

	fmt.Println("[*] Fetching waybackurls for all subdomains...")
	var allUrls []string
	for i, sub := range subs {
		fmt.Printf("  🌐 %s [%d/%d]\n", sub, i+1, len(subs))
		cmd := exec.Command("timeout", "50s", "waybackurls", "https://"+sub)
		out, _ := cmd.Output()
		urls := strings.Split(strings.TrimSpace(string(out)), "\n")
		allUrls = append(allUrls, urls...)
	}
	uniqueUrls := dedupLines(allUrls)
	writeLines(uniqueUrls, waybackFile)

	fmt.Printf("\n[✓] Saved:\n")
	fmt.Println(" - Subdomains:", subsFile)
	fmt.Println(" - WaybackURLs:", waybackFile)

	fmt.Print("\n[?] Scan waybackurls.txt for sensitive keywords? [y/N]: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	choice := strings.TrimSpace(scanner.Text())
	if strings.ToLower(choice) == "y" {
		fmt.Println("[*] Scanning for sensitive keywords...")
		keywords := []string{"admin", "login", "passwd", "password", "secret", "api", "key", "config", "debug", "token", "backup", "dump", "db", "sql", "shell", "root", "ssh", "env", "vault", "staging", "dev", "wp-admin", "wp-json", "cdn", "assets.", "_next"}
		pattern := strings.Join(keywords, "|")
		re := regexp.MustCompile(`(?i)` + pattern)
		matches := []string{}
		for _, line := range uniqueUrls {
			if re.MatchString(line) {
				matches = append(matches, line)
			}
		}
		sensitiveFile := filepath.Join(outdir, "sensitive.txt")
		writeLines(matches, sensitiveFile)
		fmt.Printf("\n🔍 Found %d potentially sensitive URLs.\n", len(matches))
		fmt.Println(" - Sensitive matches saved to:", sensitiveFile)
	} else {
		fmt.Println("[-] Skipping sensitive scan.")
	}
}
