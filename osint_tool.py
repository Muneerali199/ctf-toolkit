import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
import requests
import whois
import socket
import json
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import argparse

# 1. Username checker
def check_username(username):
    print(f"\n[*] Checking username: {username}")
    platforms = {
        "GitHub": f"https://api.github.com/users/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}/about.json",
        "Instagram": f"https://www.instagram.com/{username}/"
    }
    
    for platform, url in platforms.items():
        try:
            if platform == "GitHub":
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    print(f"[+] Found on {platform}: {url}")
            elif platform == "Reddit":
                r = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
                if "error" not in r.text:
                    print(f"[+] Found on {platform}: https://reddit.com/u/{username}")
            else:
                r = requests.get(url, allow_redirects=False, timeout=5)
                if r.status_code == 200:
                    print(f"[+] Found on {platform}: {url}")
        except Exception as e:
            print(f"[-] Error checking {platform}: {e}")
        time.sleep(1) # Rate limiting

# 2. Email breach checker
def check_email(email):
    print(f"\n[*] Checking HaveIBeenPwned for email: {email}")
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "User-Agent": "CTF-OSINT-Toolkit",
    }
    print("[!] HIBP API requires a key. Simulating request...")
    try:
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            print(f"[!] Email '{email}' found in breaches:")
            for breach in r.json():
                print(f"  - {breach['Name']}")
        elif r.status_code == 404:
            print(f"[+] Good news — no pwnage found for {email}!")
        elif r.status_code == 401:
            print("[-] API key required for HaveIBeenPwned.")
    except Exception as e:
        print(f"[-] Error: {e}")

# 3. WHOIS lookup
def get_whois(domain):
    print(f"\n[*] WHOIS lookup for {domain}")
    try:
        w = whois.whois(domain)
        print(w.text if hasattr(w, 'text') else str(w))
    except Exception as e:
        print(f"[-] WHOIS Error: {e}")

# 4. IP geolocation & reverse DNS
def ip_info(ip_or_domain):
    print(f"\n[*] IP / Reverse DNS Info for {ip_or_domain}")
    try:
        ip = socket.gethostbyname(ip_or_domain)
        print(f"[+] IP: {ip}")
        try:
            rdns = socket.gethostbyaddr(ip)
            print(f"[+] Reverse DNS: {rdns[0]}")
        except socket.herror:
            print("[-] Reverse DNS not found.")
            
        # Geolocation via ipinfo.io
        url = f"https://ipinfo.io/{ip}/json"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            print(f"[+] Location: {data.get('city')}, {data.get('region')}, {data.get('country')}")
            print(f"[+] Org: {data.get('org')}")
    except Exception as e:
        print(f"[-] IP Info Error: {e}")

# 5. Google dorking generator
def generate_dorks(domain):
    print(f"\n[*] Google Dorking Queries for {domain}")
    dorks = [
        f"site:{domain}",
        f"site:{domain} filetype:pdf",
        f"site:{domain} inurl:admin",
        f"site:{domain} intitle:index.of",
        f"site:{domain} \"password\"",
    ]
    for dork in dorks:
        print(f"  {dork}")
        
# 6. Wayback Machine URL fetcher
def wayback_urls(domain):
    print(f"\n[*] Fetching URLs from Wayback Machine for {domain}")
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&collapse=urlkey"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            results = r.json()
            if len(results) > 1:
                print(f"[+] Found {len(results)-1} URLs. Showing first 10:")
                for row in results[1:11]:
                    print(f"  {row[2]}")
            else:
                print("[-] No URLs found.")
    except Exception as e:
        print(f"[-] Wayback Error: {e}")

# 7. Metadata scraper from public URLs
def scrape_metadata(url):
    print(f"\n[*] Scraping metadata from {url}")
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, 'html.parser')
        print("[+] Title:", soup.title.string if soup.title else "None")
        
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            name = tag.get('name', tag.get('property'))
            content = tag.get('content')
            if name and content:
                print(f"  {name}: {content[:100]}")
                
        links = soup.find_all('a')
        print(f"[+] Found {len(links)} links on page.")
    except Exception as e:
        print(f"[-] Scrape Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTF OSINT Toolkit")
    parser.add_argument("--domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--username", help="Check username across platforms")
    parser.add_argument("--email", help="Check email against breaches")
    parser.add_argument("--ip", help="Check IP info")
    
    args = parser.parse_args()
    print("=== CTF OSINT Toolkit ===")
    
    if args.domain:
        get_whois(args.domain)
        ip_info(args.domain)
        generate_dorks(args.domain)
        wayback_urls(args.domain)
        scrape_metadata(f"http://{args.domain}")
        check_username(args.domain.split('.')[0])
    
    if args.username:
        check_username(args.username)
        
    if args.email:
        check_email(args.email)
        
    if args.ip:
        ip_info(args.ip)
        
    if not (args.domain or args.username or args.email or args.ip):
        parser.print_help()
