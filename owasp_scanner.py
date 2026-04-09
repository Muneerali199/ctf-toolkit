#!/usr/bin/env python3
"""
OWASP Top 10 Security Education Scanner
========================================
For educational purposes only.
Use ONLY on: localhost, DVWA, picoCTF challenges, or targets you own/have permission to test.
DO NOT use on real websites without written permission.
"""

import requests
import argparse
import re
import base64
import json
import time
import socket
import sys
from datetime import datetime
from urllib.parse import urljoin, urlparse

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    RED     = Fore.RED
    YELLOW  = Fore.YELLOW
    GREEN   = Fore.GREEN
    CYAN    = Fore.CYAN
    MAGENTA = Fore.MAGENTA
    RESET   = Style.RESET_ALL
    BOLD    = Style.BRIGHT
except ImportError:
    RED = YELLOW = GREEN = CYAN = MAGENTA = RESET = BOLD = ""

# ─── Result tracking ───────────────────────────────────────────────────────────
results = {
    "target": "",
    "timestamp": "",
    "findings": []
}

def log(level, check, message):
    """Print coloured finding and store it."""
    icons = {
        "CRITICAL": f"{RED}[CRITICAL]{RESET}",
        "WARNING":  f"{YELLOW}[WARNING] {RESET}",
        "INFO":     f"{CYAN}[INFO]    {RESET}",
        "SAFE":     f"{GREEN}[SAFE]    {RESET}",
    }
    print(f"  {icons.get(level, '[?]')} {message}")
    results["findings"].append({"level": level, "check": check, "message": message})

def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗
║         OWASP Top 10 Education Scanner               ║
║   For CTF / DVWA / localhost use ONLY                ║
╚══════════════════════════════════════════════════════╝{RESET}
""")

def safe_get(url, params=None, data=None, headers=None, method="GET", timeout=5):
    """Wrapper for requests with error handling."""
    try:
        if method == "POST":
            return requests.post(url, params=params, data=data,
                                 headers=headers, timeout=timeout, allow_redirects=True)
        return requests.get(url, params=params, headers=headers,
                            timeout=timeout, allow_redirects=True)
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None

# ══════════════════════════════════════════════════════════════════════════════
# A01 — Broken Access Control
# ══════════════════════════════════════════════════════════════════════════════
def check_a01(base_url, delay):
    print(f"\n{BOLD}[A01] Broken Access Control{RESET}")

    # IDOR — try sequential user IDs
    found_idor = False
    for uid in range(1, 6):
        r = safe_get(f"{base_url}/user/{uid}/profile")
        if r and r.status_code == 200:
            log("WARNING", "A01", f"IDOR candidate: /user/{uid}/profile returned 200")
            found_idor = True
        time.sleep(delay)
    if not found_idor:
        log("SAFE", "A01", "No obvious IDOR endpoints found on /user/<id>/profile")

    # Admin path bypass
    admin_paths = ["/admin", "/admin/", "/%61dmin", "//admin", "/Admin", "/ADMIN",
                   "/administrator", "/admin.php", "/admin/login"]
    for path in admin_paths:
        r = safe_get(base_url + path)
        if r and r.status_code in (200, 302):
            log("WARNING", "A01", f"Admin path accessible: {path} → HTTP {r.status_code}")
        time.sleep(delay)

    # Path traversal
    traversal_payloads = ["/../etc/passwd", "/../../etc/passwd", "/%2e%2e/etc/passwd"]
    for payload in traversal_payloads:
        r = safe_get(base_url + payload)
        if r and "root:" in r.text:
            log("CRITICAL", "A01", f"Path traversal works! Payload: {payload}")
        time.sleep(delay)

    # Forced browsing — common hidden paths
    hidden = ["/backup", "/old", "/test", "/dev", "/staging", "/api/v1/users",
              "/api/users", "/.git", "/config"]
    for path in hidden:
        r = safe_get(base_url + path)
        if r and r.status_code == 200:
            log("INFO", "A01", f"Hidden path responded 200: {path}")
        time.sleep(delay)

# ══════════════════════════════════════════════════════════════════════════════
# A02 — Cryptographic Failures
# ══════════════════════════════════════════════════════════════════════════════
def check_a02(base_url, delay):
    print(f"\n{BOLD}[A02] Cryptographic Failures{RESET}")

    if base_url.startswith("http://"):
        log("WARNING", "A02", "Site uses HTTP — data transmitted in plaintext!")
    else:
        log("SAFE", "A02", "Site uses HTTPS")

    r = safe_get(base_url)
    if not r:
        log("INFO", "A02", "Could not reach target for header analysis")
        return

    # Security headers check
    security_headers = {
        "Strict-Transport-Security": "HSTS missing — HTTPS not enforced",
        "X-Content-Type-Options":    "X-Content-Type-Options missing — MIME sniffing possible",
        "X-Frame-Options":           "X-Frame-Options missing — Clickjacking possible",
        "Content-Security-Policy":   "CSP missing — XSS risk higher",
        "Referrer-Policy":           "Referrer-Policy missing — data leakage risk",
    }
    for header, warning in security_headers.items():
        if header not in r.headers:
            log("WARNING", "A02", warning)
        else:
            log("SAFE", "A02", f"{header} is present")
    time.sleep(delay)

    # Sensitive keywords in response
    sensitive_keywords = ["password", "passwd", "secret", "api_key",
                          "apikey", "private_key", "auth_token"]
    for kw in sensitive_keywords:
        if kw in r.text.lower():
            log("WARNING", "A02", f"Sensitive keyword in response body: '{kw}'")

    # MD5 / SHA1 pattern detection
    md5_matches = re.findall(r'\b[a-f0-9]{32}\b', r.text)
    sha1_matches = re.findall(r'\b[a-f0-9]{40}\b', r.text)
    if md5_matches:
        log("INFO", "A02", f"Possible MD5 hashes in response: {md5_matches[:2]}")
    if sha1_matches:
        log("INFO", "A02", f"Possible SHA1 hashes in response: {sha1_matches[:2]}")

# ══════════════════════════════════════════════════════════════════════════════
# A03 — Injection
# ══════════════════════════════════════════════════════════════════════════════
def check_a03(base_url, delay):
    print(f"\n{BOLD}[A03] Injection (SQLi / XSS / CMDi){RESET}")

    sqli_payloads = [
        "' OR '1'='1", "' OR 1=1--", "1' UNION SELECT null--",
        "admin'--", "' OR 'x'='x", "\" OR \"1\"=\"1",
    ]
    sql_errors = ["you have an error in your sql", "warning: mysql",
                  "unclosed quotation", "syntax error", "ora-", "pg_query",
                  "sqlite_error", "microsoft jet database"]

    for payload in sqli_payloads:
        r = safe_get(base_url, params={"id": payload})
        if r:
            body = r.text.lower()
            for err in sql_errors:
                if err in body:
                    log("CRITICAL", "A03", f"SQLi error triggered! Payload: {payload} | Error: {err}")
                    break
        time.sleep(delay)

    # XSS payloads
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'><script>alert(1)</script>",
    ]
    for payload in xss_payloads:
        r = safe_get(base_url, params={"q": payload, "search": payload})
        if r and payload in r.text:
            log("CRITICAL", "A03", f"Possible reflected XSS! Payload echoed: {payload[:40]}")
        time.sleep(delay)

    # Command injection
    cmd_payloads = ["; echo vulnerable_cmd", "| echo vulnerable_cmd", "; id", "$(echo vulnerable_cmd)"]
    for payload in cmd_payloads:
        r = safe_get(base_url, params={"input": payload, "cmd": payload})
        if r and ("vulnerable_cmd" in r.text or "uid=" in r.text):
            log("CRITICAL", "A03", f"Command injection possible! Payload: {payload}")
        time.sleep(delay)

    log("INFO", "A03", "Injection checks complete — test manually with Burp Suite for full coverage")

# ══════════════════════════════════════════════════════════════════════════════
# A04 — Insecure Design
# ══════════════════════════════════════════════════════════════════════════════
def check_a04(base_url, delay):
    print(f"\n{BOLD}[A04] Insecure Design{RESET}")

    # Rate limiting — 6 rapid login attempts
    login_url = base_url + "/login"
    responses = []
    for i in range(6):
        r = safe_get(login_url, method="POST",
                     data={"username": "admin", "password": f"wrongpass{i}"})
        if r:
            responses.append(r.status_code)
        time.sleep(0.3)

    if responses and all(c == responses[0] for c in responses):
        log("WARNING", "A04", "No rate limiting detected on /login — brute force may be possible")
    else:
        log("SAFE", "A04", "Responses varied — rate limiting may be present")

    # Account enumeration
    r1 = safe_get(login_url, method="POST",
                  data={"username": "admin", "password": "wrongpass"})
    r2 = safe_get(login_url, method="POST",
                  data={"username": "usernotexist99999", "password": "wrongpass"})
    if r1 and r2 and r1.text != r2.text:
        log("WARNING", "A04", "Account enumeration possible — different responses for valid/invalid usernames")
    else:
        log("SAFE", "A04", "Login responses look consistent")

    time.sleep(delay)

    # Password reset endpoint
    r = safe_get(base_url + "/forgot-password")
    if r and r.status_code == 200:
        log("INFO", "A04", "Password reset endpoint found at /forgot-password — test manually for weak token")

# ══════════════════════════════════════════════════════════════════════════════
# A05 — Security Misconfiguration
# ══════════════════════════════════════════════════════════════════════════════
def check_a05(base_url, delay):
    print(f"\n{BOLD}[A05] Security Misconfiguration{RESET}")

    sensitive_files = [
        "/.env", "/config.php", "/wp-config.php", "/.git/config",
        "/web.config", "/phpinfo.php", "/server-status", "/.htaccess",
        "/robots.txt", "/crossdomain.xml", "/debug", "/test.php",
        "/info.php", "/adminer.php", "/phpmyadmin", "/backup.sql",
        "/dump.sql", "/config.yml", "/config.yaml", "/settings.py",
    ]
    for f in sensitive_files:
        r = safe_get(base_url + f)
        if r:
            if r.status_code == 200:
                log("CRITICAL", "A05", f"Sensitive file accessible! {f} → 200 OK ({len(r.text)} bytes)")
            elif r.status_code == 403:
                log("INFO", "A05", f"File exists but forbidden: {f} → 403")
        time.sleep(delay)

    # Default credentials
    default_creds = [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("root", "root"), ("test", "test"), ("admin", ""),
    ]
    login_url = base_url + "/login"
    for user, passwd in default_creds:
        r = safe_get(login_url, method="POST",
                     data={"username": user, "password": passwd})
        if r and any(kw in r.text.lower() for kw in ["dashboard", "welcome", "logout", "profile"]):
            log("CRITICAL", "A05", f"Default credentials work! → {user}:{passwd}")
        time.sleep(delay)

    # Verbose errors
    r = safe_get(base_url + "/nonexistent_page_xyz_12345")
    if r and any(kw in r.text.lower() for kw in ["traceback", "stack trace", "exception", "at line"]):
        log("WARNING", "A05", "Verbose error messages exposed — stack trace visible!")

    # HTTP methods
    for method in ["TRACE", "PUT", "DELETE"]:
        try:
            r = requests.request(method, base_url, timeout=5)
            if r.status_code not in (405, 501, 404):
                log("WARNING", "A05", f"HTTP {method} method allowed → {r.status_code}")
        except Exception:
            pass
        time.sleep(delay)

# ══════════════════════════════════════════════════════════════════════════════
# A06 — Vulnerable & Outdated Components
# ══════════════════════════════════════════════════════════════════════════════
def check_a06(base_url, delay):
    print(f"\n{BOLD}[A06] Vulnerable & Outdated Components{RESET}")

    r = safe_get(base_url)
    if not r:
        log("INFO", "A06", "Could not reach target")
        return

    server = r.headers.get("Server", "")
    powered = r.headers.get("X-Powered-By", "")

    if server:
        log("WARNING", "A06", f"Server version disclosed in header: {server}")
    if powered:
        log("WARNING", "A06", f"Technology stack disclosed: {powered}")
        if "php/5" in powered.lower():
            log("CRITICAL", "A06", "PHP 5.x detected — End of Life, many CVEs!")
        if "php/7.0" in powered.lower() or "php/7.1" in powered.lower():
            log("WARNING", "A06", "PHP 7.0/7.1 detected — End of Life")

    # Vulnerable JS library detection
    vuln_libs = {
        "jquery/1.":    "jQuery 1.x — multiple XSS CVEs (CVE-2011-4969 etc.)",
        "jquery/2.":    "jQuery 2.x — XSS vulnerabilities",
        "jquery/3.0":   "jQuery 3.0.x — prototype pollution risk",
        "bootstrap/3.": "Bootstrap 3.x — XSS in tooltip/popover",
        "angular.js/1.":"AngularJS 1.x — multiple CVEs including sandbox escapes",
    }
    for lib, cve_note in vuln_libs.items():
        if lib.lower() in r.text.lower():
            log("WARNING", "A06", f"Vulnerable library found: {cve_note}")

    # CMS version detection
    wp = re.search(r'WordPress\s+([\d.]+)', r.text)
    drupal = re.search(r'Drupal\s+([\d.]+)', r.text)
    if wp:
        log("WARNING", "A06", f"WordPress version {wp.group(1)} detected — check for known CVEs")
    if drupal:
        log("WARNING", "A06", f"Drupal version {drupal.group(1)} detected — check for known CVEs")

    time.sleep(delay)

# ══════════════════════════════════════════════════════════════════════════════
# A07 — Identification & Authentication Failures
# ══════════════════════════════════════════════════════════════════════════════
def check_a07(base_url, delay):
    print(f"\n{BOLD}[A07] Authentication Failures{RESET}")

    r = safe_get(base_url + "/login", method="POST",
                 data={"username": "testuser", "password": "testpass"})
    if not r:
        log("INFO", "A07", "Login endpoint not reachable")
        return

    # Analyse session cookies
    for name, value in r.cookies.items():
        log("INFO", "A07", f"Cookie found: {name} = {value[:40]}{'...' if len(value)>40 else ''}")

        if value.isdigit():
            log("CRITICAL", "A07", f"Numeric session ID '{name}' — highly predictable!")

        if len(value) < 16:
            log("WARNING", "A07", f"Short session token '{name}' ({len(value)} chars) — low entropy")

        try:
            decoded = base64.b64decode(value + "==").decode("utf-8")
            if any(c.isalpha() for c in decoded):
                log("WARNING", "A07", f"Cookie '{name}' is base64 encoded: {decoded[:60]}")
        except Exception:
            pass

        if name.lower() in ("sessionid", "phpsessid", "jsessionid"):
            log("INFO", "A07", f"Standard session cookie name '{name}' — check entropy")

    # JWT detection in Authorization header or response body
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
    jwt_matches = re.findall(jwt_pattern, r.text)
    for token in jwt_matches:
        parts = token.split(".")
        try:
            payload_bytes = base64.b64decode(parts[1] + "==")
            payload_json = json.loads(payload_bytes)
            log("WARNING", "A07", f"JWT found in response — payload: {payload_json}")
            if payload_json.get("alg", "").lower() == "none":
                log("CRITICAL", "A07", "JWT uses 'none' algorithm — signature bypass possible!")
        except Exception:
            pass
    time.sleep(delay)

    # Logout then re-access
    safe_get(base_url + "/logout")
    r2 = safe_get(base_url + "/dashboard")
    if r2 and r2.status_code == 200 and "login" not in r2.url.lower():
        log("WARNING", "A07", "Session may still be valid after logout — test manually")

# ══════════════════════════════════════════════════════════════════════════════
# A08 — Software & Data Integrity Failures
# ══════════════════════════════════════════════════════════════════════════════
def check_a08(base_url, delay):
    print(f"\n{BOLD}[A08] Software & Data Integrity Failures{RESET}")

    # Exposed install/update endpoints
    risky_paths = ["/update", "/upgrade", "/install", "/setup",
                   "/setup.php", "/install.php", "/migrate"]
    for path in risky_paths:
        r = safe_get(base_url + path)
        if r and r.status_code == 200:
            log("WARNING", "A08", f"Exposed setup/update endpoint: {path} → 200 OK")
        time.sleep(delay)

    # Subresource integrity check
    r = safe_get(base_url)
    if r:
        scripts = re.findall(r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*>', r.text)
        for script in scripts:
            if "integrity=" not in script:
                src = re.search(r'src=["\']([^"\']+)["\']', script)
                if src:
                    log("WARNING", "A08", f"External script without SRI integrity check: {src.group(1)[:60]}")

    # PHP serialization endpoint check
    serialized = 'O:8:"stdClass":1:{s:4:"test";s:4:"pwnd";}'
    for ep in ["/api/data", "/deserialize", "/load", "/unserialize"]:
        r = safe_get(base_url + ep, method="POST", data={"data": serialized})
        if r and r.status_code == 200 and "pwnd" in r.text:
            log("CRITICAL", "A08", f"Possible deserialization endpoint: {ep}")
        time.sleep(delay)

# ══════════════════════════════════════════════════════════════════════════════
# A09 — Security Logging & Monitoring Failures
# ══════════════════════════════════════════════════════════════════════════════
def check_a09(base_url, delay):
    print(f"\n{BOLD}[A09] Security Logging & Monitoring Failures{RESET}")

    login_url = base_url + "/login"
    locked_out = False

    for i in range(6):
        r = safe_get(login_url, method="POST",
                     data={"username": "admin", "password": f"wrongpass{i}"})
        if r and any(kw in r.text.lower() for kw in ["locked", "too many", "blocked", "suspended"]):
            log("SAFE", "A09", f"Account lockout triggered after {i+1} attempts — logging works!")
            locked_out = True
            break
        time.sleep(0.4)

    if not locked_out:
        log("WARNING", "A09", "No account lockout after 6 failed logins — poor logging/monitoring!")

    # WAF detection
    r = safe_get(base_url, params={"id": "1' OR '1'='1"})
    if r:
        if r.status_code in (403, 406, 429):
            log("SAFE", "A09", f"WAF/IDS detected SQLi attempt → HTTP {r.status_code}")
        else:
            log("WARNING", "A09", "SQLi payload not blocked — no WAF detected")
    time.sleep(delay)

# ══════════════════════════════════════════════════════════════════════════════
# A10 — Server-Side Request Forgery (SSRF)
# ══════════════════════════════════════════════════════════════════════════════
def check_a10(base_url, delay):
    print(f"\n{BOLD}[A10] Server-Side Request Forgery (SSRF){RESET}")

    ssrf_payloads = [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://0.0.0.0/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://127.0.0.1:22/",
        "http://127.0.0.1:3306/",
        "http://127.0.0.1:6379/",
    ]

    ssrf_params = ["url", "link", "src", "source", "redirect",
                   "uri", "path", "fetch", "load", "proxy", "target", "dest"]

    internal_indicators = ["root:", "localhost", "internal", "ami-id",
                           "instance-id", "ssh-", "mysql", "redis"]

    for param in ssrf_params[:4]:
        for payload in ssrf_payloads[:3]:
            r = safe_get(base_url, params={param: payload})
            if r:
                for indicator in internal_indicators:
                    if indicator in r.text.lower():
                        log("CRITICAL", "A10",
                            f"SSRF confirmed! Param: {param}, Payload: {payload}, Indicator: {indicator}")
                        break

                # Blind SSRF via response time
                start = time.time()
                safe_get(base_url, params={param: "http://127.0.0.1:9999/"})
                elapsed = time.time() - start
                if elapsed > 3:
                    log("WARNING", "A10",
                        f"Possible blind SSRF — param '{param}' caused {elapsed:.1f}s delay")
            time.sleep(delay)

    log("INFO", "A10", "SSRF basic checks done — use Burp Collaborator for blind SSRF confirmation")

# ══════════════════════════════════════════════════════════════════════════════
# Final Report
# ══════════════════════════════════════════════════════════════════════════════
def print_report(output_file=None):
    critical = [f for f in results["findings"] if f["level"] == "CRITICAL"]
    warnings  = [f for f in results["findings"] if f["level"] == "WARNING"]
    infos     = [f for f in results["findings"] if f["level"] == "INFO"]
    safes     = [f for f in results["findings"] if f["level"] == "SAFE"]

    risk_score = min(100, len(critical) * 20 + len(warnings) * 5)

    report = f"""
{'='*60}
  OWASP TOP 10 SCAN REPORT
  Target    : {results['target']}
  Timestamp : {results['timestamp']}
{'='*60}
  CRITICAL  : {len(critical)}
  WARNING   : {len(warnings)}
  INFO      : {len(infos)}
  SAFE      : {len(safes)}
  RISK SCORE: {risk_score}/100
{'='*60}

CRITICAL FINDINGS:
"""
    for f in critical:
        report += f"  [{f['check']}] {f['message']}\n"

    report += "\nWARNINGS:\n"
    for f in warnings:
        report += f"  [{f['check']}] {f['message']}\n"

    report += f"""
TOP RECOMMENDATIONS:
"""
    if critical:
        report += f"  1. Fix CRITICAL issues immediately: {critical[0]['message'][:60]}\n"
    if warnings:
        report += f"  2. Review WARNINGS: {warnings[0]['message'][:60]}\n"
    report += "  3. Run manual testing with Burp Suite for full coverage\n"
    report += "  4. Use DVWA to practice fixing each vulnerability type\n"
    report += "  5. Check OWASP Testing Guide: owasp.org/www-project-web-security-testing-guide\n"

    print(report)

    if output_file:
        with open(output_file, "w") as f:
            f.write(report)
        print(f"{GREEN}[+] Report saved to: {output_file}{RESET}")

# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════
CHECKS = {
    "a01": check_a01,
    "a02": check_a02,
    "a03": check_a03,
    "a04": check_a04,
    "a05": check_a05,
    "a06": check_a06,
    "a07": check_a07,
    "a08": check_a08,
    "a09": check_a09,
    "a10": check_a10,
}

def main():
    parser = argparse.ArgumentParser(
        description="OWASP Top 10 Education Scanner — localhost/CTF/DVWA only"
    )
    parser.add_argument("--url",    required=True, help="Target URL e.g. http://localhost")
    parser.add_argument("--check",  default="all",  help="Check to run: a01/a02/.../a10/all")
    parser.add_argument("--output", default=None,   help="Save report to file e.g. report.txt")
    parser.add_argument("--delay",  type=float, default=0.5, help="Delay between requests (seconds)")
    args = parser.parse_args()

    # Safety check
    parsed = urlparse(args.url)
    hostname = parsed.hostname or ""
    safe_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1", "dvwa", "hackthebox", "tryhackme",
                  "picoctf", "ctf", "vulnhub", "webshell"]
    is_safe = any(h in hostname for h in safe_hosts) or hostname.startswith("10.") \
              or hostname.startswith("192.168.") or hostname.startswith("172.")

    if not is_safe:
        print(f"{RED}[!] WARNING: Target '{hostname}' may not be a CTF/local environment!{RESET}")
        print(f"{YELLOW}    This tool is for localhost, DVWA, CTF platforms only.{RESET}")
        confirm = input("    Are you authorized to test this target? (yes/no): ")
        if confirm.lower() != "yes":
            print("Exiting. Only test targets you own or have permission to test!")
            sys.exit(0)

    banner()
    results["target"] = args.url
    results["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"{CYAN}Target   : {args.url}{RESET}")
    print(f"{CYAN}Check    : {args.check.upper()}{RESET}")
    print(f"{CYAN}Delay    : {args.delay}s{RESET}")
    print(f"{CYAN}Started  : {results['timestamp']}{RESET}")

    if args.check.lower() == "all":
        for name, fn in CHECKS.items():
            fn(args.url, args.delay)
    elif args.check.lower() in CHECKS:
        CHECKS[args.check.lower()](args.url, args.delay)
    else:
        print(f"{RED}Unknown check '{args.check}'. Use: a01-a10 or all{RESET}")
        sys.exit(1)

    print_report(args.output)

if __name__ == "__main__":
    main()
