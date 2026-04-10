
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
import requests
import re
import base64
import os
import binascii
import sys
import argparse
import codecs
from collections import defaultdict

# Regex for flags: picoCTF{...}, CTF{...}, FLAG{...}
FLAG_PATTERN = re.compile(r'((picoCTF|CTF|FLAG)\{.*?\})', re.IGNORECASE)

report_data = defaultdict(list)

def log_result(tech, result, conf=100):
    report_data[tech].append({"result": result, "confidence": conf})
    print(f"[+] {tech} (Conf: {conf}%): {result}")

def detect_input_type(target):
    if target.startswith("http://") or target.startswith("https://"):
        return "web"
    elif os.path.exists(target):
        return "file"
    else:
        return "unknown"

def auto_solve_web(url):
    print(f"\n[*] Starting Web Auto-Solve for {url}")
    try:
        r = requests.get(url, timeout=5)
        # 1. SQLi test
        print("[*] Testing basic SQLi...")
        sqli_payload = "'"
        r_sqli = requests.get(f"{url}?id={sqli_payload}", timeout=5)
        if "sql" in r_sqli.text.lower() or "syntax" in r_sqli.text.lower():
            log_result("SQLi Check", f"Vulnerable parameter found at {url}?id={sqli_payload}")

        # 2. XSS test
        print("[*] Testing basic XSS...")
        xss_payload = "<script>alert(1)</script>"
        r_xss = requests.get(f"{url}?q={xss_payload}", timeout=5)
        if xss_payload in r_xss.text:
            log_result("XSS Check", f"Reflected XSS found at {url}?q={xss_payload}")

        # 3. Headers check
        print("[*] Checking headers...")
        for header, value in r.headers.items():
            if FLAG_PATTERN.search(value):
                log_result("Header Check", f"Flag found in header {header}: {value}", 100)

        # Look for flags in response
        matches = FLAG_PATTERN.findall(r.text)
        for match in matches:
            log_result("Source Code Check", f"Flag found: {match[0]}", 100)
            
    except Exception as e:
        print(f"[-] Web Check Error: {e}")

def auto_solve_file(filepath):
    print(f"\n[*] Starting File Auto-Solve for {filepath}")
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        # 1. Magic bytes
        magic = data[:4]
        if magic == b'\xff\xd8\xff\xe0': log_result("Magic Bytes", "JPEG Image detected", 90)
        elif magic == b'\x89\x50\x4e\x47': log_result("Magic Bytes", "PNG Image detected", 90)
        elif magic == b'PK\x03\x04': log_result("Magic Bytes", "ZIP Archive detected", 90)
        
        # 2. Extract strings & find flag
        print("[*] Extracting strings...")
        strings = ""
        for byte in data:
            char = chr(byte)
            if 32 <= byte <= 126:
                strings += char
            else:
                if len(strings) > 5:
                    matches = FLAG_PATTERN.findall(strings)
                    for match in matches:
                        log_result("String Extraction", f"Flag found: {match[0]}", 100)
                strings = ""

        # 3. Try Decodings
        print("[*] Attempting basic decodings...")
        text_data = data.decode(errors='ignore')
        
        # Base64
        try:
            b64_decoded = base64.b64decode(text_data).decode(errors='ignore')
            matches = FLAG_PATTERN.findall(b64_decoded)
            for match in matches:
                log_result("Base64 Decode", f"Flag found: {match[0]}", 100)
        except Exception: pass
        
        # Hex
        try:
            hex_decoded = binascii.unhexlify(text_data.strip()).decode(errors='ignore')
            matches = FLAG_PATTERN.findall(hex_decoded)
            for match in matches:
                log_result("Hex Decode", f"Flag found: {match[0]}", 100)
        except Exception: pass
        
        # ROT13
        rot13 = codecs.encode(text_data, 'rot_13')
        matches = FLAG_PATTERN.findall(rot13)
        for match in matches:
            log_result("ROT13 Decode", f"Flag found: {match[0]}", 100)
            
        # Binary
        if all(c in '01 ' for c in text_data):
            try:
                binary_str = text_data.replace(' ', '')
                n = int(binary_str, 2)
                bin_decoded = n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()
                matches = FLAG_PATTERN.findall(bin_decoded)
                for match in matches:
                    log_result("Binary Decode", f"Flag found: {match[0]}", 100)
            except Exception: pass

    except Exception as e:
        print(f"[-] File Check Error: {e}")

def save_report():
    print(f"\n[*] Saving report to report.txt")
    with open('report.txt', 'w') as f:
        f.write("=== CTF Master Auto-Solver Report ===\n\n")
        if not report_data:
            f.write("No significant findings or flags located.\n")
        for tech, results in report_data.items():
            f.write(f"--- {tech} ---\n")
            for r in results:
                f.write(f"Confidence {r['confidence']}%: {r['result']}\n")
            f.write("\n")
    print("[+] Report saved successfully.")

if __name__ == "__main__":
    print("=== CTF Master Auto-Solver ===")
    
        
    parser = argparse.ArgumentParser(description="CTF Master Auto-Solver")
    parser.add_argument("--module", help="Target URL or Filepath", required=True)
    args = parser.parse_args()
    target = args.module
    target_type = detect_input_type(target)
    
    if target_type == "web":
        auto_solve_web(target)
    elif target_type == "file":
        auto_solve_file(target)
    else:
        print(f"[-] Unknown target format: {target}")
        
    save_report()
