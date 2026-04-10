import hashlib
import string
import base64
import collections

# 1. Auto hash identifier
def identify_hash(h):
    print(f"\n[*] Identifying Hash: {h}")
    length = len(h)
    if length == 32:
        print("[+] Possible Type: MD5 (or NTLM, MD4)")
    elif length == 40:
        print("[+] Possible Type: SHA-1")
    elif length == 64:
        print("[+] Possible Type: SHA-256")
    elif h.startswith("$2a$") or h.startswith("$2b$"):
        print("[+] Possible Type: bcrypt")
    else:
        print("[-] Unknown hash type or format.")

# 2. Hash cracker
def crack_hash(target_hash, wordlist_path):
    print(f"\n[*] Attempting to crack hash: {target_hash}")
    algo = 'md5' if len(target_hash) == 32 else 'sha1' if len(target_hash) == 40 else 'sha256'
    try:
        with open(wordlist_path, 'r', errors='ignore') as f:
            for line in f:
                word = line.strip()
                h = hashlib.new(algo)
                h.update(word.encode())
                if h.hexdigest() == target_hash:
                    print(f"[+++] Found password: {word} (Algo: {algo})")
                    return word
        print("[-] Password not found in wordlist.")
    except Exception as e:
        print(f"[-] Error: {e}")

# 3. Caesar cipher brute force
def caesar_brute(ciphertext):
    print("\n[*] Caesar Cipher Brute Force:")
    for shift in range(1, 26):
        plaintext = ''
        for char in ciphertext:
            if char.isalpha():
                base = ord('a') if char.islower() else ord('A')
                plaintext += chr((ord(char) - base - shift) % 26 + base)
            else:
                plaintext += char
        print(f"Shift {shift:2d}: {plaintext}")

# 4. Encoders/Decoders
def decode_common(data):
    print("\n[*] Common Decodings:")
    # ROT13
    rot13 = ''.join(chr((ord(c) - 97 + 13) % 26 + 97) if c.islower() else (chr((ord(c) - 65 + 13) % 26 + 65) if c.isupper() else c) for c in data)
    print(f"[+] ROT13: {rot13}")
    
    # Base64
    try:
        b64 = base64.b64decode(data).decode('utf-8')
        print(f"[+] Base64: {b64}")
    except:
        pass
        
    # Base32
    try:
        b32 = base64.b32decode(data).decode('utf-8')
        print(f"[+] Base32: {b32}")
    except:
        pass

# 5. XOR brute force (single byte)
def xor_brute(ciphertext_hex):
    print("\n[*] XOR Single-Byte Brute Force:")
    try:
        data = bytes.fromhex(ciphertext_hex)
        for key in range(256):
            decoded = bytes(b ^ key for b in data)
            if all(32 <= b <= 126 for b in decoded): # Only print printable ascii
                print(f"Key 0x{key:02x}: {decoded.decode('ascii', errors='ignore')}")
    except Exception as e:
        print(f"[-] Error in XOR brute: {e}")

# 6. Frequency Analysis
def frequency_analysis(text):
    print("\n[*] Frequency Analysis:")
    text = ''.join(filter(str.isalpha, text.lower()))
    counter = collections.Counter(text)
    total = sum(counter.values())
    for char, count in counter.most_common():
        print(f"{char}: {count/total:.2%} ({count})")

# 7. Vigenere cracker (basic manual key)
def vigenere_decrypt(ciphertext, key):
    print(f"\n[*] Vigenere Decrypt with key '{key}':")
    key = key.lower()
    key_idx = 0
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            k_shift = ord(key[key_idx % len(key)]) - ord('a')
            plaintext += chr((ord(char) - base - k_shift) % 26 + base)
            key_idx += 1
        else:
            plaintext += char
    print(f"[+] Result: {plaintext}")

if __name__ == "__main__":
    print("=== CTF Cryptography Toolkit ===")
    identify_hash("5d41402abc4b2a76b9719d911017c592")
    caesar_brute("Khoor Zruog!")
    decode_common("SGVsbG8gV29ybGQ=")
    xor_brute("3f3e3333307f28302d333b")
    frequency_analysis("This is a test of frequency analysis in a substitution cipher.")
    vigenere_decrypt("Rijvs Uyvjn!", "key")