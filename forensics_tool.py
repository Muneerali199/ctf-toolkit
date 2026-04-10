import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
import os
import struct
import zipfile
import string
import re
import argparse
try:
    from PIL import Image
    import exifread
except ImportError:
    print("Please install Pillow and exifread: pip install Pillow exifread")
    exit(1)

# 1. File type identifier
def identify_file(filepath):
    print(f"\n[*] Identifying File: {filepath}")
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(4)
            if magic == b'\xff\xd8\xff\xe0':
                print("[+] Type: JPEG Image")
            elif magic == b'\x89\x50\x4e\x47':
                print("[+] Type: PNG Image")
            elif magic == b'PK\x03\x04':
                print("[+] Type: ZIP Archive")
            elif magic == b'%PDF':
                print("[+] Type: PDF Document")
            else:
                print(f"[-] Unknown Magic Bytes: {magic.hex()}")
    except Exception as e:
        print(f"[-] Error: {e}")

# 2. Metadata extractor
def extract_metadata(filepath):
    print(f"\n[*] Extracting Metadata for {filepath}")
    try:
        with open(filepath, 'rb') as f:
            tags = exifread.process_file(f)
            if tags:
                for tag, value in tags.items():
                    print(f"  {tag}: {value}")
            else:
                print("[-] No EXIF metadata found.")
    except Exception as e:
        print(f"[-] Error: {e}")

# 3. Strings extractor
def extract_strings(filepath):
    print(f"\n[*] Extracting Strings from {filepath}")
    flag_pattern = re.compile(r'(picoCTF\{.*?\}|CTF\{.*?\})')
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            strings = ""
            for byte in data:
                char = chr(byte)
                if char in string.printable:
                    strings += char
                else:
                    if len(strings) >= 4:
                        matches = flag_pattern.findall(strings)
                        if matches:
                            for match in matches:
                                print(f"[+++] FLAG FOUND: {match}")
                    strings = ""
    except Exception as e:
        print(f"[-] Error: {e}")

# 4. LSB steganography detector
def check_lsb(filepath):
    print(f"\n[*] Checking LSB Steganography in {filepath}")
    try:
        img = Image.open(filepath)
        pixels = img.load()
        width, height = img.size
        extracted_bits = []
        for y in range(height):
            for x in range(width):
                pixel = pixels[x, y]
                if isinstance(pixel, int):
                    extracted_bits.append(pixel & 1)
                else:
                    extracted_bits.append(pixel[0] & 1)
        
        extracted_bytes = [extracted_bits[i:i+8] for i in range(0, len(extracted_bits), 8)]
        msg = ""
        for b in extracted_bytes:
            if len(b) == 8:
                char = chr(int(''.join(map(str, b)), 2))
                if char in string.printable:
                    msg += char
        print(f"[+] LSB Message start: {msg[:100]}...")
    except Exception as e:
        print(f"[-] Error (Maybe not an image?): {e}")

# 5. ZIP brute forcer
def zip_bruteforce(filepath, wordlist):
    print(f"\n[*] ZIP Password Brute Forcing {filepath}")
    try:
        zip_file = zipfile.ZipFile(filepath)
        with open(wordlist, 'r', errors='ignore') as f:
            for line in f:
                pwd = line.strip().encode('utf-8')
                try:
                    zip_file.extractall(pwd=pwd)
                    print(f"[+++] Found Password: {pwd.decode()}")
                    return
                except (RuntimeError, zipfile.BadZipFile):
                    pass
        print("[-] Password not found in wordlist.")
    except Exception as e:
        print(f"[-] Error: {e}")

# 6. Hex dump viewer
def hexdump(filepath, length=256):
    print(f"\n[*] Hex Dump (First {length} bytes) of {filepath}")
    try:
        with open(filepath, 'rb') as f:
            data = f.read(length)
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                print(f"{i:08x}  {hex_str:<48}  |{ascii_str}|")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTF Forensics Toolkit")
    parser.add_argument("--file", help="Target file for forensics analysis", required=True)
    parser.add_argument("--zipbrute", help="Wordlist to brute force ZIP password")
    
    args = parser.parse_args()
    
    print("=== CTF Forensics Toolkit ===")
    identify_file(args.file)
    extract_metadata(args.file)
    extract_strings(args.file)
    check_lsb(args.file)
    hexdump(args.file)
    
    if args.zipbrute:
        zip_bruteforce(args.file, args.zipbrute)
