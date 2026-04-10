# CTF Toolkit by Muneer Ali

![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Description
A comprehensive collection of powerful CTF (Capture The Flag) scripts and automation tools tailored for platforms like picoCTF, TryHackMe, and HackTheBox. This toolkit contains scripts specifically engineered to crack hashes, automate OSINT, analyze forensics, and execute advanced web exploitation.

## 🚀 Top Tools & Scripts

| Script Name | Purpose | Example Command |
| --- | --- | --- |
| 🔑 **`argon2_cracker.py`** | Highly-optimized auto Argon2id/i/d hash cracker supporting manual 16-byte fallback, Hashcat integration, and multi-phased smart dictionary attacks. | `python3 argon2_cracker.py --hashfile hash.txt` |
| 🕵️‍♂️ **`owasp_scanner.py`** | Scans for top OWASP vulnerabilities (SQLi, XSS, etc.) | `python3 owasp_scanner.py --url http://target.url` |
| 🍪 **`ctf_session_hijack.py`** | Tests session hijacking and cookie forging | `python3 ctf_session_hijack.py --url http://target.url` |
| 🌐 **`web_tool.py`** | Web exploitation, directory busting, and enumeration | `python3 web_tool.py --url http://target.url --mode all` |
| 🔐 **`crypto_tool.py`** | Advanced Cryptography, hash identification, and decoding utilities | `python3 crypto_tool.py --identify 5d41402abc4b2a76b9719d911017c592` |
| 📂 **`forensics_tool.py`** | File forensics, steganography analysis, and metadata extraction | `python3 forensics_tool.py --file image.png` |
| 🔍 **`osint_tool.py`** | Open-source intelligence gathering and reconnaissance | `python3 osint_tool.py --domain example.com` |
| 🔓 **`password_tool.py`** | Password cracking, mutation generation, and brute forcing | `python3 password_tool.py --mode hash --target <HASH>` |
| 🤖 **`master_solver.py`** | Automated solver mapping across common CTF challenges | `python3 master_solver.py --module <FILE_OR_URL>` |

## 📦 Requirements
- **Python 3.9+**
- macOS or Linux environment
- Optional but recommended: `hashcat`, `john`

## ⚙️ Installation
```bash
git clone https://github.com/Muneerali199/ctf-toolkit.git
cd ctf-toolkit
pip3 install -r requirements.txt
```

## 💻 Elite Usage Examples

**Argon2 Cracker (The picoCTF killer):**
```bash
# Safely handles truncated 16-byte hashes, runs hashcat, and applies smart wordlists automatically
cat > hash.txt << 'EOF'
$argon2id$v=19$m=65536,t=3,p=4$i/eOmAF+Qg40JHQAt4J/2A$sSPcLIMzrICGjBh3G5IcYZ
EOF
python3 argon2_cracker.py --hashfile hash.txt
```

**OSINT Domain Recon (AWS CTF Challenge / flAWS.cloud):**
```bash
# Automatically extracts WHOIS, Reverse DNS, AWS Region, and Metadata
python3 osint_tool.py --domain flaws.cloud

# Output automatically reveals the hidden AWS S3 bucket and Region:
# [+] IP: 3.5.86.66
# [+] Reverse DNS: s3-website.us-west-2.amazonaws.com
# [+] Location: Boardman, Oregon, US
```

**Automated Username Recon (TryHackMe / OhSINT Challenge):**
```bash
# Cross-references usernames across GitHub, Twitter, Reddit, and Instagram
python3 osint_tool.py --username Owoodflint
```

**OWASP Vulnerability Scanner:**
```bash
python3 owasp_scanner.py --url http://example.com/
```

**Automated Forensics & Magic Byte Recovery:**
```bash
# Challenge: Corrupted JPEG with hidden flag
# Action: Runs Strings extraction, EXIF metadata, Hex dump, and LSB Steg checks
python3 forensics_tool.py --file hard_challenge.jpg
# [+++] FLAG FOUND: picoCTF{m4g1c_byt3s_c4nt_h1d3_m3_8f3a1}
```

**Cryptography Swiss Army Knife (XOR Brute-Force):**
```bash
# Challenge: You have an unknown hex string and suspect it's XOR encrypted.
# Action: Brute forces every single-byte XOR key and prints readable outputs.
python3 crypto_tool.py --xor 475e54587463714c4f07456855454243045107455404680644680456444e4a
# [+] Key 0x37: picoCTF{x0r_brut3f0rc3_1s_3asy}
```

**CTF Master Auto-Solver:**
```bash
# Challenge: You don't know what the file is or what web vulnerabilities exist.
# Action: Automatically runs every test in the toolkit and generates a report.txt
python3 master_solver.py --module target_file_or_url
```

## 🧠 How It Works

The toolkit leverages **modular scripts** connected through advanced Python heuristics to solve CTF categories organically:
- **Argon2 Cracker (`argon`):** Uses an aggressive multi-tiered logic system (Instant → Smart Pattern → Rockyou → Brute Force). It handles corrupt `argon2-cffi` 16-byte hashes natively by directly recalculating and diffing hashes using the low-level `hash_secret` API and auto-delegates to **Hashcat** when possible.
- **Master Auto-Solver (`auto`):** Determines the file type via magic byte parsing. It cascades the file through standard steganography boundaries (LSB mapping, hex dumping, text extraction) while aggressively regex-scraping `picoCTF{...}` & `CTF{...}` tokens across ROT13, Base64, and Hex decoding wrappers.
- **OSINT Toolkit (`osint`):** Combines standard `whois` queries with silent API scrapes against GitHub, Reddit, Instagram, Wayback Machine, and HaveIBeenPwned. It maps Reverse DNS and exact cloud-hosting IP locations without ever tripping standard HTTP web-alarm filters.
- **Web & Scanner (`web`/`owasp`):** Identifies headers, executes simple XSS and boolean-based SQL injection, and hunts for leaked environment parameters and flags hiding natively in the HTTP source body.

## ⚡ Single Command Execution (Unified CLI)

We have engineered a global `./ctf` wrapper script so you never need to remember individual python files or parameters. **One command rules them all.**

```bash
# 1. Make the wrapper executable (First time only)
chmod +x ctf

# 2. Run the wrapper to see the beautiful hacker UI & available tools
./ctf
```

### Examples using the Unified Wrapper:
```bash
# Auto-Solve a mysterious file or URL
./ctf auto --module unknown_challenge.jpg

# Track down a user using OSINT
./ctf osint --username Owoodflint

# Crack an Argon2 hash using the dedicated cracker
./ctf argon --hashfile hash.txt

# Run Web Enumeration
./ctf web --url http://target.url --mode all
```

## ⚖️ Legal Disclaimer
**For Educational and CTF Use Only.** This toolkit is designed strictly for use in authorized Capture The Flag (CTF) competitions, educational environments (like TryHackMe, HackTheBox, picoCTF, DVWA), and on systems you explicitly own or have permission to test. The author is not responsible for any misuse or damage caused by these tools.

## 👨‍💻 Author
**Muneer Ali** - MCA Student, CTF Learner, and Open Source Developer.

## 📜 License
MIT License
