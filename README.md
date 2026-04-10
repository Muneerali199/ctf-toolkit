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

**OWASP Vulnerability Scanner:**
```bash
python3 owasp_scanner.py --url http://example.com/
```

**Automated Session Hijacker:**
```bash
python3 ctf_session_hijack.py --url http://target.thm/admin --token "session=12345"
```

**Cryptography Swiss Army Knife:**
```bash
python3 crypto_tool.py --demo
python3 crypto_tool.py --decode "SGVsbG8="
```

**OSINT Domain Recon:**
```bash
python3 osint_tool.py --domain google.com
```

*(Run any script with `--help` for more detailed usage instructions specific to that tool).*

## ⚖️ Legal Disclaimer
**For Educational and CTF Use Only.** This toolkit is designed strictly for use in authorized Capture The Flag (CTF) competitions, educational environments (like TryHackMe, HackTheBox, picoCTF, DVWA), and on systems you explicitly own or have permission to test. The author is not responsible for any misuse or damage caused by these tools.

## 👨‍💻 Author
**Muneer Ali** - MCA Student, CTF Learner, and Open Source Developer.

## 📜 License
MIT License
