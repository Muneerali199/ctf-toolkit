# CTF Toolkit by Muneer Ali

![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Description
A collection of CTF scripts and tools tailored for platforms like picoCTF, TryHackMe, and HackTheBox.

## Scripts Overview

| Script Name | Purpose | Command to Use |
| --- | --- | --- |
| `owasp_scanner.py` | Scans for top OWASP vulnerabilities | `python3 owasp_scanner.py --target <URL>` |
| `ctf_session_hijack.py` | Tests session hijacking vulnerabilities | `python3 ctf_session_hijack.py --url <URL> --cookie <COOKIE>` |
| `web_toolkit/web_tool.py` | Web exploitation and enumeration | `python3 web_toolkit/web_tool.py --help` |
| `crypto_toolkit/crypto_tool.py` | Cryptography and decoding utilities | `python3 crypto_toolkit/crypto_tool.py --help` |
| `forensics_toolkit/forensics_tool.py` | File forensics and metadata extraction | `python3 forensics_toolkit/forensics_tool.py --file <FILE>` |
| `osint_toolkit/osint_tool.py` | Open-source intelligence gathering | `python3 osint_toolkit/osint_tool.py --domain <DOMAIN>` |
| `password_toolkit/password_tool.py` | Password cracking and generation | `python3 password_toolkit/password_tool.py --hash <HASH>` |
| `auto_solver/master_solver.py` | Automated solver for common CTF challenges | `python3 auto_solver/master_solver.py --module <MODULE>` |

## Requirements
- Python 3.9+
- macOS or Linux

## Installation
```bash
pip3 install -r requirements.txt
```

## Usage Examples

**OWASP Scanner:**
```bash
python3 owasp_scanner.py --target http://example.com/
```

**Session Hijacker:**
```bash
python3 ctf_session_hijack.py --url http://target.thm/admin --cookie "session=12345"
```

*(Run any script with `--help` for more detailed usage instructions specific to that tool).*

## Legal Disclaimer
**For Educational and CTF Use Only.** This toolkit is designed strictly for use in authorized Capture The Flag (CTF) competitions, educational environments (like TryHackMe, HackTheBox, picoCTF, DVWA), and on systems you explicitly own or have permission to test. The author is not responsible for any misuse or damage caused by these tools.

## Author
**Muneer Ali** - MCA Student, CTF Learner, and Open Source Developer.

## License
MIT License
