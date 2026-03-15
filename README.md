<div align="center">

```
███████╗    ███████╗██╗   ██╗███████╗███████╗
██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
███████╗    █████╗   ╚████╔╝ █████╗  ███████╗
╚════██║    ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
███████║    ███████╗   ██║   ███████╗███████║
╚══════╝    ╚══════╝   ╚═╝   ╚══════╝╚══════╝
```

**Full-Spectrum Intelligence & Security Toolkit**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.0.0-cyan?style=flat-square)
![AES](https://img.shields.io/badge/Encryption-AES--256--GCM-red?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)

*15 modules · AES-256-GCM vault · 500-variant OSINT · Recovery passphrase · Nuclear wipe*

</div>

---

> ⚠️ **For educational & authorized security testing only.**
> Use only on systems you own or have written permission to test.
> Unauthorized use is illegal. The author takes no responsibility for misuse.

---

## Installation

```bash
#create env
python3 -m venv venv

#go to env
source venv/bin/activate
```

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/5eyes.git
cd 5eyes

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch
python 5eyes.py
```

**Kali / Parrot / Debian (externally managed environments):**
```bash
pip install -r requirements.txt --break-system-packages
```

**Full install — enables EXIF, steganography, rich DNS:**
```bash
pip install pycryptodome requests colorama Pillow dnspython qrcode
```

---

## First Launch

On the very first run, you create a master password and receive a **recovery passphrase**.
Write it down before pressing Enter — it is the only way to recover a forgotten password.

```
  New password (min 8 chars): ••••••••
  Confirm password:           ••••••••

  ╔══════════════════════════════════════════╗
  ║   yankee-forge-tiger-viper-kilo-pulse    ║
  ╚══════════════════════════════════════════╝
  Press Enter ONLY after writing this down…
```

---

## Dashboard Commands

| Key | Action |
|-----|--------|
| `1`–`15` | Run a numbered module |
| `f` | Forgot password → reset via recovery passphrase |
| `c` | Change password (auto-generates new passphrase) |
| `p` | Panic wipe — wipe logs + integrity DB, exit now |
| `n` | **Nuclear wipe** — full self-destruct, destroy everything |
| `s` | Stealth mode — disguise as MathHelper calculator |
| `h` | Help — show all module descriptions |
| `q` | Quit |
| `Ctrl+C` | Emergency panic wipe |

---

## Modules

| # | Module | Key Features |
|---|--------|--------------|
| 1 | IP / Domain Recon | WHOIS · GeoIP · ASN · rDNS · 10 DNS record types |
| 2 | Subdomain Enum | DNS brute (184 words) + crt.sh CT logs + 71 permutations |
| 3 | Username OSINT | 500 variants · 25 platforms · parallel · report export |
| 4 | Email Headers | Hop trace · SPF/DKIM/DMARC · phishing detection |
| 5 | Port Scanner | Threaded TCP · banner grab · CVE hints for 8 services |
| 6 | AES-256 Vault | Encrypt / decrypt text · Base64 output |
| 7 | File Encrypt | Any file → AES-256-GCM · `.enc` extension |
| 8 | Secure Notes | Per-note AES-256-GCM · 3-pass secure delete |
| 9 | Password Suite | Generate · entropy · HIBP k-anonymity breach check |
| 10 | Hash Suite | 5 algorithms · wordlist cracker · file integrity monitor |
| 11 | JWT Analyzer | Decode · alg=none detection · expiry · sensitive claims |
| 12 | Metadata | EXIF (images) · Office author/revision · multi-hash |
| 13 | Steganography | LSB hide / extract text in PNG (emoji-safe) |
| 14 | Encode / Decode | Auto-detect · Base64 / Hex / Binary / ROT13 / Morse |
| 15 | Tor / Proxy | Public IP · Tor exit check · proxy leak · anonymity score |

---

## Quick Examples

**IP Recon:**
```
❯ 1  →  8.8.8.8
  Country: US  ·  ISP: Google LLC  ·  ASN: AS15169  ·  rDNS: dns.google
```

**Username OSINT — 500 variants across 25 platforms:**
```
❯ 3  →  cyph3r  →  Mode: 3 (Full 500)
  [● ALIVE]  cyph3r    GitHub    https://github.com/cyph3r
  [● ALIVE]  cypher    Reddit    https://reddit.com/user/cypher
```

**Port scan with CVE hints:**
```
❯ 5  →  192.168.1.1  →  1-1024
  [+] 22/tcp    SSH     SSH-2.0-OpenSSH_8.9
  [+] 6379/tcp  Redis   ⚠ CVE-2022-0543 — Lua sandbox escape / auth bypass
```

**HIBP breach check (password never leaves your machine):**
```
❯ 9  →  3  →  ••••••••
  ⚠ Found in 3,861,493 breaches — change immediately
```

---

## Security Features

**Panic Wipe `[p]`**
Instantly 3-pass wipes `ops.log` and `integrity.json` then exits.
Vault data and config are preserved. Also triggered by `Ctrl+C`.

**Nuclear Wipe `[n]`** — irreversible, two-step auth:
```
Type exactly:  NUKE EVERYTHING
Password:      ••••••••
→ All notes · exports · config · vault destroyed (3-pass overwrite).
  Tool returns to fresh first-time setup on next launch.
```

**Recovery Passphrase**
Type `f` at any password prompt → enter 6-word passphrase → set new password.
A brand-new passphrase is generated every reset. Old one is immediately invalidated.

---

## Vault Structure

All data lives in `~/.5eyes_vault/` — never inside the project folder.

```
~/.5eyes_vault/
├── config.json      ← PBKDF2-SHA256 hashes only (no plaintext ever)
├── ops.log          ← Operation log (passwords/targets never logged)
├── integrity.json   ← File integrity index
├── notes/           ← *.enote  (AES-256-GCM, one file per note)
├── exports/         ← OSINT scan reports (.txt / .csv)
└── steg/            ← Steganography output images
```

---

## Dependencies

| Package | Required | Purpose |
|---------|----------|---------|
| `pycryptodome` | ✅ Yes | AES-256-GCM encryption |
| `requests` | ✅ Yes | HTTP — recon, HIBP, OSINT APIs |
| `colorama` | ✅ Yes | Coloured terminal (cross-platform) |
| `Pillow` | Optional | EXIF extraction + steganography |
| `dnspython` | Optional | Richer DNS lookups |
| `qrcode` | Optional | QR code generation |

---

## Project Structure

```
5eyes/
├── 5eyes.py             ← Main tool (single file, no install needed)
├── requirements.txt     ← Python dependencies
├── LICENSE              ← MIT License
├── CHANGELOG.md         ← Full version history
├── SECURITY.md          ← Vulnerability disclosure policy
├── .gitignore           ← Blocks vault data, .enc, exports
└── docs/
    └── vault_structure.md  ← Vault schema & .enote format
```

---

## License

MIT — see [LICENSE](LICENSE).
Built for offensive security research and authorized penetration testing.
