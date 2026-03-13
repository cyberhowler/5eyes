#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                                                                              ║
# ║    ██████╗     ███████╗██╗   ██╗███████╗███████╗                            ║
# ║    ██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝                            ║
# ║    ╚█████╗     █████╗   ╚████╔╝ █████╗  ███████╗                            ║
# ║     ╚═══██╗    ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║                            ║
# ║    ██████╔╝    ███████╗   ██║   ███████╗███████║                            ║
# ║    ╚═════╝     ╚══════╝   ╚═╝   ╚══════╝╚══════╝                            ║
# ║                                                                              ║
# ║          FULL-SPECTRUM INTELLIGENCE & SECURITY TOOLKIT  v1.0                ║
# ║                        Developed by: cyph3r (RG)                            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#
# WHAT'S NEW IN v1.0:
#   • Complete TUI redesign — dashboard layout, box-drawing, progress bars
#   • Pruned 26 features → 15 focused, production-grade modules
#   • Subdomain Enum upgraded: DNS brute + Certificate Transparency (crt.sh)
#     + permutation engine (Amass-style multi-source)
#   • IP/Domain Recon: ASN lookup, reverse DNS, full DNS record set
#   • OSINT Username: 20 platforms, parallel checking, confidence scoring
#   • Password Suite: HIBP breach check (k-anonymity), zxcvbn-style cracktime
#   • Hash Suite: file integrity + cracker unified
#   • Metadata: EXIF extraction (images), Office doc metadata
#   • Encoding Center: auto-detect encoding type
#   • All datetime calls timezone-aware (no deprecation warnings)
#   • Auto-migrate old config.json (v5/v6 compat)

import os, sys, ast, json, time, hmac, base64, math, secrets
import hashlib, getpass, platform, re, operator, socket, struct
import threading, ipaddress, itertools, textwrap, shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Required ───────────────────────────────────────────────────────────────
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    print("[!] Missing pycryptodome.  Run:  pip install pycryptodome"); sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] Missing requests.  Run:  pip install requests"); sys.exit(1)

# ─── Optional ───────────────────────────────────────────────────────────────
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import qrcode
    QR_AVAILABLE = True and PIL_AVAILABLE
except ImportError:
    QR_AVAILABLE = False

try:
    import dns.resolver, dns.reversename, dns.exception
    DNS_LIB = True
except ImportError:
    DNS_LIB = False

try:
    from colorama import init as _ci, Fore, Style, Back
    _ci(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    class _FC:
        def __getattr__(self, _): return ""
    Fore = Style = Back = _FC()
    _HAS_COLOR = False

# ════════════════════════════════════════════════════════════════════════════
#  PATHS
# ════════════════════════════════════════════════════════════════════════════
HOME         = Path.home()
VAULT_DIR    = HOME / ".5eyes_vault";   VAULT_DIR.mkdir(parents=True, exist_ok=True)
NOTES_DIR    = VAULT_DIR / "notes";    NOTES_DIR.mkdir(exist_ok=True)
STEG_DIR     = VAULT_DIR / "steg";     STEG_DIR.mkdir(exist_ok=True)
EXPORT_DIR   = VAULT_DIR / "exports";  EXPORT_DIR.mkdir(exist_ok=True)
CFG_FILE     = VAULT_DIR / "config.json"
LOG_FILE     = VAULT_DIR / "ops.log"
INTEGRITY_DB = VAULT_DIR / "integrity.json"

# ════════════════════════════════════════════════════════════════════════════
#  COLOUR / TUI PRIMITIVES
# ════════════════════════════════════════════════════════════════════════════
W = shutil.get_terminal_size((100, 30)).columns

def _c(color, text):  return color + str(text) + Style.RESET_ALL
def _ok(m):     print(_c(Fore.GREEN,  f"  ✔  {m}"))
def _warn(m):   print(_c(Fore.YELLOW, f"  ⚠  {m}"))
def _err(m):    print(_c(Fore.RED,    f"  ✖  {m}"))
def _info(m):   print(_c(Fore.CYAN,   f"  ►  {m}"))
def _sep(char="─", color=Fore.CYAN):
    print(_c(color, char * min(W, 80)))

def _box(title: str, color=Fore.CYAN) -> None:
    w = min(W, 80)
    print(_c(color, "╔" + "═"*(w-2) + "╗"))
    pad = (w - 2 - len(title)) // 2
    print(_c(color, "║") + " " * pad + _c(Fore.WHITE, title) + " " * (w-2-pad-len(title)) + _c(color, "║"))
    print(_c(color, "╚" + "═"*(w-2) + "╝"))

def _hdr(title: str, color=Fore.CYAN) -> None:
    w = min(W, 80)
    print()
    print(_c(color, "┌─ ") + _c(Fore.WHITE + Style.BRIGHT, title) + _c(color, " " + "─"*(w-4-len(title))))
    print(_c(color, "│"))

def _hdr_end(color=Fore.CYAN):
    print(_c(color, "└" + "─"*min(W-1, 79)))

def _progress(label: str, done: int, total: int, width: int = 30) -> None:
    pct   = done / max(total, 1)
    filled = int(pct * width)
    bar   = "█" * filled + "░" * (width - filled)
    pct_s = f"{pct*100:5.1f}%"
    print(f"\r  {_c(Fore.CYAN, label)} [{_c(Fore.GREEN, bar)}] {pct_s}  {done}/{total}  ", end="", flush=True)

def _spinner(label: str) -> None:
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    for c in chars:
        print(f"\r  {_c(Fore.CYAN, c)}  {label}  ", end="", flush=True)
        time.sleep(0.05)

def clr():  os.system("cls" if os.name == "nt" else "clear")
def pause(msg="  Press Enter to continue…"):
    try:    input(_c(Fore.CYAN, msg))
    except: pass

# ════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ════════════════════════════════════════════════════════════════════════════
def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def ts_human(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def log(op: str, msg: str = "") -> None:
    redact = ("password","key","secret","token","note","hash")
    if any(w in msg.lower() for w in redact): msg = "[REDACTED]"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{utcnow()}] [{op}] {msg}\n")
    except: pass

def read_json(p: Path, default=None):
    try:
        with open(p, "r", encoding="utf-8") as f: return json.load(f)
    except: return default

def write_json(p: Path, data) -> None:
    try:
        with open(p, "w", encoding="utf-8") as f: json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e: _err(f"JSON write: {e}")

def secure_delete(p: Path) -> None:
    if p.exists():
        sz = max(p.stat().st_size, 1)
        with open(p, "r+b") as f:
            for _ in range(3):
                f.seek(0); f.write(os.urandom(sz)); f.flush(); os.fsync(f.fileno())
        p.unlink()

def sha256h(b: bytes) -> str: return hashlib.sha256(b).hexdigest()

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
def rua() -> str: return secrets.choice(_UA_POOL)

# ════════════════════════════════════════════════════════════════════════════
#  AES-256-GCM
# ════════════════════════════════════════════════════════════════════════════
_MAGIC = b"5EYv8"

def _kdf(pw: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000, dklen=32)

def aes_enc(data: bytes, pw: str) -> bytes:
    s = get_random_bytes(16); n = get_random_bytes(16)
    c = AES.new(_kdf(pw, s), AES.MODE_GCM, nonce=n)
    ct, tag = c.encrypt_and_digest(data)
    return _MAGIC + s + n + tag + ct

def aes_dec(blob: bytes, pw: str) -> bytes:
    if not blob.startswith(_MAGIC): raise ValueError("Bad magic — wrong file or corrupted.")
    o = len(_MAGIC)
    s, n, tag, ct = blob[o:o+16], blob[o+16:o+32], blob[o+32:o+48], blob[o+48:]
    c = AES.new(_kdf(pw, s), AES.MODE_GCM, nonce=n)
    try:    return c.decrypt_and_verify(ct, tag)
    except: raise ValueError("Decryption failed — wrong password or tampered data.")

# ════════════════════════════════════════════════════════════════════════════
#  MASTER PASSWORD (PBKDF2 + salt, with v5/v6 auto-migration)
# ════════════════════════════════════════════════════════════════════════════
def _master_hash(pw: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 300_000, dklen=32).hex()

def _phrase_hash(phrase: str, salt: bytes) -> str:
    """PBKDF2 hash of a passphrase (separate KDF from master pw)."""
    return hashlib.pbkdf2_hmac("sha256", phrase.lower().strip().encode(),
                               salt, 200_000, dklen=32).hex()

# ── Passphrase wordlist (BIP-39-inspired, easy to write down) ────────────────
_PHRASE_WORDS = [
    "alpha","bravo","cobra","delta","eagle","foxtrot","gamma","hunter","india",
    "juliet","kilo","lima","mobile","nova","oscar","phantom","quebec","romeo",
    "sierra","tango","ultra","victor","whiskey","xray","yankee","zulu",
    "black","white","red","blue","green","solar","lunar","arctic","storm",
    "tiger","wolf","falcon","raven","viper","shadow","ghost","cipher","blade",
    "forge","prime","nexus","vault","flame","frost","iron","steel","thunder",
    "proxy","relay","node","root","shell","byte","core","gate","link","mesh",
    "orbit","pixel","quartz","radio","spark","trace","unity","vector","warp",
    "xenon","yield","zenith","apex","burst","cloud","drift","ember","flux",
    "glitch","helix","iota","jolt","kinetic","lumen","mach","null","onyx",
    "pulse","qubit","realm","shard","token","sigma","verge","woven","xeno",
]

def _gen_passphrase(n_words: int = 6) -> str:
    """Generate a random n-word passphrase from the built-in wordlist."""
    return "-".join(secrets.choice(_PHRASE_WORDS) for _ in range(n_words))

def _show_passphrase(phrase: str) -> None:
    """Display the passphrase in a prominent box with write-down prompt."""
    w = 72
    print(_c(Fore.RED + Style.BRIGHT, "\n  " + "!" * w))
    print(_c(Fore.RED + Style.BRIGHT,
          "  !!  RECOVERY PASSPHRASE — WRITE THIS DOWN, STORE IT SAFELY  !!"))
    print(_c(Fore.RED + Style.BRIGHT, "  " + "!" * w))
    print()
    print(_c(Fore.WHITE + Style.BRIGHT,
          f"  ╔{'═'*(w-2)}╗"))
    pad  = (w - 2 - len(phrase)) // 2
    print(_c(Fore.WHITE + Style.BRIGHT, "  ║") +
          " " * pad + _c(Fore.YELLOW + Style.BRIGHT, phrase) +
          " " * (w - 2 - pad - len(phrase)) +
          _c(Fore.WHITE + Style.BRIGHT, "║"))
    print(_c(Fore.WHITE + Style.BRIGHT, f"  ╚{'═'*(w-2)}╝"))
    print()
    print(_c(Fore.YELLOW,
          "  This passphrase lets you RESET your master password if forgotten."))
    print(_c(Fore.YELLOW,
          "  A NEW passphrase is generated after each successful reset."))
    print(_c(Fore.RED,
          "  If you lose both your password AND this passphrase — data is gone forever."))
    print()

def _login_screen() -> None:
    clr()
    banner = r"""
  ██████╗     ███████╗██╗   ██╗███████╗███████╗
  ██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝
  ╚█████╗     █████╗   ╚████╔╝ █████╗  ███████╗
   ╚═══██╗    ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║
  ██████╔╝    ███████╗   ██║   ███████╗███████║
  ╚═════╝     ╚══════╝   ╚═╝   ╚══════╝╚══════╝"""
    for line in banner.splitlines():
        print(_c(Fore.CYAN, line))
    print(_c(Fore.YELLOW, "  Full-Spectrum Intelligence & Security Toolkit  v1.0"))
    print(_c(Fore.WHITE,   "  cyph3r (RG)  ·  AES-256-GCM  ·  PBKDF2-SHA256"))
    _sep()

def _migrate(cfg: dict) -> None:
    """Auto-upgrade old v5/v6 config (unsalted SHA-256) to PBKDF2+salt."""
    print(_c(Fore.YELLOW,
        "\n  Config upgrade needed (old password format detected).\n"
        "  Enter your existing password once to upgrade — vault data unchanged.\n"))
    for attempt in range(1, 4):
        pw = getpass.getpass("  Current password: ")
        if secrets.compare_digest(sha256h(pw.encode()), cfg.get("master_hash", "")):
            salt = get_random_bytes(32)
            cfg["master_hash"] = _master_hash(pw, salt)
            cfg["master_salt"] = base64.b64encode(salt).decode()
            cfg["migrated_at"] = utcnow()
            write_json(CFG_FILE, cfg)
            _ok("Password format upgraded!"); log("MIGRATE", "ok"); return
        left = 3 - attempt
        print(_c(Fore.RED, f"  ✖  Incorrect.{f'  {left} attempt(s) left.' if left else ''}"))
    print(_c(Fore.RED, "  Too many failed attempts.")); sys.exit(1)

def _reset_password(cfg: dict) -> str:
    """
    Reset master password using the recovery passphrase.
    On success: saves new password, generates NEW passphrase, returns new pw.
    """
    clr()
    _sep(color=Fore.RED)
    print(_c(Fore.RED + Style.BRIGHT, "  PASSWORD RESET — RECOVERY PASSPHRASE REQUIRED"))
    _sep(color=Fore.RED)
    print(_c(Fore.YELLOW,
          "\n  Enter your recovery passphrase (e.g. alpha-tiger-vault-storm-relay-nexus)"))
    print(_c(Fore.CYAN,   "  Note: case-insensitive, hyphens required\n"))

    phrase_salt = base64.b64decode(cfg.get("phrase_salt", ""))
    if not phrase_salt:
        _err("No passphrase is registered. Cannot reset.")
        pause(); return ""

    for attempt in range(1, 4):
        entered = input("  Passphrase: ").strip()
        if secrets.compare_digest(
            _phrase_hash(entered, phrase_salt), cfg.get("phrase_hash", "")
        ):
            break
        left = 3 - attempt
        _err(f"Wrong passphrase.{f'  {left} attempt(s) left.' if left else ''}")
    else:
        log("RESET_FAIL", "3 wrong passphrases")
        _err("Too many wrong passphrases. Returning to login."); pause(); return ""

    # ── Set new master password ───────────────────────────────────────────────
    print(_c(Fore.GREEN, "\n  ✔  Passphrase verified — set your new master password.\n"))
    while True:
        p1 = getpass.getpass("  New password (min 8 chars): ")
        p2 = getpass.getpass("  Confirm new password:       ")
        if p1 != p2:    _err("Passwords do not match."); continue
        if len(p1) < 8: _err("Too short (min 8 chars)."); continue
        break

    # ── Generate NEW passphrase for next reset cycle ──────────────────────────
    new_phrase  = _gen_passphrase()
    new_p_salt  = get_random_bytes(32)
    new_m_salt  = get_random_bytes(32)

    cfg["master_hash"]  = _master_hash(p1, new_m_salt)
    cfg["master_salt"]  = base64.b64encode(new_m_salt).decode()
    cfg["phrase_hash"]  = _phrase_hash(new_phrase, new_p_salt)
    cfg["phrase_salt"]  = base64.b64encode(new_p_salt).decode()
    cfg["reset_at"]     = utcnow()
    write_json(CFG_FILE, cfg)

    # ── Show new passphrase ───────────────────────────────────────────────────
    _show_passphrase(new_phrase)
    print(_c(Fore.GREEN + Style.BRIGHT,
          "  Password reset complete! Your new recovery passphrase is shown above."))
    print(_c(Fore.YELLOW, "  The old passphrase no longer works — use the new one.\n"))
    log("RESET_OK", "password reset via passphrase")
    pause("  Press Enter after saving your new passphrase safely…")
    return p1

def auth() -> str:
    """Show login screen, handle first-time setup or login. Returns master pw."""
    _login_screen()
    cfg = read_json(CFG_FILE, default={})

    # ── First-time setup ──────────────────────────────────────────────────────
    if not cfg.get("initialized"):
        print(_c(Fore.YELLOW, "\n  ┌─ FIRST RUN SETUP ──────────────────────────────────────────────────"))
        print(_c(Fore.YELLOW,   "  │  Create your master password AND save your recovery passphrase."))
        print(_c(Fore.YELLOW,   "  └──────────────────────────────────────────────────────────────────\n"))
        while True:
            p1 = getpass.getpass("  New password (min 8 chars): ")
            p2 = getpass.getpass("  Confirm password:           ")
            if p1 != p2:    _err("Passwords do not match."); continue
            if len(p1) < 8: _err("Too short (min 8 chars)."); continue
            break

        # Generate recovery passphrase
        phrase   = _gen_passphrase()
        p_salt   = get_random_bytes(32)
        m_salt   = get_random_bytes(32)

        write_json(CFG_FILE, {
            "master_hash":  _master_hash(p1, m_salt),
            "master_salt":  base64.b64encode(m_salt).decode(),
            "phrase_hash":  _phrase_hash(phrase, p_salt),
            "phrase_salt":  base64.b64encode(p_salt).decode(),
            "initialized":  True,
            "created_at":   utcnow(),
        })

        _show_passphrase(phrase)
        input(_c(Fore.GREEN + Style.BRIGHT,
              "  Press Enter ONLY after you have written down your passphrase… "))
        _ok("Master password set!  Welcome to 5EYES."); log("SETUP", "init")
        time.sleep(0.5); return p1

    # ── Migration (v5/v6) ─────────────────────────────────────────────────────
    if "master_salt" not in cfg:
        _migrate(cfg); cfg = read_json(CFG_FILE, {})

    # ── Login ─────────────────────────────────────────────────────────────────
    print()
    if not cfg.get("phrase_hash"):
        print(_c(Fore.YELLOW, "  ⚠  No recovery passphrase found.  Run [r] from menu to set one.\n"))

    salt = base64.b64decode(cfg["master_salt"])
    print(_c(Fore.CYAN, "  [Enter password]  or  [f] Forgot password (use passphrase)\n"))
    for attempt in range(1, 4):
        pw = getpass.getpass("  Password: ")
        if pw.lower().strip() == "f":
            # Passphrase reset flow
            new_pw = _reset_password(cfg)
            if new_pw:
                cfg = read_json(CFG_FILE, {})
                return new_pw
            # Reset failed — restart login
            _login_screen()
            salt = base64.b64decode(read_json(CFG_FILE, {}).get("master_salt", base64.b64encode(salt).decode()))
            continue
        if secrets.compare_digest(_master_hash(pw, salt), cfg["master_hash"]):
            log("LOGIN", "ok"); return pw
        left = 3 - attempt
        _err(f"Incorrect password.{f'  {left} attempt(s) left.' if left else ''}")
        if attempt == 2:
            print(_c(Fore.YELLOW, "  Tip: type  f  and press Enter to reset via passphrase."))

    log("LOCKOUT", "3 fails")
    print(_c(Fore.RED, "\n  Too many failed attempts."))
    print(_c(Fore.YELLOW, "  Type  f  to attempt password reset via passphrase, or Ctrl+C to exit."))
    last = getpass.getpass("  Password (or f): ").strip()
    if last.lower() == "f":
        new_pw = _reset_password(read_json(CFG_FILE, {}))
        if new_pw: return new_pw
    print(_c(Fore.RED, "  Locked out.")); sys.exit(1)

# ════════════════════════════════════════════════════════════════════════════
_MENU = [
    # (key, category_label, item_label)
    ("",   "RECON  &  OSINT",         ""),
    ("1",  "",  "IP / Domain Recon          — WHOIS · GeoIP · ASN · full DNS"),
    ("2",  "",  "Subdomain Enumerator       — DNS brute · crt.sh CT · permutations"),
    ("3",  "",  "Username OSINT             — 20 platforms · parallel · confidence"),
    ("4",  "",  "Email Header Analyzer      — hop trace · SPF/DKIM/DMARC · spoof"),
    ("5",  "",  "Port Scanner               — TCP · banner grab · CVE hints"),
    ("",   "CRYPTO  &  VAULT",        ""),
    ("6",  "",  "AES-256 Vault              — text encrypt / decrypt"),
    ("7",  "",  "File Encrypt / Decrypt     — AES-GCM, no key stored on disk"),
    ("8",  "",  "Secure Notes               — per-note AES-GCM · list · delete"),
    ("9",  "",  "Password Suite             — generate · strength · HIBP breach check"),
    ("",   "FORENSICS  &  ANALYSIS",  ""),
    ("10", "",  "Hash Suite                 — hash · crack · file integrity monitor"),
    ("11", "",  "JWT Analyzer               — decode · alg audit · expiry · claims"),
    ("12", "",  "Metadata Extractor         — EXIF · Office · file hashes"),
    ("13", "",  "Steganography              — LSB hide / extract (PNG)"),
    ("",   "ENCODING  &  DECODING",   ""),
    ("14", "",  "Encode / Decode Center     — auto-detect · B64 · ROT · Hex · Caesar"),
    ("",   "NETWORK  &  PRIVACY",     ""),
    ("15", "",  "Tor / Proxy Checker        — exit-node · header leak · anonymity score"),
    ("",   "SYSTEM  &  SECURITY",    ""),
    (" n", "",  "Nuclear Wipe               — FULL self-destruct: vault + config + all data"),
    (" c", "",  "Change Password            — new password + regenerated recovery passphrase"),
    (" p", "",  "Panic Wipe                 — wipe logs + integrity DB only, exit now"),
    (" s", "",  "Stealth Mode               — disguise as MathHelper calculator"),
]

def dashboard() -> None:
    clr()
    fp = sha256h(
        f"{platform.node()}|{platform.system()}|{platform.machine()}".encode()
    )[:20]
    w = min(W, 80)
    print(_c(Fore.CYAN,  "╔" + "═"*(w-2) + "╗"))
    title = "  5EYES  INTELLIGENCE TOOLKIT  v1.0  "
    pad = (w-2-len(title))//2
    print(_c(Fore.CYAN, "║") + " "*pad + _c(Fore.WHITE+Style.BRIGHT, title)
          + " "*(w-2-pad-len(title)) + _c(Fore.CYAN, "║"))
    sub = f"  Device: {fp}…   {utcnow()}  "
    pad2 = (w-2-len(sub))//2
    print(_c(Fore.CYAN, "║") + " "*pad2 + _c(Fore.YELLOW, sub)
          + " "*(w-2-pad2-len(sub)) + _c(Fore.CYAN, "║"))
    print(_c(Fore.CYAN, "╠" + "═"*(w-2) + "╣"))

    for key, cat, item in _MENU:
        if cat:
            lbl = f"  ◈  {cat}  "
            print(_c(Fore.CYAN, "║") + _c(Fore.YELLOW+Style.BRIGHT, lbl)
                  + " "*(w-2-len(lbl)) + _c(Fore.CYAN, "║"))
        elif key:
            line = f"    [{key:>2}]  {item}"
            print(_c(Fore.CYAN, "║") + _c(Fore.GREEN, f"  [{key:>2}]")
                  + _c(Fore.WHITE, f"  {item}")
                  + " "*(w-2-len(line)) + _c(Fore.CYAN, "║"))

    print(_c(Fore.CYAN, "╠" + "═"*(w-2) + "╣"))
    ctrl = "  [q] Quit    [p] Panic    [n] NUKE    [c] Change-PW    [h] Help    [s] Stealth  "
    pad3 = (w-2-len(ctrl))//2
    print(_c(Fore.CYAN, "║") + " "*pad3 + _c(Fore.RED, ctrl)
          + " "*(w-2-pad3-len(ctrl)) + _c(Fore.CYAN, "║"))
    print(_c(Fore.CYAN, "╚" + "═"*(w-2) + "╝"))

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 1 — IP / DOMAIN RECON
# ════════════════════════════════════════════════════════════════════════════
def _whois(target: str, server="whois.iana.org") -> str:
    try:
        with socket.create_connection((server, 43), timeout=10) as s:
            s.sendall((target + "\r\n").encode())
            buf = b""
            while True:
                c = s.recv(4096)
                if not c: break
                buf += c
        text = buf.decode("utf-8", errors="replace")
        for line in text.splitlines():
            if line.lower().startswith("refer:"):
                ref = line.split(":", 1)[1].strip()
                if ref != server: return _whois(target, ref)
        return text
    except Exception as e: return f"WHOIS error: {e}"

def _geoip(ip: str) -> dict:
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719",
                         timeout=8, headers={"User-Agent": rua()})
        return r.json() if r.ok else {}
    except: return {}

def _asn_lookup(ip: str) -> str:
    """Cymru Team ASN lookup via DNS TXT."""
    try:
        rev = ".".join(reversed(ip.split(".")))
        ans = socket.getaddrinfo(f"{rev}.origin.asn.cymru.com", None)
        return str(ans[0]) if ans else "?"
    except:
        pass
    # Fallback: use ip-api org field
    return ""

def _dns_all(domain: str) -> Dict[str, List[str]]:
    records: Dict[str, List[str]] = {}
    rtypes = ["A","AAAA","MX","TXT","NS","CNAME","SOA","CAA","PTR","SRV"]
    if DNS_LIB:
        res = dns.resolver.Resolver()
        res.timeout = 4; res.lifetime = 6
        for rtype in rtypes:
            try:
                ans = res.resolve(domain, rtype)
                records[rtype] = [str(r) for r in ans]
            except: pass
    else:
        try:
            ips = {i[4][0] for i in socket.getaddrinfo(domain, None)}
            records["A"] = list(ips)
        except: pass
    return records

def _rdns(ip: str) -> str:
    try:    return socket.gethostbyaddr(ip)[0]
    except: return "—"

def ip_recon(target: str) -> None:
    _hdr(f"IP / Domain Recon  →  {target}")
    is_ip = False
    try:   ipaddress.ip_address(target); is_ip = True; ip = target
    except:
        try:
            ip = socket.gethostbyname(target)
            print(_c(Fore.CYAN, f"  │  ") + f"Resolved  : {_c(Fore.GREEN, ip)}")
        except Exception as e: _err(f"Cannot resolve: {e}"); return

    # GeoIP
    geo = _geoip(ip)
    if geo.get("status") == "success":
        print(_c(Fore.CYAN,"  │"))
        print(_c(Fore.CYAN,"  │  ") + _c(Fore.YELLOW+Style.BRIGHT, "[ GeoIP ]"))
        for k, label in [("country","Country"),("regionName","Region"),("city","City"),
                          ("isp","ISP"),("org","Org"),("as","ASN"),
                          ("lat","Lat"),("lon","Lon"),("timezone","Timezone")]:
            v = geo.get(k,"")
            if v: print(_c(Fore.CYAN,"  │  ") + f"{label:<12}: {_c(Fore.WHITE, str(v))}")

    # Reverse DNS
    rdns = _rdns(ip)
    print(_c(Fore.CYAN,"  │"))
    print(_c(Fore.CYAN,"  │  ") + f"Reverse DNS: {_c(Fore.WHITE, rdns)}")

    # DNS records
    if not is_ip:
        print(_c(Fore.CYAN,"  │"))
        print(_c(Fore.CYAN,"  │  ") + _c(Fore.YELLOW+Style.BRIGHT, "[ DNS Records ]"))
        dns_recs = _dns_all(target)
        if dns_recs:
            for rtype, vals in dns_recs.items():
                for v in vals[:5]:
                    print(_c(Fore.CYAN,"  │  ") + f"{_c(Fore.GREEN, rtype):<10} {v}")
        else: print(_c(Fore.CYAN,"  │  ") + "No records found")

    # WHOIS (key lines only)
    print(_c(Fore.CYAN,"  │"))
    print(_c(Fore.CYAN,"  │  ") + _c(Fore.YELLOW+Style.BRIGHT, "[ WHOIS (key fields) ]"))
    raw = _whois(target if is_ip else target)
    important = re.compile(
        r"^(registrar|registrant|admin|tech|name.server|creation|expir|updated|country"
        r"|organization|netname|inetnum|cidr|route|descr|abuse)",
        re.IGNORECASE
    )
    shown = 0
    for line in raw.splitlines():
        if important.match(line.strip()) and ":" in line and shown < 25:
            k, _, v = line.partition(":")
            v = v.strip()
            if v and v not in ("REDACTED FOR PRIVACY", "Please query the RDDS"):
                print(_c(Fore.CYAN,"  │  ") + f"{k.strip():<22}: {_c(Fore.WHITE, v)}")
                shown += 1

    _hdr_end(); log("RECON", f"target={target}")

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 2 — SUBDOMAIN ENUMERATOR  (Amass-style multi-source)
# ════════════════════════════════════════════════════════════════════════════
_SUB_WORDLIST = [
    "www","mail","ftp","smtp","pop","ns1","ns2","ns3","ns4","webmail","vpn",
    "dev","api","app","test","staging","beta","admin","portal","secure","remote",
    "cloud","m","mobile","blog","shop","store","media","cdn","static","assets",
    "img","images","video","files","download","uploads","s3","backup","db",
    "database","mysql","redis","mongo","ldap","imap","pop3","exchange","owa",
    "autodiscover","mx","mx1","mx2","relay","gateway","proxy","fw","firewall",
    "vpn1","vpn2","sso","auth","login","oauth","id","idp","git","gitlab",
    "jira","confluence","wiki","docs","help","support","status","monitor",
    "jenkins","ci","cd","build","k8s","docker","registry","internal","intranet",
    "corp","office","hq","dc","prod","production","uat","qa","sandbox","demo",
    "old","legacy","new","v1","v2","v3","api2","rest","graphql","ws","socket",
    "payment","pay","billing","crm","erp","hr","finance","analytics","stats",
    "metrics","logs","sec","security","cert","ssl","smtp1","smtp2","mail2",
    "dns","dns1","dns2","ntp","repo","mirror","vault","config","web","web2",
    "server","server1","server2","node","lb","cache","master","primary","db2",
    "pgadmin","phpmyadmin","kibana","grafana","prometheus","elastic","jupyter",
    "notebook","spark","kafka","solr","cassandra","mongo2","influx","minio",
    "share","nas","backup2","dr","failover","read","write","queue","worker",
    "cron","agent","hub","event","alert","report","export","sync","data",
    "datalake","warehouse","ml","ai","model","inference","train","rstudio",
]

def _crtsh(domain: str) -> List[str]:
    """Certificate Transparency via crt.sh — returns list of unique subdomains."""
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15, headers={"User-Agent": rua()}
        )
        if not r.ok: return []
        subs = set()
        for entry in r.json():
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    subs.add(name.lower())
        return sorted(subs)
    except: return []

def _permutations(domain: str) -> List[str]:
    """Generate common sub-domain permutations from base wordlist."""
    base = domain.split(".")[0]
    extras = set()
    prefixes = ["dev","stg","staging","prod","api","internal","test","new","old","2","3"]
    for w in _SUB_WORDLIST[:30]:
        extras.add(f"{w}-{base}.{domain}")
        extras.add(f"{base}-{w}.{domain}")
    for p in prefixes:
        extras.add(f"{p}.{domain}")
    return list(extras)

def _resolve_sub(fqdn: str, timeout: float = 2.5) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(fqdn)
    except: return None
    finally: socket.setdefaulttimeout(None)

def subdomain_enum(domain: str, custom_wl: Optional[List[str]] = None,
                   threads: int = 60, use_crtsh: bool = True) -> List[Dict]:
    found: List[Dict] = []
    seen:  set = set()
    lock  = threading.Lock()

    # ── Source 1: wordlist ──────────────────────────────────────────────────
    wl = custom_wl or _SUB_WORDLIST
    candidates = [f"{w}.{domain}" for w in wl]

    # ── Source 2: crt.sh ───────────────────────────────────────────────────
    crtsh_subs: List[str] = []
    if use_crtsh:
        _info("Querying Certificate Transparency (crt.sh)…")
        crtsh_subs = _crtsh(domain)
        _ok(f"crt.sh returned {len(crtsh_subs)} unique names")
        # Add any new ones not already in candidates
        for s in crtsh_subs:
            if s not in candidates:
                candidates.append(s)

    # ── Source 3: permutations ─────────────────────────────────────────────
    _info("Generating permutations…")
    perms = _permutations(domain)
    for p in perms:
        if p not in candidates: candidates.append(p)

    # ── Wildcard check ──────────────────────────────────────────────────────
    rand_sub = secrets.token_hex(12) + f".{domain}"
    wildcard_ip = _resolve_sub(rand_sub)
    if wildcard_ip:
        _warn(f"Wildcard DNS detected ({wildcard_ip}) — filtering wildcard results")

    total = len(candidates); done = [0]

    def worker(fqdn: str):
        ip = _resolve_sub(fqdn)
        done[0] += 1
        if done[0] % 40 == 0:
            _progress("Scanning", done[0], total)
        if ip and ip != wildcard_ip and fqdn not in seen:
            with lock:
                seen.add(fqdn)
                source = "crt.sh" if fqdn in crtsh_subs else "dns"
                found.append({"subdomain": fqdn, "ip": ip, "source": source})
                print(_c(Fore.GREEN, f"\n  [+] {fqdn:<50} {ip:<16}  [{source}]"))

    _info(f"Resolving {total} candidates ({threads} threads)…\n")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        list(ex.map(worker, candidates))

    print()
    found.sort(key=lambda x: x["subdomain"])

    # Export
    if found:
        out = EXPORT_DIR / f"subdomains_{domain}_{int(time.time())}.csv"
        with open(out, "w") as f:
            f.write("subdomain,ip,source\n")
            for r in found: f.write(f"{r['subdomain']},{r['ip']},{r['source']}\n")
        _ok(f"Exported {len(found)} results → {out}")

    log("SUBDOMAIN", f"domain={domain} found={len(found)}")
    return found

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 3 — USERNAME OSINT v2  (combo engine · 25 platforms · only ALIVE)
# ════════════════════════════════════════════════════════════════════════════

_PLATFORMS = {
    "GitHub":        ("https://github.com/{u}",                         200),
    "GitLab":        ("https://gitlab.com/{u}",                         200),
    "Reddit":        ("https://www.reddit.com/user/{u}",                200),
    "X / Twitter":   ("https://x.com/{u}",                              200),
    "Instagram":     ("https://www.instagram.com/{u}/",                 200),
    "TikTok":        ("https://www.tiktok.com/@{u}",                    200),
    "YouTube":       ("https://www.youtube.com/@{u}",                   200),
    "Twitch":        ("https://www.twitch.tv/{u}",                      200),
    "Pinterest":     ("https://www.pinterest.com/{u}/",                 200),
    "Medium":        ("https://medium.com/@{u}",                        200),
    "Dev.to":        ("https://dev.to/{u}",                             200),
    "Keybase":       ("https://keybase.io/{u}",                         200),
    "Telegram":      ("https://t.me/{u}",                               200),
    "LinkedIn":      ("https://www.linkedin.com/in/{u}/",               200),
    "HackerNews":    ("https://news.ycombinator.com/user?id={u}",       200),
    "Steam":         ("https://steamcommunity.com/id/{u}",              200),
    "Pastebin":      ("https://pastebin.com/u/{u}",                     200),
    "Replit":        ("https://replit.com/@{u}",                        200),
    "Codepen":       ("https://codepen.io/{u}",                         200),
    "Tryhackme":     ("https://tryhackme.com/p/{u}",                    200),
    "HackTheBox":    ("https://app.hackthebox.com/profile/{u}",         200),
    "Bugcrowd":      ("https://bugcrowd.com/{u}",                       200),
    "Hackerone":     ("https://hackerone.com/{u}",                      200),
    "Stackoverflow": ("https://stackoverflow.com/users/{u}",            200),
    "Snapchat":      ("https://www.snapchat.com/add/{u}",               200),
}

# Leet table: char -> list of possible substitutions (original first)
_LEET = {
    "a": ["a","4","@"],   "e": ["e","3"],      "i": ["i","1","!"],
    "o": ["o","0"],       "s": ["s","5","$"],  "t": ["t","7"],
    "g": ["g","9"],       "b": ["b","8"],      "l": ["l","1"],
    "z": ["z","2"],
}

# Number suffixes (years, classics, gamer numbers)
_NUM_SUFFIXES = [
    "1990","1991","1992","1993","1994","1995","1996","1997","1998","1999",
    "2000","2001","2002","2003","2004","2005","2006","2007","2008","2009","2010",
    "90","91","92","93","94","95","96","97","98","99",
    "00","01","02","03","04","05","06","07","08","09","10",
    "1","2","3","007","13","21","42","69","77","99","100","101","123",
    "1337","31337","404","420","666","777","999","1234","12345","2023","2024","2025",
]

# Word suffixes (role / style / platform slang)
_WORD_SUFFIXES = [
    "_og","_real","_official","_irl","_tv","_yt","_ig","_ttv",
    "_xx","_xo","_pro","_dev","_sec","_hax","_pwn","_r00t",
    "_admin","_x","_vip","_elite","_dark","_shadow","_ghost",
    "_online","_active","_live","_new","_old","_backup",
]

# Word prefixes
_WORD_PREFIXES = [
    "x_","xx_","the_","real_","i_","iam_","its_","im_",
    "official_","mr_","ms_","dr_","0x_","th3_","1337_",
]


def _leet_variants(username: str) -> List[str]:
    variants: set = set()
    u = username.lower()
    variants.add(u)
    # Single-char swaps
    for i, ch in enumerate(u):
        if ch in _LEET:
            for sub in _LEET[ch]:
                if sub != ch:
                    variants.add(u[:i] + sub + u[i+1:])
    # All-leet variant
    all_leet = ""
    changed = False
    for ch in u:
        alts = _LEET.get(ch, [ch])
        best = next((a for a in alts if a != ch), ch)
        if best != ch: changed = True
        all_leet += best
    if changed: variants.add(all_leet)
    # Reverse-leet (symbols back to letters)
    rev = {"4":"a","@":"a","3":"e","1":"i","!":"i","0":"o","5":"s","$":"s","7":"t","9":"g","8":"b","2":"z"}
    rev_str = "".join(rev.get(ch, ch) for ch in u)
    if rev_str != u: variants.add(rev_str)
    return sorted(variants)


def _generate_combinations(username: str, max_combos: int = 500) -> List[str]:
    base   = username.lower().strip()
    combos: set = set()

    # 1. Original + case variants
    combos.update([base, base.upper(), base.capitalize()])

    # 2. Leet variants
    leets = _leet_variants(base)
    combos.update(leets)

    # 3. Number suffixes on base + all leet variants (with separators)
    for variant in list(leets) + [base]:
        for sep in ("", "_", "-", "."):
            for num in _NUM_SUFFIXES:
                combos.add(f"{variant}{sep}{num}")
                if len(combos) >= max_combos * 3: break

    # 4. Word suffixes
    for variant in list(leets) + [base]:
        for wsuf in _WORD_SUFFIXES:
            combos.add(f"{variant}{wsuf}")

    # 5. Word prefixes
    for wpfx in _WORD_PREFIXES:
        combos.add(f"{wpfx}{base}")

    # 6. Double (handle mirror-style handles)
    for sep in ("_", "__", ".", ""):
        combos.add(f"{base}{sep}{base}")

    # Trim: original always first
    ordered = [base] + sorted(c for c in combos if c != base)
    return ordered[:max_combos]


def _check_one(platform: str, url_tmpl: str, exp_code: int,
               username: str, timeout: int = 7) -> Tuple[str, Optional[str], str]:
    url  = url_tmpl.format(u=username)
    hdrs = {"User-Agent": rua()}
    try:
        r = requests.head(url, timeout=timeout, headers=hdrs, allow_redirects=True)
        if r.status_code == exp_code:  return (platform, url, "ALIVE")
        if r.status_code == 404:       return (platform, None, "DEAD")
        r2 = requests.get(url, timeout=timeout, headers=hdrs, allow_redirects=True)
        if r2.status_code == exp_code: return (platform, url, "ALIVE")
        return (platform, None, f"HTTP {r2.status_code}")
    except Exception as e:
        return (platform, None, f"ERR:{str(e)[:30]}")


def username_osint(username: str) -> None:
    _hdr(f"Username OSINT  →  {username}")

    # Step 1: generate + preview combos
    combos = _generate_combinations(username)
    print(_c(Fore.YELLOW+Style.BRIGHT,
          f"  │  [ Combination Engine — {len(combos)} variants generated ]"))
    preview = combos[:24]
    cols = 4
    for row in [preview[i:i+cols] for i in range(0, len(preview), cols)]:
        print("  │    " + "  ".join(f"{_c(Fore.CYAN, v):<32}" for v in row))
    if len(combos) > 24:
        print(_c(Fore.CYAN, f"  │    … and {len(combos)-24} more variants"))
    print(_c(Fore.CYAN, "  │"))

    # Step 2: mode selection
    print("  │  Scan mode:")
    print("  │    [1]  Original username only               (~25 checks, instant)")
    print("  │    [2]  Original + leet variants             (~8 variants x 25)")
    print(f"  │    [3]  FULL combo scan — all {len(combos)} variants  (deep recon)")
    print("  │    [4]  Custom — pick specific variants to scan")
    mode = input(_c(Fore.WHITE, "  │  Mode [1]: ")).strip() or "1"

    if mode == "1":
        targets = [username]
    elif mode == "2":
        targets = list(dict.fromkeys([username] + _leet_variants(username)[:8]))
    elif mode == "3":
        targets = combos
    elif mode == "4":
        print(f"\n  Variants (first 60):")
        for i, c in enumerate(combos[:60], 1):
            print(f"    {i:>3}. {c}")
        raw = input("  Enter numbers (e.g. 1,3,5,12): ").strip()
        try:
            idxs = [int(x.strip())-1 for x in raw.split(",") if x.strip().isdigit()]
            targets = [combos[i] for i in idxs if 0 <= i < len(combos)] or [username]
        except: targets = [username]
    else:
        targets = [username]

    targets = list(dict.fromkeys(targets))

    # Step 3: parallel scan
    total_checks = len(targets) * len(_PLATFORMS)
    done         = [0]
    lock         = threading.Lock()
    all_results: Dict[str, List[Tuple[str, str]]] = {}
    alive_count  = [0]

    jobs = [
        (variant, platform, tmpl, code)
        for variant in targets
        for platform, (tmpl, code) in _PLATFORMS.items()
    ]

    print(_c(Fore.CYAN, "  │"))
    print(_c(Fore.YELLOW+Style.BRIGHT,
          f"  │  [ Scanning {len(targets)} username(s) × {len(_PLATFORMS)} platforms "
          f"= {total_checks} total checks ]"))
    print(_c(Fore.CYAN, "  │"))

    def worker(job):
        variant, platform, tmpl, code = job
        plat, url, status = _check_one(platform, tmpl, code, variant)
        with lock:
            done[0] += 1
            if done[0] % 25 == 0 or done[0] == total_checks:
                _progress("Scanning", done[0], total_checks, width=35)
            if status == "ALIVE" and url:
                alive_count[0] += 1
                all_results.setdefault(variant, []).append((plat, url))
                print(_c(Fore.GREEN,
                      f"\n  [● ALIVE]  "
                      f"{_c(Fore.WHITE+Style.BRIGHT, variant):<32}  "
                      f"{plat:<18}  {_c(Fore.CYAN, url)}"))

    with ThreadPoolExecutor(max_workers=min(80, total_checks or 1)) as ex:
        list(ex.map(worker, jobs))

    print("\n")

    # Step 4: summary
    _sep("═")
    print(_c(Fore.YELLOW+Style.BRIGHT, "  RESULTS — ALIVE ONLY"))
    _sep("─")

    if not all_results:
        _warn("No alive accounts found.")
    else:
        print(_c(Fore.GREEN+Style.BRIGHT,
              f"  ✔  {alive_count[0]} alive hit(s) across {len(all_results)} username variant(s)\n"))
        for variant, hits in sorted(all_results.items()):
            print(_c(Fore.WHITE+Style.BRIGHT, f"  ◈  {variant}"))
            for plat, url in sorted(hits):
                print(f"      {_c(Fore.GREEN, '● ALIVE')}  {plat:<22}  {_c(Fore.CYAN, url)}")
            print()

    # Confidence bar (original username)
    orig_hits = len(all_results.get(username, []))
    conf      = round((orig_hits / len(_PLATFORMS)) * 100)
    bar       = "█"*(conf//5) + "░"*(20-conf//5)
    color     = Fore.GREEN if conf > 40 else Fore.YELLOW if conf > 10 else Fore.RED
    print(f"  Presence score ({username}): [{_c(color, bar)}]  {conf}%  "
          f"({orig_hits}/{len(_PLATFORMS)} platforms)")

    # Step 5: save report
    if all_results:
        out_file = EXPORT_DIR / f"osint_{username}_{int(time.time())}.txt"
        with open(out_file, "w", encoding="utf-8") as f:
            f.write("=" * 72 + "\n")
            f.write(f"  5EYES USERNAME OSINT REPORT\n")
            f.write(f"  Target   : {username}\n")
            f.write(f"  Variants : {len(targets)}\n")
            f.write(f"  Platforms: {len(_PLATFORMS)}\n")
            f.write(f"  Checks   : {total_checks}\n")
            f.write(f"  Alive    : {alive_count[0]}\n")
            f.write(f"  Date     : {utcnow()}\n")
            f.write("=" * 72 + "\n\n")
            for variant, hits in sorted(all_results.items()):
                f.write(f"[{variant}]\n")
                for plat, url in sorted(hits):
                    f.write(f"  ALIVE  {plat:<24}  {url}\n")
                f.write("\n")
        _ok(f"Report saved → {out_file}")

    _hdr_end()
    log("OSINT_USER", f"user={username} variants={len(targets)} alive={alive_count[0]}")


# ════════════════════════════════════════════════════════════════════════════
#  MODULE 4 — EMAIL HEADER ANALYZER
# ════════════════════════════════════════════════════════════════════════════
def email_header_analyze(raw: str) -> None:
    _hdr("Email Header Analyzer")
    raw = raw.replace("\r\n","\n").replace("\r","\n")
    # Unfold
    hdrs: List[str] = []
    for line in raw.splitlines():
        if line and line[0] in (" ","\t") and hdrs: hdrs[-1] += " " + line.strip()
        else: hdrs.append(line)
    parsed: Dict[str, List[str]] = {}
    for h in hdrs:
        if ":" in h:
            k, _, v = h.partition(":"); parsed.setdefault(k.strip().lower(), []).append(v.strip())

    # Key fields
    print(_c(Fore.YELLOW+Style.BRIGHT, "  │  [ Key Fields ]"))
    for f in ("from","to","reply-to","subject","date","message-id","x-originating-ip","x-mailer"):
        v = parsed.get(f, [""])[0]
        if v: print(_c(Fore.CYAN,"  │  ") + f"  {f:<24}: {_c(Fore.WHITE, v[:100])}")

    # Hops
    received = parsed.get("received", [])
    print(_c(Fore.CYAN,"  │"))
    print(_c(Fore.YELLOW+Style.BRIGHT, f"  │  [ Relay Hops — {len(received)} ]"))
    for i, hop in enumerate(received, 1):
        ts = re.search(r";\s*(.{10,40}(?:GMT|UTC|[+-]\d{4}))", hop)
        tstr = ts.group(1).strip() if ts else ""
        print(_c(Fore.CYAN,"  │  ") + f"  Hop {i}: {hop[:90]}")
        if tstr: print(_c(Fore.CYAN,"  │  ") + f"         {_c(Fore.CYAN, 'Time: '+tstr)}")

    # Auth / spoofing
    print(_c(Fore.CYAN,"  │"))
    print(_c(Fore.YELLOW+Style.BRIGHT, "  │  [ Authentication & Spoofing ]"))
    full = " ".join(sum(parsed.values(), [])).lower()
    checks = {
        "SPF":   ("spf=pass", "spf=fail",  "spf=softfail"),
        "DKIM":  ("dkim=pass","dkim=fail",  "dkim=none"),
        "DMARC": ("dmarc=pass","dmarc=fail","dmarc=none"),
    }
    for proto, (ok_kw, fail_kw, soft_kw) in checks.items():
        if ok_kw   in full: print(_c(Fore.CYAN,"  │  ") + _c(Fore.GREEN,  f"  ✔  {proto}: PASS"))
        elif fail_kw in full: print(_c(Fore.CYAN,"  │  ") + _c(Fore.RED,  f"  ✖  {proto}: FAIL  ← spoofing risk"))
        elif soft_kw in full: print(_c(Fore.CYAN,"  │  ") + _c(Fore.YELLOW,f"  ⚠  {proto}: SOFTFAIL"))
        else: print(_c(Fore.CYAN,"  │  ") + _c(Fore.YELLOW, f"  ?  {proto}: not found"))

    # FROM vs REPLY-TO domain check
    fd = re.search(r"@([\w.-]+)", parsed.get("from",[""])[0] or "")
    rd = re.search(r"@([\w.-]+)", parsed.get("reply-to",[""])[0] or "")
    if fd and rd and fd.group(1).lower() != rd.group(1).lower():
        print(_c(Fore.CYAN,"  │  ") + _c(Fore.RED,
            f"  ✖  FROM domain ({fd.group(1)}) ≠ REPLY-TO domain ({rd.group(1)})  ← phishing indicator"))

    _hdr_end()

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 5 — PORT SCANNER
# ════════════════════════════════════════════════════════════════════════════
_SVC = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
    111:"RPC",135:"MSRPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",
    465:"SMTPS",587:"SMTP-TLS",631:"IPP",993:"IMAPS",995:"POP3S",
    1433:"MSSQL",1521:"Oracle",2049:"NFS",2181:"ZooKeeper",3306:"MySQL",
    3389:"RDP",4444:"MSF-Shell",5432:"PostgreSQL",5900:"VNC",5984:"CouchDB",
    6379:"Redis",6667:"IRC",8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"Jupyter",
    9200:"Elasticsearch",9418:"Git",11211:"Memcached",27017:"MongoDB",
}
# Simple CVE hints for common services
_CVE_HINTS = {
    "Redis":         "CVE-2022-0543 — Lua sandbox escape; auth bypass if no password set",
    "Elasticsearch": "CVE-2021-22145 — info disclosure; often unauthenticated by default",
    "MongoDB":       "CVE-2013-2132 — no auth by default in older versions",
    "Memcached":     "CVE-2018-1000115 — UDP amplification DDoS vector",
    "Jupyter":       "No auth → RCE if exposed publicly",
    "MSF-Shell":     "Common Metasploit payload port — possible active implant",
    "FTP":           "Anonymous login / cleartext credentials common",
    "Telnet":        "Cleartext protocol — MITM trivial",
    "RDP":           "CVE-2019-0708 BlueKeep — check patch level",
    "SMB":           "CVE-2017-0144 EternalBlue / MS17-010 — critical if unpatched",
}

def _scan_port(host: str, port: int, to: float) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=to) as s:
            s.settimeout(0.4)
            try:    return s.recv(1024).decode("utf-8", errors="replace").strip()
            except: return ""
    except: return None

def port_scan(host: str, ports: List[int], timeout: float = 1.0, threads: int = 150) -> List[Dict]:
    results: List[Dict] = []; lock = threading.Lock()
    total = len(ports); done = [0]

    def worker(port):
        banner = _scan_port(host, port, timeout)
        done[0] += 1
        if done[0] % 50 == 0: _progress("Scanning", done[0], total)
        if banner is not None:
            svc = _SVC.get(port, "Unknown")
            with lock:
                results.append({"port":port,"service":svc,"banner":banner[:80]})
                print(_c(Fore.GREEN, f"\n  [+] {port}/tcp  {svc:<16}  {banner[:55]}"))

    _info(f"Scanning {len(ports)} port(s) on {host}…\n")
    with ThreadPoolExecutor(max_workers=min(threads, len(ports))) as ex:
        list(ex.map(worker, ports))

    print()
    results.sort(key=lambda x: x["port"])
    # CVE hints
    for r in results:
        hint = _CVE_HINTS.get(r["service"])
        if hint: print(_c(Fore.YELLOW, f"  ⚠  [{r['port']}] {r['service']}: {hint}"))
    return results

def parse_ports(spec: str) -> List[int]:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1); ports.update(range(int(a), int(b)+1))
        else: ports.add(int(part))
    return sorted(ports)

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 6 — AES-256 VAULT  (text)
# ════════════════════════════════════════════════════════════════════════════
def vault_text(pw: str) -> None:
    _hdr("AES-256-GCM Text Vault")
    print("  1. Encrypt text    2. Decrypt blob")
    sub = input(_c(Fore.WHITE,"  Choice > ")).strip()
    if sub == "1":
        data = input("  Data: ")
        if not data: return
        enc = aes_enc(data.encode(), pw)
        print(_c(Fore.GREEN, "\n  Encrypted (Base64):"))
        print("  " + base64.b64encode(enc).decode())
    elif sub == "2":
        b64 = input("  Base64 blob: ")
        try:
            plain = aes_dec(base64.b64decode(b64 + "=="), pw)
            print(_c(Fore.GREEN, "\n  Decrypted: ") + plain.decode("utf-8", errors="replace"))
        except Exception as e: _err(str(e))
    _hdr_end()

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 7 — FILE ENCRYPT / DECRYPT
# ════════════════════════════════════════════════════════════════════════════
def file_enc_dec() -> None:
    _hdr("File Encrypt / Decrypt")
    print("  1. Encrypt file    2. Decrypt file")
    sub = input(_c(Fore.WHITE,"  Choice > ")).strip()
    fp  = input("  File path: ").strip()
    p   = Path(fp)
    if not p.exists(): _err("File not found."); return
    pw = getpass.getpass("  Password: ")
    if sub == "1":
        pw2 = getpass.getpass("  Confirm : ")
        if pw != pw2: _err("Passwords do not match."); return
        out = str(p) + ".enc"
        Path(out).write_bytes(aes_enc(p.read_bytes(), pw))
        _ok(f"Encrypted → {out}"); log("ENC_FILE", fp)
    elif sub == "2":
        try:
            raw = aes_dec(p.read_bytes(), pw)
            out = str(p)[:-4] if fp.endswith(".enc") else str(p) + ".dec"
            Path(out).write_bytes(raw)
            _ok(f"Decrypted → {out}"); log("DEC_FILE", fp)
        except Exception as e: _err(str(e))
    _hdr_end()

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 8 — SECURE NOTES
# ════════════════════════════════════════════════════════════════════════════
def _note_p(name: str) -> Path:
    return NOTES_DIR / (re.sub(r"[^\w\-]","_",name.strip()) + ".enote")

def notes_menu(master_pw: str) -> None:
    _hdr("Secure Notes Vault")
    print("  1. New note    2. Read note    3. List notes    4. Delete note")
    sub = input(_c(Fore.WHITE,"  Choice > ")).strip()

    if sub == "1":
        name = input("  Note name: ").strip()
        print("  Content (blank line twice to finish):")
        lines, prev = [], ""
        while True:
            try:
                l = input()
                if l == "" and prev == "": break
                lines.append(l); prev = l
            except EOFError: break
        content = "\n".join(lines)
        pw = getpass.getpass("  Note password: ")
        data = json.dumps({"name":name,"content":content,"ts":utcnow()}).encode()
        _note_p(name).write_bytes(aes_enc(data, pw))
        _ok(f"Note '{name}' saved."); log("NOTE_SAVE", f"name={name}")

    elif sub == "2":
        name = input("  Note name: ").strip()
        pw   = getpass.getpass("  Note password: ")
        try:
            note = json.loads(aes_dec(_note_p(name).read_bytes(), pw))
            print(_c(Fore.CYAN, f"\n  ── {note['name']}  [{note['ts']}] ──"))
            print(note["content"])
        except Exception as e: _err(str(e))

    elif sub == "3":
        notes = [p.stem for p in NOTES_DIR.glob("*.enote")]
        if notes:
            print(_c(Fore.CYAN, f"  Saved notes ({len(notes)}):"))
            for n in notes: print(f"    •  {n}")
        else: _warn("No notes saved.")

    elif sub == "4":
        name = input("  Note name to delete: ").strip()
        if input(f"  Delete '{name}'? [y/N]: ").lower() == "y":
            try: secure_delete(_note_p(name)); _ok("Deleted.")
            except Exception as e: _err(str(e))
    _hdr_end()

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 9 — PASSWORD SUITE
# ════════════════════════════════════════════════════════════════════════════
def _crack_time(entropy: float) -> str:
    """Estimate crack time at 10 billion guesses/sec (modern GPU cluster)."""
    guesses = 2 ** entropy
    secs    = guesses / 10e9
    if secs < 1:        return "< 1 second"
    if secs < 60:       return f"{secs:.0f} seconds"
    if secs < 3600:     return f"{secs/60:.0f} minutes"
    if secs < 86400:    return f"{secs/3600:.0f} hours"
    if secs < 31536000: return f"{secs/86400:.0f} days"
    if secs < 3.15e9:   return f"{secs/31536000:.0f} years"
    return "centuries"

def _hibp_check(password: str) -> Tuple[bool, int]:
    """k-anonymity HIBP check — only first 5 chars of SHA1 sent."""
    try:
        h   = hashlib.sha1(password.encode()).hexdigest().upper()
        pfx, sfx = h[:5], h[5:]
        r   = requests.get(f"https://api.pwnedpasswords.com/range/{pfx}",
                           timeout=8, headers={"User-Agent": rua(),
                                               "Add-Padding": "true"})
        for line in r.text.splitlines():
            hpart, _, count = line.partition(":")
            if hpart.strip() == sfx: return True, int(count)
        return False, 0
    except: return False, -1

def pw_suite() -> None:
    _hdr("Password Suite")
    print("  1. Generate password    2. Analyze password    3. HIBP breach check")
    sub = input(_c(Fore.WHITE,"  Choice > ")).strip()

    if sub == "1":
        try:    ln = int(input("  Length [20]: ").strip() or "20")
        except: ln = 20
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()-_=+[]{}|;:,.<>?"
        pw = "".join(secrets.choice(chars) for _ in range(ln))
        cs = 95  # full printable ASCII
        ent = round(ln * math.log2(cs), 1)
        print(_c(Fore.GREEN, f"\n  Password : {pw}"))
        print(f"  Entropy  : {ent} bits")
        print(f"  CrackTime: {_crack_time(ent)}  (@ 10B guesses/sec)")

    elif sub == "2":
        pw = getpass.getpass("  Password to analyze: ")
        cs = sum([
            26 if re.search(r"[a-z]",pw) else 0,
            26 if re.search(r"[A-Z]",pw) else 0,
            10 if re.search(r"[0-9]",pw) else 0,
            32 if re.search(r"[^A-Za-z0-9]",pw) else 0,
        ])
        ent = round(len(pw) * math.log2(max(cs,1)), 1)
        score = ("VERY WEAK" if len(pw)<6 or pw.lower() in {"password","123456"}
                 else "WEAK" if ent<28 else "MODERATE" if ent<50
                 else "STRONG" if ent<80 else "VERY STRONG")
        color = Fore.RED if score in ("VERY WEAK","WEAK") else Fore.YELLOW if score=="MODERATE" else Fore.GREEN
        bar = "█"*int(ent//5) + "░"*(16-int(ent//5))
        print(f"\n  Length   : {len(pw)}")
        print(f"  Entropy  : {ent} bits  [{_c(color, bar)}]")
        print(f"  Strength : {_c(color, score)}")
        print(f"  CrackTime: {_crack_time(ent)}")
        # Pattern warnings
        if re.search(r"(.)\1{2,}", pw): _warn("Repeated characters detected")
        if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde)", pw.lower()):
            _warn("Sequential pattern detected")

    elif sub == "3":
        pw = getpass.getpass("  Password to check: ")
        _info("Checking HaveIBeenPwned (k-anonymity — password never sent)…")
        breached, count = _hibp_check(pw)
        if count == -1: _warn("HIBP check failed (network error)")
        elif breached:  _err(f"BREACHED — seen {count:,} times in known leaks!")
        else:           _ok("Not found in any known breaches.")
    _hdr_end()

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 10 — HASH SUITE
# ════════════════════════════════════════════════════════════════════════════
def _hash_file(path: str, algo: str = "sha256") -> str:
    h = hashlib.new(algo.lower())
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
    return h.hexdigest()

def hash_suite() -> None:
    _hdr("Hash Suite")
    print("  1. Hash text/file    2. Crack hash (wordlist)    3. File integrity monitor")
    sub = input(_c(Fore.WHITE,"  Choice > ")).strip()

    if sub == "1":
        target = input("  Text or file path: ").strip()
        algos  = ["md5","sha1","sha256","sha512","sha3_256"]
        p = Path(target)
        if p.exists():
            for a in algos: print(f"  {a:<10}: {_hash_file(target, a)}")
        else:
            for a in algos:
                h = hashlib.new(a, target.encode()).hexdigest()
                print(f"  {a:<10}: {h}")

    elif sub == "2":
        th = input("  Target hash: ").strip()
        al = input("  Algorithm [sha256]: ").strip() or "sha256"
        wl = input("  Wordlist path: ").strip()
        if not Path(wl).exists(): _err("Wordlist not found."); return
        th = th.lower(); found = None; tried = 0
        _info("Attacking…")
        start = time.time()
        with open(wl, "r", errors="replace") as f:
            for line in f:
                w = line.rstrip("\n")
                for v in [w, w.lower(), w.upper(), w.capitalize(),
                           w+"1", w+"123", w+"!", w+"@", w+"#", "1"+w, w+"2024"]:
                    tried += 1
                    if hashlib.new(al, v.encode()).hexdigest() == th:
                        found = v; break
                if found: break
                if tried % 100_000 == 0:
                    print(_c(Fore.YELLOW, f"\r    {tried:,} tried…"), end="")
        elapsed = time.time() - start
        print()
        if found: _ok(f"CRACKED: {_c(Fore.GREEN+Style.BRIGHT, found)}  [{elapsed:.1f}s / {tried:,} tried]")
        else: _warn(f"Not found.  [{elapsed:.1f}s / {tried:,} tried]")

    elif sub == "3":
        print("  1. Index folder    2. Scan for changes")
        s2 = input("  Choice > ").strip()
        if s2 == "1":
            folder = input("  Folder path: ").strip()
            fp = Path(folder)
            if not fp.exists(): _err("Not found."); return
            db = read_json(INTEGRITY_DB, {})
            added = 0
            for file in fp.rglob("*"):
                if file.is_file():
                    db[str(file)] = {"hash": _hash_file(str(file)), "mtime": file.stat().st_mtime}
                    added += 1
            write_json(INTEGRITY_DB, db); _ok(f"Indexed {added} files.")
        elif s2 == "2":
            db = read_json(INTEGRITY_DB, {})
            alerts = []
            for fp_str, meta in db.items():
                p2 = Path(fp_str)
                if not p2.exists(): alerts.append((fp_str, "DELETED"))
                elif _hash_file(fp_str) != meta["hash"]: alerts.append((fp_str, "MODIFIED"))
            if alerts:
                for f, st in alerts:
                    ((_err if st=="DELETED" else _warn)(f"{f}: {st}"))
            else: _ok("No changes detected.")
    _hdr_end()

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 11 — JWT ANALYZER
# ════════════════════════════════════════════════════════════════════════════
def _b64url_dec(s: str) -> bytes:
    s = s.replace("-","+").replace("_","/")
    return base64.b64decode(s + "=" * ((4-len(s)%4)%4))

def jwt_analyze(token: str) -> None:
    _hdr("JWT Analyzer")
    parts = token.strip().split(".")
    if len(parts) != 3: _err("Not a valid JWT (need 3 parts)."); return
    try:
        hdr = json.loads(_b64url_dec(parts[0]))
        pay = json.loads(_b64url_dec(parts[1]))
    except Exception as e: _err(f"Decode error: {e}"); return

    print(_c(Fore.YELLOW+Style.BRIGHT, "  │  [ Header ]"))
    for k, v in hdr.items(): print(_c(Fore.CYAN,"  │  ") + f"  {k:<10}: {v}")

    print(_c(Fore.CYAN,"  │"))
    print(_c(Fore.YELLOW+Style.BRIGHT, "  │  [ Payload ]"))
    now_ts = int(time.time())
    for k, v in pay.items():
        if k in ("iat","exp","nbf") and isinstance(v, int):
            dt = datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            print(_c(Fore.CYAN,"  │  ") + f"  {k:<10}: {v}  ({dt})")
        else:
            print(_c(Fore.CYAN,"  │  ") + f"  {k:<10}: {str(v)[:120]}")

    print(_c(Fore.CYAN,"  │"))
    print(_c(Fore.YELLOW+Style.BRIGHT, "  │  [ Security Analysis ]"))
    alg = hdr.get("alg","none").upper()
    if alg == "NONE":
        print(_c(Fore.CYAN,"  │  ") + _c(Fore.RED,    "  ✖  Algorithm: none — UNSIGNED, trivially forgeable!"))
    elif alg.startswith("HS"):
        print(_c(Fore.CYAN,"  │  ") + _c(Fore.YELLOW, f"  ⚠  Algorithm: {alg} (HMAC-symmetric) — brute-forceable with weak secret"))
    else:
        print(_c(Fore.CYAN,"  │  ") + _c(Fore.GREEN,  f"  ✔  Algorithm: {alg} (asymmetric)"))

    exp = pay.get("exp")
    if exp:
        if now_ts > exp:
            print(_c(Fore.CYAN,"  │  ") + _c(Fore.RED, f"  ✖  EXPIRED  ({datetime.fromtimestamp(exp,tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')})"))
        else:
            left = exp - now_ts
            h,r  = divmod(left,3600); m,s = divmod(r,60)
            print(_c(Fore.CYAN,"  │  ") + _c(Fore.GREEN, f"  ✔  Valid for {h}h {m}m {s}s"))
    else:
        print(_c(Fore.CYAN,"  │  ") + _c(Fore.YELLOW, "  ⚠  No 'exp' claim — token never expires"))

    sens = [k for k in pay if any(x in k.lower() for x in ("pass","secret","key","token","credit","ssn","pwd"))]
    if sens:
        print(_c(Fore.CYAN,"  │  ") + _c(Fore.RED, f"  ✖  Sensitive payload fields: {', '.join(sens)}"))

    _hdr_end()

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 12 — METADATA EXTRACTOR  (EXIF + Office + file hashes)
# ════════════════════════════════════════════════════════════════════════════
def metadata_extract(path: str) -> None:
    _hdr(f"Metadata — {path}")
    p = Path(path)
    if not p.exists(): _err("File not found."); return
    st = p.stat()

    print(_c(Fore.YELLOW+Style.BRIGHT, "  │  [ File Info ]"))
    print(_c(Fore.CYAN,"  │  ") + f"  Path     : {p.resolve()}")
    print(_c(Fore.CYAN,"  │  ") + f"  Size     : {st.st_size:,} bytes")
    print(_c(Fore.CYAN,"  │  ") + f"  Created  : {ts_human(st.st_ctime)}")
    print(_c(Fore.CYAN,"  │  ") + f"  Modified : {ts_human(st.st_mtime)}")

    print(_c(Fore.CYAN,"  │"))
    print(_c(Fore.YELLOW+Style.BRIGHT, "  │  [ Hashes ]"))
    for algo in ("md5","sha1","sha256","sha512"):
        print(_c(Fore.CYAN,"  │  ") + f"  {algo:<8}: {_hash_file(path, algo)}")

    # EXIF (images)
    if PIL_AVAILABLE and p.suffix.lower() in (".jpg",".jpeg",".tiff",".tif",".png",".webp"):
        print(_c(Fore.CYAN,"  │"))
        print(_c(Fore.YELLOW+Style.BRIGHT, "  │  [ EXIF ]"))
        try:
            img  = Image.open(path)
            exif = img._getexif() if hasattr(img,"_getexif") else None
            if exif:
                for tag_id, val in exif.items():
                    tag = TAGS.get(tag_id, str(tag_id))
                    if isinstance(val, bytes): continue  # skip raw binary
                    print(_c(Fore.CYAN,"  │  ") + f"  {tag:<28}: {str(val)[:80]}")
            else: print(_c(Fore.CYAN,"  │  ") + "  No EXIF data found.")
        except Exception as e: _warn(f"EXIF read error: {e}")

    # Office/ZIP metadata (docx, xlsx, pptx are ZIP)
    if p.suffix.lower() in (".docx",".xlsx",".pptx",".odt",".ods"):
        print(_c(Fore.CYAN,"  │"))
        print(_c(Fore.YELLOW+Style.BRIGHT, "  │  [ Office Metadata ]"))
        try:
            import zipfile
            with zipfile.ZipFile(path, "r") as z:
                if "docProps/core.xml" in z.namelist():
                    xml = z.read("docProps/core.xml").decode("utf-8", errors="replace")
                    for tag in ("dc:creator","cp:lastModifiedBy","cp:revision",
                                "dcterms:created","dcterms:modified","cp:lastPrinted"):
                        m = re.search(f"<{tag}[^>]*>(.*?)</{tag}>", xml, re.DOTALL)
                        if m:
                            clean_tag = tag.split(":")[-1]
                            print(_c(Fore.CYAN,"  │  ") + f"  {clean_tag:<22}: {m.group(1).strip()}")
        except Exception as e: _warn(f"Office metadata error: {e}")

    _hdr_end()

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 13 — STEGANOGRAPHY  (LSB PNG)
# ════════════════════════════════════════════════════════════════════════════
_STEG_DELIM     = "<<5EYEND>>"                       # ASCII-only — safe for byte-by-byte LSB rebuild
_STEG_DELIM_B   = _STEG_DELIM.encode("utf-8")         # b"<<5EYEND>>"

def steg_hide(img_path: str, message: str, out: Optional[str] = None) -> str:
    if not PIL_AVAILABLE: raise RuntimeError("Install Pillow: pip install Pillow")
    img  = Image.open(img_path).convert("RGB")
    pxls = list(img.getdata())
    payload = (message + _STEG_DELIM).encode("utf-8")
    bits = "".join(format(b,"08b") for b in payload)
    if len(bits) > len(pxls)*3:
        raise ValueError(f"Image too small ({len(pxls)*3} bits available, need {len(bits)})")
    new_pxls = []; bi = 0
    for r, g, b in pxls:
        if bi < len(bits): r=(r&~1)|int(bits[bi]); bi+=1
        if bi < len(bits): g=(g&~1)|int(bits[bi]); bi+=1
        if bi < len(bits): b=(b&~1)|int(bits[bi]); bi+=1
        new_pxls.append((r,g,b))
    dest = out or str(STEG_DIR / f"steg_{int(time.time())}.png")
    ni = Image.new("RGB", img.size); ni.putdata(new_pxls); ni.save(dest, "PNG")
    return dest

def steg_extract(img_path: str) -> str:
    if not PIL_AVAILABLE: raise RuntimeError("Install Pillow: pip install Pillow")
    img  = Image.open(img_path).convert("RGB")
    bits = []
    for r,g,b in img.getdata(): bits.extend([str(r&1),str(g&1),str(b&1)])
    # Collect raw bytes, then UTF-8 decode — handles multi-byte chars (emoji, etc.) correctly
    raw = bytearray()
    dlen = len(_STEG_DELIM_B)
    for i in range(0, len(bits)-7, 8):
        raw.append(int("".join(bits[i:i+8]), 2))
        if len(raw) >= dlen and raw[-dlen:] == _STEG_DELIM_B:
            try:
                return raw[:-dlen].decode("utf-8")
            except UnicodeDecodeError:
                return raw[:-dlen].decode("latin-1")
    return "No hidden message found."

def steg_menu() -> None:
    _hdr("Steganography — LSB (PNG)")
    print("  1. Hide message    2. Extract message")
    sub = input(_c(Fore.WHITE,"  Choice > ")).strip()
    if sub == "1":
        img = input("  Input PNG path: ").strip()
        msg = input("  Secret message: ")
        out = input("  Output path [auto]: ").strip() or None
        try:
            saved = steg_hide(img, msg, out)
            _ok(f"Stego image saved: {saved}"); log("STEG_HIDE","ok")
        except Exception as e: _err(str(e))
    elif sub == "2":
        img = input("  Stego PNG path: ").strip()
        try:
            msg = steg_extract(img)
            print(_c(Fore.GREEN,"\n  Extracted: ") + msg); log("STEG_EXTRACT","ok")
        except Exception as e: _err(str(e))
    _hdr_end()

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 14 — ENCODE / DECODE CENTER  (with auto-detection)
# ════════════════════════════════════════════════════════════════════════════
def _detect_encoding(text: str) -> str:
    """Heuristic auto-detect what encoding a string might be."""
    t = text.strip()
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", t) and len(t) % 4 == 0:
        try: base64.b64decode(t); return "base64"
        except: pass
    if re.fullmatch(r"[01 ]+", t) and all(len(b)==8 for b in t.split()):
        return "binary"
    if re.fullmatch(r"[0-9a-fA-F]+", t.replace(" ","")) and len(t.replace(" ","")) % 2 == 0:
        return "hex"
    if re.fullmatch(r"[\.\- /]+", t):
        return "morse"
    if re.fullmatch(r"[A-Za-z0-9\+\/=\n]+", t):
        return "base64 (possible)"
    return "unknown"

def _rot13(t):
    return t.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))

def _rot47(t):
    return "".join(chr(33+((ord(c)-33+47)%94)) if 33<=ord(c)<=126 else c for c in t)

def _caesar(t, s, decode=False):
    if decode: s = -s
    s %= 26
    return "".join(
        chr((ord(c)-65+s)%26+65) if c.isupper() else
        chr((ord(c)-97+s)%26+97) if c.islower() else c for c in t)

_MORSE_ENC = {
    'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---',
    'K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-',
    'U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',
    '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....',
    '6':'-....','7':'--...','8':'---..','9':'-  ---.',' ':'/'
}
_MORSE_DEC = {v:k for k,v in _MORSE_ENC.items()}

def encode_decode_center() -> None:
    _hdr("Encode / Decode Center")
    text = input("  Input text: ")
    detected = _detect_encoding(text)
    print(_c(Fore.YELLOW, f"  Auto-detected format: {detected}\n"))

    print("  ENCODE: [e1]Base64  [e2]Hex  [e3]Binary  [e4]ROT13  [e5]ROT47  [e6]Caesar  [e7]Morse")
    print("  DECODE: [d1]Base64  [d2]Hex  [d3]Binary  [d4]ROT13  [d5]ROT47  [d6]Caesar  [d7]Morse")
    choice = input(_c(Fore.WHITE,"  Choice > ")).strip().lower()

    result = None
    try:
        if   choice == "e1": result = base64.b64encode(text.encode()).decode()
        elif choice == "d1":
            pad = "="*((4-len(text)%4)%4)
            result = base64.b64decode(text+pad).decode("utf-8",errors="replace")
        elif choice == "e2": result = text.encode().hex()
        elif choice == "d2": result = bytes.fromhex(text.replace(" ","")).decode("utf-8",errors="replace")
        elif choice == "e3": result = " ".join(format(b,"08b") for b in text.encode())
        elif choice == "d3":
            b = text.replace(" ","")
            result = bytes(int(b[i:i+8],2) for i in range(0,len(b),8)).decode("utf-8",errors="replace")
        elif choice == "e4": result = _rot13(text)
        elif choice == "d4": result = _rot13(text)
        elif choice == "e5": result = _rot47(text)
        elif choice == "d5": result = _rot47(text)
        elif choice == "e6":
            try: sh = int(input("  Shift: "))
            except: sh = 13
            result = _caesar(text, sh)
        elif choice == "d6":
            try: sh = int(input("  Shift: "))
            except: sh = 13
            result = _caesar(text, sh, decode=True)
        elif choice == "e7":
            result = "   ".join(" ".join(_MORSE_ENC.get(c,"<?>") for c in w) for w in text.upper().split())
        elif choice == "d7":
            result = " ".join("".join(_MORSE_DEC.get(s,"?") for s in w.split()) for w in text.strip().split("   "))
        else: _err("Unknown choice")
    except Exception as e: _err(f"Error: {e}")

    if result is not None:
        print(_c(Fore.GREEN, "\n  Result:"))
        # Wrap long results
        for chunk in textwrap.wrap(result, width=72):
            print(f"  {chunk}")

    _hdr_end()

# ════════════════════════════════════════════════════════════════════════════
#  MODULE 15 — TOR / PROXY CHECKER
# ════════════════════════════════════════════════════════════════════════════
def tor_proxy_check() -> None:
    _hdr("Tor / Proxy Anonymity Checker")
    _info("Fetching public IP…")
    try:
        r   = requests.get("https://api64.ipify.org?format=json",
                           timeout=8, headers={"User-Agent": rua()})
        ip  = r.json().get("ip","?")
    except Exception as e: _err(f"Can't fetch IP: {e}"); return

    geo = _geoip(ip)
    print(_c(Fore.CYAN,"  │  ") + f"  Public IP  : {_c(Fore.WHITE+Style.BRIGHT, ip)}")
    if geo.get("status") == "success":
        for k, label in [("country","Country"),("isp","ISP"),("org","Org"),("as","ASN")]:
            v = geo.get(k,"")
            if v: print(_c(Fore.CYAN,"  │  ") + f"  {label:<11}: {v}")

    # Tor exit-node list check
    _info("Checking Tor exit-node list…")
    is_tor = False
    try:
        r2 = requests.get("https://check.torproject.org/torbulkexitlist",
                          timeout=12, headers={"User-Agent": rua()})
        is_tor = ip in r2.text
    except: _warn("Could not reach torproject.org")
    label = _c(Fore.GREEN,"YES — Tor exit node") if is_tor else _c(Fore.WHITE,"No")
    print(_c(Fore.CYAN,"  │  ") + f"  Tor Exit?  : {label}")

    # Proxy header leak
    _info("Checking for proxy header leaks via httpbin.org…")
    try:
        r3  = requests.get("https://httpbin.org/get",timeout=10,headers={"User-Agent":rua()})
        hdrs = r3.json().get("headers",{})
        proxy_hdrs = {k:v for k,v in hdrs.items()
                      if any(x in k.lower() for x in ("forward","proxy","via","real-ip","client-ip"))}
        if proxy_hdrs:
            _warn("Proxy headers detected — anonymity compromised!")
            for k,v in proxy_hdrs.items():
                print(_c(Fore.CYAN,"  │  ") + f"    {k}: {v}")
        else:
            _ok("No proxy headers detected")
    except: _warn("Could not reach httpbin.org")

    # Score
    score = (2 if is_tor else 0)
    print()
    label = ("🟢 HIGH" if score >= 2 else "🟡 MEDIUM" if score == 1 else "🔴 LOW")
    print(_c(Fore.CYAN,"  │  ") + f"  Anonymity Score: {_c(Fore.WHITE+Style.BRIGHT, label)}")
    _hdr_end(); log("TOR_CHECK", f"ip={ip}")

# ════════════════════════════════════════════════════════════════════════════
#  PANIC WIPE  (logs + integrity DB only — quick clear)
# ════════════════════════════════════════════════════════════════════════════
def panic_wipe() -> None:
    clr()
    print(_c(Fore.RED+Style.BRIGHT, "  !! PANIC WIPE — CLEARING OPERATIONAL DATA !!"))
    for f in [LOG_FILE, INTEGRITY_DB]:
        try:
            if f.exists(): secure_delete(f); print(f"  Wiped: {f}")
        except: pass
    log("PANIC","triggered"); raise SystemExit(0)

# ════════════════════════════════════════════════════════════════════════════
#  NUCLEAR WIPE  (full self-destruct: vault + config + stored data)
# ════════════════════════════════════════════════════════════════════════════
def nuclear_wipe(master_pw: str) -> None:
    """
    Completely destroy all 5EYES stored data:
      - All vault files (notes, exports, steg, keys, qr)
      - Config file (master password hash + passphrase hash)
      - Logs and integrity database
      - Vault directory itself
    After this the tool starts fresh on next run (new password + passphrase).
    """
    clr()
    _sep(color=Fore.RED)
    print(_c(Fore.RED+Style.BRIGHT, "  !! NUCLEAR WIPE — COMPLETE SELF-DESTRUCT !!"))
    _sep(color=Fore.RED)
    print(_c(Fore.YELLOW, "\n  This will PERMANENTLY destroy:"))
    print(_c(Fore.WHITE, f"    • All secure notes  ({NOTES_DIR})"))
    print(_c(Fore.WHITE, f"    • All exports        ({EXPORT_DIR})"))
    print(_c(Fore.WHITE, f"    • All steg images    ({STEG_DIR})"))
    print(_c(Fore.WHITE, f"    • Master password hash + recovery passphrase"))
    print(_c(Fore.WHITE, f"    • Logs and integrity database"))
    print(_c(Fore.WHITE, f"    • Entire vault dir   ({VAULT_DIR})"))
    print(_c(Fore.RED+Style.BRIGHT,
          "\n  !! This action is IRREVERSIBLE. All encrypted data will be unrecoverable. !!\n"))

    # Confirmation step 1 — type phrase
    print(_c(Fore.YELLOW, '  Type exactly:  NUKE EVERYTHING  to confirm:'))
    confirm = input("  > ").strip()
    if confirm != "NUKE EVERYTHING":
        _warn("Aborted — confirmation text did not match."); return

    # Confirmation step 2 — master password
    print(_c(Fore.YELLOW, "\n  Enter master password to authorize:"))
    cfg  = read_json(CFG_FILE, {})
    salt = base64.b64decode(cfg.get("master_salt", base64.b64encode(b'\x00'*32).decode()))
    pw   = getpass.getpass("  Password: ")
    if not secrets.compare_digest(_master_hash(pw, salt), cfg.get("master_hash", "")):
        _err("Wrong password — nuclear wipe ABORTED."); log("NUKE_ABORT","wrong pw"); return

    print()
    print(_c(Fore.RED+Style.BRIGHT, "  ■ AUTHORIZED — Beginning nuclear wipe…\n"))
    wiped_files = 0; wiped_dirs  = 0

    def _wipe_file(p: Path) -> None:
        nonlocal wiped_files
        try:
            secure_delete(p)
            print(_c(Fore.RED, f"  ✖  WIPED  ") + str(p))
            wiped_files += 1
        except Exception as e:
            print(_c(Fore.YELLOW, f"  ⚠  Could not wipe {p}: {e}"))

    def _wipe_dir(d: Path) -> None:
        """Recursively wipe all files then remove directory."""
        nonlocal wiped_dirs
        if not d.exists(): return
        for item in d.rglob("*"):
            if item.is_file(): _wipe_file(item)
        # Remove empty dirs bottom-up
        for item in sorted(d.rglob("*"), reverse=True):
            if item.is_dir():
                try: item.rmdir(); wiped_dirs += 1
                except: pass
        try: d.rmdir(); wiped_dirs += 1
        except: pass

    import time as _time
    # Wipe all subdirectories
    for sub in [NOTES_DIR, EXPORT_DIR, STEG_DIR,
                VAULT_DIR / "keys", VAULT_DIR / "qr"]:
        _wipe_dir(sub)

    # Wipe top-level files in vault
    for f in [LOG_FILE, INTEGRITY_DB, CFG_FILE]:
        if f.exists(): _wipe_file(f)

    # Wipe vault dir itself
    try: VAULT_DIR.rmdir(); wiped_dirs += 1
    except: pass

    _time.sleep(0.3)
    print()
    _sep(color=Fore.RED)
    print(_c(Fore.RED+Style.BRIGHT,
          f"  NUCLEAR WIPE COMPLETE — {wiped_files} file(s), {wiped_dirs} dir(s) destroyed"))
    print(_c(Fore.YELLOW,
          "  All stored data has been securely overwritten and removed."))
    print(_c(Fore.GREEN,
          "  Next launch: fresh setup with new password + passphrase."))
    _sep(color=Fore.RED)
    log("NUKE", f"files={wiped_files} dirs={wiped_dirs}")
    print()
    raise SystemExit(0)

# ════════════════════════════════════════════════════════════════════════════
#  CHANGE MASTER PASSWORD  (requires current password)
# ════════════════════════════════════════════════════════════════════════════
def change_password(master_pw: str) -> str:
    """Change master password. Generates a fresh recovery passphrase automatically."""
    _hdr("Change Master Password")
    cfg = read_json(CFG_FILE, {})

    # Verify current password
    salt = base64.b64decode(cfg.get("master_salt", ""))
    print(_c(Fore.YELLOW, "  │  Verify current password first:"))
    for attempt in range(1, 4):
        cur = getpass.getpass("  │  Current password: ")
        if secrets.compare_digest(_master_hash(cur, salt), cfg.get("master_hash","")):
            break
        left = 3 - attempt
        _err(f"Wrong password.{f'  {left} try left.' if left else ''}")
    else:
        _err("Too many wrong attempts."); _hdr_end(); return master_pw

    # New password
    print(_c(Fore.CYAN, "\n  │  Set new password:"))
    while True:
        p1 = getpass.getpass("  │  New password (min 8 chars): ")
        p2 = getpass.getpass("  │  Confirm:                    ")
        if p1 != p2:    _err("Do not match."); continue
        if len(p1) < 8: _err("Too short."); continue
        break

    # New salts + new passphrase
    new_phrase = _gen_passphrase()
    new_p_salt = get_random_bytes(32)
    new_m_salt = get_random_bytes(32)

    cfg["master_hash"] = _master_hash(p1, new_m_salt)
    cfg["master_salt"] = base64.b64encode(new_m_salt).decode()
    cfg["phrase_hash"] = _phrase_hash(new_phrase, new_p_salt)
    cfg["phrase_salt"] = base64.b64encode(new_p_salt).decode()
    cfg["changed_at"]  = utcnow()
    write_json(CFG_FILE, cfg)

    _show_passphrase(new_phrase)
    _ok("Master password changed! New recovery passphrase shown above.")
    log("PW_CHANGE", "ok")
    pause("  Press Enter after saving your new passphrase safely…")
    _hdr_end()
    return p1
# ════════════════════════════════════════════════════════════════════════════
#  STEALTH CALCULATOR
# ════════════════════════════════════════════════════════════════════════════
_OPS_FN = {
    ast.Add:operator.add, ast.Sub:operator.sub, ast.Mult:operator.mul,
    ast.Div:operator.truediv, ast.FloorDiv:operator.floordiv,
    ast.Mod:operator.mod, ast.Pow:operator.pow, ast.USub:operator.neg,
}
def _safe_eval(expr: str) -> float:
    def _ev(n):
        if isinstance(n, ast.Constant) and isinstance(n.value,(int,float)): return n.value
        if isinstance(n, ast.BinOp):
            fn = _OPS_FN.get(type(n.op))
            if not fn: raise ValueError
            return fn(_ev(n.left), _ev(n.right))
        if isinstance(n, ast.UnaryOp):
            fn = _OPS_FN.get(type(n.op))
            if not fn: raise ValueError
            return fn(_ev(n.operand))
        raise ValueError
    return _ev(ast.parse(expr, mode="eval").body)

def stealth_calc() -> bool:
    clr()
    print(_c(Back.BLUE + Fore.WHITE, "  MathHelper v2.1 — free calculator"))
    print("  Type :unlock to exit stealth mode\n")
    while True:
        try:
            cmd = input(">>> ").strip()
            if cmd.lower() in (":unlock",":unlock opensesame"): return True
            if cmd.lower() in ("exit","quit","q"): return False
            if cmd:
                try:
                    r = _safe_eval(cmd)
                    print(int(r) if isinstance(r,float) and r.is_integer() else r)
                except: print("Error: invalid expression")
        except (KeyboardInterrupt, EOFError): return False

# ════════════════════════════════════════════════════════════════════════════
#  HELP
# ════════════════════════════════════════════════════════════════════════════
def show_help() -> None:
    clr()
    _box("5EYES TOOLKIT v1.0 — HELP")
    entries = [
        (" 1","IP / Domain Recon",   "WHOIS · GeoIP · ASN · reverse DNS · full DNS record set"),
        (" 2","Subdomain Enum",       "DNS brute (built-in 160-word list) + crt.sh CT logs + permutations"),
        (" 3","Username OSINT",       "20 platforms, parallel checks, presence confidence score, CSV export"),
        (" 4","Email Header Analyzer","Hop tracing, SPF/DKIM/DMARC results, FROM≠REPLY-TO phishing flag"),
        (" 5","Port Scanner",         "Threaded TCP, banner grab, CVE hints for common services"),
        (" 6","AES-256 Vault",        "Encrypt/decrypt text blobs with AES-256-GCM"),
        (" 7","File Encrypt/Decrypt", "AES-256-GCM file encryption, password never stored"),
        (" 8","Secure Notes",         "Per-note AES-GCM encrypted notes, stored in vault"),
        (" 9","Password Suite",       "Generate · strength analysis · HIBP k-anonymity breach check"),
        ("10","Hash Suite",           "Multi-algo hashing · wordlist cracker · file integrity monitor"),
        ("11","JWT Analyzer",         "Decode · alg audit · expiry check · sensitive claim scan"),
        ("12","Metadata Extractor",   "File info · EXIF (images) · Office author metadata · multi-hash"),
        ("13","Steganography",        "LSB hide/extract text in PNG images"),
        ("14","Encode/Decode Center", "Auto-detect + B64/Hex/Binary/ROT13/ROT47/Caesar/Morse"),
        ("15","Tor/Proxy Checker",    "Public IP · GeoIP · Tor exit-node · proxy header leak · score"),
        (" p","Panic Wipe",           "Wipe logs + integrity DB only, then exit immediately"),
        (" n","Nuclear Wipe",          "FULL self-destruct — vault + config + all files wiped"),
        (" c","Change Password",       "Change master password + auto-generate new passphrase"),
        (" s","Stealth Mode",          "Disguise as MathHelper calculator  (:unlock to return)"),
        (" f","Forgot Password",       "Type f at login screen to reset via recovery passphrase"),
    ]
    for num, name, desc in entries:
        print(f"  {_c(Fore.GREEN, f'[{num}]')}  {_c(Fore.WHITE+Style.BRIGHT, f'{name:<24}')}"
              f"  {_c(Fore.CYAN, desc)}")
    print()
    print(_c(Fore.YELLOW, "  Dependencies:"))
    print("    Required : pycryptodome  requests  colorama")
    print("    Optional : Pillow (EXIF+steg)  qrcode  dnspython (richer DNS)")
    print()
    print(_c(Fore.YELLOW, "  Install all:"))
    print("    pip install pycryptodome requests colorama Pillow dnspython")

# ════════════════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════════════════
def main() -> None:
    master_pw = auth()
    log("START", f"v1.0 device={sha256h(platform.node().encode())[:12]}")

    while True:
        try:
            dashboard()
            choice = input(_c(Fore.WHITE + Style.BRIGHT, "\n  ❯  ")).strip().lower()

            if   choice == "q":
                print(_c(Fore.GREEN,"\n  Session ended. Stay safe.")); log("QUIT","ok"); break
            elif choice == "p":  panic_wipe()
            elif choice == "n":  nuclear_wipe(master_pw)
            elif choice == "c":
                new_pw = change_password(master_pw)
                if new_pw: master_pw = new_pw
            elif choice == "s":
                if stealth_calc(): continue
            elif choice == "h":  show_help(); pause()

            elif choice == "1":
                t = input(_c(Fore.WHITE,"  IP or domain: ")).strip()
                if t: ip_recon(t)
                pause()

            elif choice == "2":
                domain = input(_c(Fore.WHITE,"  Target domain: ")).strip()
                if not domain: continue
                use_crt = input("  Use crt.sh Certificate Transparency? [Y/n]: ").strip().lower() != "n"
                use_custom = input("  Custom wordlist? path or Enter to skip: ").strip()
                wl = None
                if use_custom:
                    try:
                        with open(use_custom,"r",errors="replace") as f:
                            wl = [l.strip() for l in f if l.strip()]
                        _ok(f"Loaded {len(wl)} words")
                    except Exception as e: _err(str(e)); pause(); continue
                res = subdomain_enum(domain, wl, use_crtsh=use_crt)
                _info(f"Total: {len(res)} subdomain(s) discovered")
                pause()

            elif choice == "3":
                u = input(_c(Fore.WHITE,"  Username: ")).strip()
                if u: username_osint(u)
                pause()

            elif choice == "4":
                print("  Paste raw email headers. Enter a blank line twice to finish:")
                lines, prev = [], ""
                while True:
                    try:
                        l = input()
                        if l == "" and prev == "": break
                        lines.append(l); prev = l
                    except EOFError: break
                raw = "\n".join(lines)
                if raw.strip(): email_header_analyze(raw)
                else: _warn("No input.")
                pause()

            elif choice == "5":
                host  = input(_c(Fore.WHITE,"  Target host/IP: ")).strip()
                pspec = input("  Ports (e.g. 1-1024, 22,80,443) or Enter for top-40: ").strip()
                try:    to = float(input("  Timeout [1.0]: ").strip() or "1.0")
                except: to = 1.0
                ports = parse_ports(pspec) if pspec else sorted(_SVC.keys())
                results = port_scan(host, ports, timeout=to)
                _info(f"{len(results)} open port(s)"); pause()

            elif choice == "6":  vault_text(master_pw)
            elif choice == "7":  file_enc_dec()
            elif choice == "8":  notes_menu(master_pw)
            elif choice == "9":  pw_suite(); pause()
            elif choice == "10": hash_suite(); pause()

            elif choice == "11":
                t = input(_c(Fore.WHITE,"  JWT token: ")).strip()
                if t: jwt_analyze(t)
                pause()

            elif choice == "12":
                p = input(_c(Fore.WHITE,"  File path: ")).strip()
                if p: metadata_extract(p)
                pause()

            elif choice == "13": steg_menu(); pause()
            elif choice == "14": encode_decode_center(); pause()
            elif choice == "15": tor_proxy_check(); pause()

            else:
                _err("Invalid choice — enter 1-15, or: q=quit  p=panic  n=NUKE  c=change-pw  h=help  s=stealth")
                pause()

        except KeyboardInterrupt:
            print(_c(Fore.RED,"\n  Ctrl+C — panic wipe triggered")); panic_wipe()
        except Exception as e:
            log("ERROR", str(e))
            _err(f"Unexpected error: {e}"); pause()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        panic_wipe()
    except Exception as e:
        log("CRASH", str(e))
        print(_c(Fore.RED, f"Fatal: {e}")); sys.exit(1)
