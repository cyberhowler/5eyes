# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active |


## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Use GitHub's private **Security Advisory** system:
> Repo → Security tab → Report a vulnerability

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

Response time: within 72 hours.

## Scope

In scope:
- AES encryption / key derivation implementation
- Master password or passphrase storage / verification
- Vault file exposure or information leakage
- Safe-eval injection bypass
- Nuclear / panic wipe bypass

Out of scope:
- Attacks requiring physical access to an unlocked session
- Third-party API reliability (HIBP, ip-api, crt.sh)
- Wordlist quality for hash cracking
