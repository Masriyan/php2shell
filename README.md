# PHP2Shell

> Research & assessment tool for **CVE-2026-109618** and **CVE-2026-109619** ("PHP2Shell").

A single-file Python tool that fingerprints a target, verifies the confirmed
`session.upload_progress` **session-file poisoning** primitive, and produces a
coarse exposure verdict — **without** shipping a weaponized RCE exploit.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](#disclaimer)
[![Status](https://img.shields.io/badge/Status-Research-orange.svg)](#disclaimer)

---

## ⚠️ Disclaimer

This tool is provided for **authorized security research and assessment only**.

- Run it **only** against systems you own or have **explicit written authorization** to test.
- It **verifies an observable primitive and assesses exposure** — it does **not**
  perform code execution against any target.
- The author assumes **no liability** for misuse or unauthorized testing.

> **Not for public release** — this repository is a private/internal research
> artifact shared for review purposes.

---

## What this is (and isn't)

### It IS

- ✅ A **CMS fingerprinting** tool (11 CMS + generic PHP fallback)
- ✅ A **PHP version / type / support-status** detector
- ✅ A **verifier** of the confirmed `session.upload_progress` poisoning primitive
  (P1 + P2), using an **inert canary** (a PHP comment — never a shell)
- ✅ An **exposure assessor** that combines primitive observation with PHP
  branch support status

### It is NOT

- ❌ A weaponized RCE exploit
- ❌ A PHP object-deserialization gadget chain
- ❌ A guarantee of code execution

---

## Background

PHP2Shell refers to the developing disclosure around two PHP-core remote code
execution bugs. As of the advisory window (Oct 2026), the **only technically
documented primitive** is **session-file poisoning** via the
`session.upload_progress` feature:

| Primitive | Description |
|-----------|-------------|
| **P1** | Set a session ID *cookie-lessly* via a `PHPSESSID` field in the multipart body. |
| **P2** | Inject arbitrary content (e.g. `<?php ...`) into the session file via the `PHP_SESSION_UPLOAD_PROGRESS` field value and the uploaded filename, which PHP serializes verbatim into `sess_<id>`. |

Injected content only becomes **code execution** when the target application
performs an `include()` / `require()` on the poisoned session file. Stock
WordPress / Joomla / Drupal do **not** hand you that sink.

> **Important:** the official affected/fixed versions were **still unpublished**
> at the time of writing (NVD returns 0 results for both CVEs). No verified
> public PoC for the RCE exists — only the poisoning primitive is public.

For deeper background, see [`docs/RESEARCH.md`](docs/RESEARCH.md).

---

## Features

- 🎯 **Interactive + CLI** target input (`--url`, or prompt)
- 🧭 **11 CMS fingerprints** — WordPress, Joomla, Drupal, Magento, Laravel,
  CodeIgniter, Symfony, phpBB, PrestaShop, OpenCart, Typo3 (+ generic PHP)
- 🐘 **PHP version / type / support-status** detection (active / security / EOL)
- 🧪 **Inert** poisoning-primitive probe (P1 + P2, canary = PHP comment)
- 📊 **Coarse exposure verdict** (Likely affected → Unreachable)
- 🔗 **Per-CMS** candidate `include()`/LFI sink scan (`--sink-scan`)

---

## Requirements

- Python **3.8+**
- [`requests`](https://pypi.org/project/requests/)

```bash
pip install requests
```

---

## Usage

```bash
python3 php2shell.py --url https://example.com
```

### Full options

```
usage: php2shell.py [-h] [--url URL] [--probe-path PROBE_PATH]
                    [--sink-scan] [--no-confirm]

options:
  -h, --help            show this help message and exit
  --url, -u URL         Target URL (e.g. https://example.com)
  --probe-path PATH     Path for the upload-progress probe (default: /index.php)
  --sink-scan           Also probe for candidate include()/LFI sinks
  --no-confirm          Skip confirmation prompt before sending the probe
```

### Examples

```bash
# Detection only (answer 'n' at the confirmation prompt)
python3 php2shell.py --url https://example.com

# Full run including sink scan, no interactive prompt
python3 php2shell.py -u https://example.com --sink-scan --no-confirm

# Custom probe path (e.g. WordPress backend)
python3 php2shell.py -u https://example.com --probe-path /wp-login.php
```

---

## How it works

See the module docstring (top of `php2shell.py`) or [`docs/HOW_IT_WORKS.md`](docs/HOW_IT_WORKS.md)
for a step-by-step breakdown of the 7-phase flow.

---

## Repository layout

```
.
├── README.md
├── php2shell.py          # main tool (single file)
├── docs/
│   ├── RESEARCH.md       # research findings & source summary
│   ├── HOW_IT_WORKS.md   # step-by-step technical breakdown
│   └── SECURITY.md       # responsible-use / security notes
└── LICENSE               # (optional) license terms
```

---

## Author

- **sudo3rs (Mas Rian)**
- GitHub: [github.com/masriyan/php2shell](https://github.com/masriyan/php2shell)
- LinkedIn: [linkedin.com/in/sudo3rs](https://www.linkedin.com/in/sudo3rs/)

---

## References

- [Sansec — Critical PHP RCE](https://sansec.io/research/php2shell)
- [Huntress — PHP2Shell: Leaked critical PHP vulnerabilities](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities)
- [watchTowr — PHP RCE FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [PentestIT — What we know about php2shell](https://pentestit.com/php-cve-2026-109618-and-cve-2026-109619-what-we-know-about-php2shell/)
- [syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection)
- [mikensec/php2shell-lab](https://github.com/mikensec/php2shell-lab)
