# PHP2Shell

> Research & assessment tool for **CVE-2026-109618** and **CVE-2026-109619** ("PHP2Shell").

A single-file, **stdlib-only** Python tool that fingerprints a target's **PHP
version** and **CMS/platform**, correlates the two CVEs with **live threat
intel** (CISA KEV + FIRST EPSS), and produces a coarse exposure verdict —
**without** shipping, or even attempting, any code-execution payload.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/deps-stdlib%20only-success.svg)](#requirements)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](#disclaimer)
[![Status](https://img.shields.io/badge/Status-Research-orange.svg)](#disclaimer)

---

## ⚠️ Disclaimer

This tool is provided for **authorized security research and assessment only**.

- Run it **only** against systems you own or have **explicit written authorization** to test.
- It **fingerprints and assesses exposure** — it does **not** perform code
  execution, send exploit payloads, poison sessions, or write files on any target.
- The author assumes **no liability** for misuse or unauthorized testing.

---

## Why this is detection-only

Both CVEs are **internal PHP memory-safety bugs**:

| CVE | Class | Advisory |
|-----|-------|----------|
| **CVE-2026-109618** | Out-of-memory handling corrupts partially-initialized request data | GHSA-w8hw-w9fx-j79w |
| **CVE-2026-109619** | Use-after-free: request state outlives freed memory, reused by a later request on the same worker | GHSA-6wmf-4rv5-p3rp |

Both are rated **CVSS v4.0 9.2 (critical)**. There is **no safe, reliable
boolean "trigger"** for them: a genuine attempt to drive the UAF/OOM condition
tends to crash the worker and amounts to weaponization. So this tool determines
exposure the responsible way — by **fingerprinting the reported PHP version and
configuration** and comparing against the vendor's fixed releases.

### Affected / fixed versions

- **Vulnerable:** PHP **5.4 through 8.5.11**
- **Fixed builds:** **8.5.12 · 8.4.27 · 8.3.36 · 8.2.35**
- **EOL branches (≤ 8.1):** vulnerable, **no official fix** — upgrade to a
  supported branch; interim mitigation: `session.upload_progress.enabled=0` +
  restart all PHP workers (not a complete fix).

---

## What it is (and isn't)

### It IS

- ✅ A **PHP version detector** (from `Server` / `X-Powered-By`, and — in active
  mode — PHP's version-disclosure "egg"), with a heuristic "PHP present but
  version hidden" signal.
- ✅ A **CMS/platform fingerprinter** (10 built-ins + overridable via JSON).
- ✅ A **version-based exposure assessor** (`vulnerable` / `patched` / `unknown`).
- ✅ A **threat-intel correlator** — live CISA KEV presence + FIRST EPSS scores.
- ✅ A **scanner**: concurrent, proxy-aware, multiple output formats.

### It is NOT

- ❌ A weaponized RCE exploit or PoC.
- ❌ A session-poisoning / `session.upload_progress` primitive prober.
- ❌ A deserialization gadget chain, LFI sink scanner, or file writer.
- ❌ A guarantee of exploitability — a version match is *exposure*, not proof.

---

## Requirements

- Python **3.10+** (uses structural `match` and `X | None` typing)
- **No third-party dependencies** — standard library only.

---

## Usage

```bash
python3 script_test.py https://target.example
```

The tool prints a banner + colored table to the terminal, and a one-line
threat-intel summary. Colors, banner, and the live progress indicator are
automatically disabled when output is piped or when `--format json|csv`.

### Options

```
positional arguments:
  urls                        target URLs

options:
  -h, --help                  show this help message and exit
  -i, --input FILE            file with one URL per line ('-' for stdin)
  --no-safe-mode              active recon: version-disclosure egg + CMS marker
                              paths (non-destructive)
  --workers N                 concurrent workers (default 10)
  --scheme {https,http,both}  scheme to assume for bare hosts (default https)
  --timeout SECONDS           per-request timeout (default 15)
  --retries N                 transport-error retries (default 2)
  --insecure                  skip TLS certificate verification
  --proxy URL                 proxy URL, e.g. http://127.0.0.1:8080 (Burp/mitmproxy)
  -H, --header "NAME: VALUE"  extra request header (repeatable)
  --user-agent UA             override the User-Agent
  --signatures FILE           external CMS signature JSON instead of built-ins
  --no-intel                  skip live CISA KEV / EPSS correlation
  --fail-on {never,vulnerable,unknown,error}
                              exit nonzero at this severity or worse (default vulnerable)
  --format {table,json,csv,md}
  --out FILE                  write output to a file
  --log FILE                  also write timestamped logs to this file
  --no-color                  disable ANSI colors
  --no-banner                 suppress the startup banner
  -v, --verbose
```

### Scan modes

> **Neither mode performs code execution or sends an exploit payload.** The
> difference is only how the PHP version and CMS are discovered.

| Mode | Flag | Behaviour |
|------|------|-----------|
| **safe** (default) | *(none)* | **Passive.** Reads the PHP version and CMS only from response headers and the landing-page HTML. One request per target (plus scheme fallback). |
| **active** | `--no-safe-mode` | Adds **non-destructive recon**: PHP's version-disclosure "egg" query (recovers the version even when `expose_php` is off) and a few well-known CMS marker paths (e.g. `/readme.html`, `/CHANGELOG.txt`). Still read-only. |

### Exposure verdicts

| Status | Meaning |
|--------|---------|
| `vulnerable` | Detected PHP version is below the fixed build for its branch, or on an EOL branch. |
| `patched` | Detected version ≥ the fixed build for its branch. |
| `unknown` | Version could not be determined (often PHP present but banner hidden), or outside the tracked range. |
| `error` | Target unreachable (DNS/TLS/timeout after retries). |

**Exit codes:** `0` clean · `1` a result met `--fail-on` severity (default
`vulnerable`) · `2` usage error.

### Examples

```bash
# Single target, table + live KEV/EPSS intel
python3 script_test.py https://example.com

# Concurrent scan from a file, active recon
python3 script_test.py --no-safe-mode --workers 20 -i urls.txt

# Through Burp, with a session cookie, machine-readable JSON
python3 script_test.py https://example.com \
    --proxy http://127.0.0.1:8080 -H "Cookie: SESS=..." --format json

# Obsidian-ready Markdown report (YAML frontmatter + tags)
python3 script_test.py -i urls.txt --format md --out report.md

# CSV for spreadsheets; try HTTP as well as HTTPS; fail CI on 'unknown' too
python3 script_test.py -i urls.txt --format csv --scheme both --fail-on unknown
```

---

## Output formats

- **table** — colored terminal table with an intel banner (default).
- **json** — `{ "results": [...], "intel": {...} }`, one object per target with
  full evidence (`evidence`, `final_url`, `checked_at`, `php_detected`, …).
- **csv** — flat rows for spreadsheets / data pipelines.
- **md** — Markdown with YAML frontmatter and `#threat-intel` tags, ready to drop
  into an Obsidian vault.

---

## Threat intel correlation

On each run (unless `--no-intel`) the tool fetches:

- **CISA KEV** — whether CVE-2026-109618/109619 are in the Known Exploited
  Vulnerabilities catalog yet (cached locally for 6h at `~/.cache/php2shell/`).
- **FIRST EPSS** — current exploitation-probability scores for both CVEs.

These appear as an `Intel —` banner (table/md) or an `intel` object (json).

---

## Custom CMS signatures

Override the built-in fingerprints with `--signatures file.json`:

```json
[
  {
    "name": "CustomCMS",
    "html_patterns": ["X-Custom-Thing", "powered by customcms ?(\\d[\\d.]*)"],
    "active_paths": ["/custom/version.txt"],
    "version_pattern": "customcms ?(\\d[\\d.]*)"
  }
]
```

Built-in CMS fingerprints (10): **WordPress, Joomla, Drupal, Magento, TYPO3,
PrestaShop, Laravel, phpBB, MediaWiki, Plesk** — plus a generic "PHP present"
heuristic (via `PHPSESSID` cookie, `X-Powered-By`, or `.php` references).

---

## Tests

```bash
python3 -m pytest -q          # 30 tests
python3 test_script_test.py   # same, if pytest isn't installed
```

Tests never touch the network — the HTTP layer is monkeypatched. They cover the
version-assessment boundaries, CMS detection, scheme fallback, `--fail-on`
logic, header parsing, and the full `check_url` pipeline.

---

## Repository layout

```
.
├── README.md
├── CLAUDE.md             # guidance for AI coding agents
├── script_test.py       # main tool (single file, stdlib only)
└── test_script_test.py  # pytest suite (30 tests)
```

---

## Author

- **sudo3rs (Mas Riyan)**
- GitHub: [github.com/masriyan/php2shell](https://github.com/masriyan/php2shell)
- LinkedIn: [linkedin.com/in/sudo3rs](https://www.linkedin.com/in/sudo3rs/)

---

## References

- [Sansec — PHP2Shell: PHP RCE](https://sansec.io/research/php2shell)
- [Rapid7 — Critical Unauthenticated RCE in PHP](https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/)
- [Tenable — PHP2Shell FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)
- [watchTowr — PHP RCE FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [Google Cloud — Responding to core PHP vulnerabilities](https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619)
- [SOCRadar — Affected Versions & Fix](https://socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619/)
- [Help Net Security — PHP2Shell patched](https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/)
- [Plesk — PHP2Shell advisory](https://support.plesk.com/hc/en-us/articles/44397729587351)
