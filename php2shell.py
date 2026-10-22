#!/usr/bin/env python3
"""PHP2Shell exposure checker — CVE-2026-109618 & CVE-2026-109619.

================================================================================
 PHP2Shell — CVE-2026-109618 / CVE-2026-109619 research & assessment tool
================================================================================
 Author   : sudo3rs (Mas Riyan)
 GitHub   : https://github.com/masriyan/php2shell
 LinkedIn : https://www.linkedin.com/in/sudo3rs/

 Authorized use only. PUBLIC RELEASE.
 Run only against systems you own or have explicit written authorization to test.
================================================================================

Detects whether a URL is likely exposed to the "PHP2Shell" PHP RCE pair
(disclosed 2026-10-21) by fingerprinting the PHP version, the CMS/platform, and
relevant config, then comparing against the vendor's fixed releases. Findings
are correlated with live threat intel (CISA KEV + FIRST EPSS).

This is a DETECTION tool for authorized testing, not an exploit. Both CVEs are
internal memory-safety bugs (OOM-driven corruption / use-after-free); there is
no safe boolean "trigger" probe, so this script determines exposure from the
reported PHP version and mitigation signals — it never sends an exploit payload.

Only run this against hosts you own or are explicitly authorized to test.

Two measurement modes:
  safe (default)  passive: read PHP version + CMS from headers and the landing
                  page HTML only.
  --no-safe-mode  active recon: also query PHP's version-disclosure "egg" and a
                  few well-known CMS fingerprint paths. Non-destructive.

Examples:
    python3 script_test.py https://target.example
    python3 script_test.py --no-safe-mode --workers 20 -i urls.txt --format json
    python3 script_test.py -i urls.txt --proxy http://127.0.0.1:8080 --format csv
    python3 script_test.py https://a.example --scheme both --fail-on unknown
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import pathlib
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# --- Advisory data, aligned with public research as of 2026-10-22 ------------
# PHP2Shell: CVE-2026-109618 (OOM memory corruption, GHSA-w8hw-w9fx-j79w) and
# CVE-2026-109619 (use-after-free, GHSA-6wmf-4rv5-p3rp). CVSS v4.0 9.2.
# Vulnerable: PHP 5.4 through 8.5.11. First patched build per supported branch:
FIXED_VERSIONS: dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
# Branches <= 8.1 are end-of-life: vulnerable with no official fix.
EOL_CEILING = (8, 1)
CVES = ["CVE-2026-109618", "CVE-2026-109619"]
# Interim mitigation for EOL hosts (not a full fix): disable upload progress.
MITIGATION = "session.upload_progress.enabled=0 + restart all PHP workers"

# PHP's long-standing version-disclosure easter-egg query string. Appending it
# to any PHP URL makes the interpreter emit a credit/logo page whose headers
# leak the version even when expose_php hides it from normal responses.
PHP_EGG_QUERY = "?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE_DIR = pathlib.Path.home() / ".cache" / "php2shell"

USER_AGENT = "php2shell-exposure-check/1.1 (authorized-testing)"
MAX_BODY = 262_144  # bytes of HTML to sniff for CMS fingerprints
log = logging.getLogger("php2shell-check")

# --- Presentation ------------------------------------------------------------
BANNER = r"""
  ____  _   _ ____ ____  ____  _   _ _____ _     _
 |  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | |
 | |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | |
 |  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___
 |_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____|
        P H P 2 S H E L L   ·   by sudo3rs
   CVE-2026-109618 / CVE-2026-109619  —  exposure checker
   Authorized testing only. Detection, not exploitation.
"""

# ANSI colors (disabled automatically when not a TTY, NO_COLOR, or --no-color).
_COLORS = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
}
_USE_COLOR = False


def c(text: str, *styles: str) -> str:
    if not _USE_COLOR:
        return text
    prefix = "".join(_COLORS.get(s, "") for s in styles)
    return f"{prefix}{text}{_COLORS['reset']}" if prefix else text


STATUS_STYLE = {"vulnerable": ("red", "bold"), "patched": ("green",),
                "unknown": ("yellow",), "error": ("dim",)}


# --- CMS fingerprinting ------------------------------------------------------
# Each CMS: regexes against the landing-page HTML/headers (passive), plus
# optional marker paths checked only in active mode. These identify the platform
# that ships/embeds PHP; they do not probe for CMS-specific vulnerabilities.
@dataclass
class CmsSignature:
    name: str
    html_patterns: list[str]
    active_paths: list[str] = field(default_factory=list)
    version_pattern: str | None = None  # applied to HTML to grab a CMS version


CMS_SIGNATURES = [
    CmsSignature("WordPress",
                 [r'<meta name="generator" content="WordPress ?(\d[\d.]*)',
                  r"/wp-content/", r"/wp-includes/"],
                 ["/wp-login.php", "/readme.html"],
                 r"WordPress ?(\d[\d.]*)"),
    CmsSignature("Joomla",
                 [r'<meta name="generator" content="Joomla!? ?(\d[\d.]*)', r"/media/jui/"],
                 ["/administrator/manifests/files/joomla.xml"],
                 r"Joomla!? ?(\d[\d.]*)"),
    CmsSignature("Drupal",
                 [r'<meta name="Generator" content="Drupal ?(\d[\d.]*)', r"/sites/default/files/", r"Drupal\.settings"],
                 ["/CHANGELOG.txt", "/core/CHANGELOG.txt"],
                 r"Drupal ?(\d[\d.]*)"),
    CmsSignature("Magento", [r"Mage\.Cookies", r"/static/version\d+/", r"/skin/frontend/"], ["/magento_version"]),
    CmsSignature("TYPO3", [r"/typo3conf/", r'<meta name="generator" content="TYPO3']),
    CmsSignature("PrestaShop", [r"/modules/", r"var prestashop", r"PrestaShop"]),
    CmsSignature("Laravel", [r"laravel_session", r"XSRF-TOKEN"]),
    CmsSignature("phpBB", [r"phpBB", r"/styles/prosilver/"]),
    CmsSignature("MediaWiki", [r'<meta name="generator" content="MediaWiki ?(\d[\d.]*)'], [], r"MediaWiki ?(\d[\d.]*)"),
    CmsSignature("Plesk", [r"Plesk", r"/plesk-site-preview/"]),
]


@dataclass
class Result:
    url: str
    final_url: str | None = None
    checked_at: str = ""
    php_version: str | None = None
    php_detected: bool = False
    version_source: str | None = None
    cms: str | None = None
    cms_version: str | None = None
    cms_source: str | None = None
    server: str | None = None
    evidence: str = ""
    status: str = "unknown"  # vulnerable | patched | unknown | error
    reason: str = ""
    cves: list[str] = field(default_factory=lambda: list(CVES))
    recommendation: str = ""


@dataclass
class Intel:
    """Live threat-intel context for the two CVEs (report-level, not per host)."""
    in_kev: bool | None = None
    kev_date_added: str | None = None
    epss: dict[str, float] = field(default_factory=dict)
    note: str = "intel not fetched"


# --- HTTP client -------------------------------------------------------------
@dataclass
class HttpClient:
    timeout: float = 15.0
    insecure: bool = False
    retries: int = 2           # extra attempts after the first
    backoff: float = 1.5       # seconds, multiplied each retry
    proxy: str | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    user_agent: str = USER_AGENT

    def _opener(self) -> urllib.request.OpenerDirector:
        ctx = ssl.create_default_context()
        if self.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPSHandler(context=ctx)]
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}))
        return urllib.request.build_opener(*handlers)

    def _headers(self) -> dict[str, str]:
        return {"User-Agent": self.user_agent, **self.extra_headers}

    def fetch(self, url: str, want_body: bool) -> tuple[int, dict[str, str], str]:
        """Return (status, lowercased-headers, body) with retry/backoff.

        A 4xx/5xx is a valid response and returned immediately. Only transport
        errors (DNS, timeout, reset) are retried; the last one is raised as
        RuntimeError. A fresh opener per call keeps this thread-safe.
        """
        opener = self._opener()
        methods = ("GET",) if want_body else ("HEAD", "GET")
        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            for method in methods:
                req = urllib.request.Request(url, method=method, headers=self._headers())
                try:
                    with opener.open(req, timeout=self.timeout) as resp:
                        body = resp.read(MAX_BODY).decode("utf-8", "replace") if want_body else ""
                        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body
                except urllib.error.HTTPError as exc:
                    body = exc.read(MAX_BODY).decode("utf-8", "replace") if want_body else ""
                    return exc.code, {k.lower(): v for k, v in exc.headers.items()}, body
                except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                    last_exc = exc  # try next method, then retry
            if attempt < self.retries:
                wait = self.backoff * (attempt + 1)
                log.info("retry %d/%d for %s in %.1fs (%s)", attempt + 1, self.retries, url, wait, last_exc)
                time.sleep(wait)
        raise RuntimeError(str(last_exc))

    def get_json(self, url: str) -> dict:
        """Fetch and parse a full JSON document (no body-size cap, with retry)."""
        opener = self._opener()
        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                req = urllib.request.Request(url, headers=self._headers())
                with opener.open(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8", "replace"))
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last_exc = exc
                if attempt < self.retries:
                    time.sleep(self.backoff * (attempt + 1))
        raise RuntimeError(str(last_exc))


# --- Fingerprinting ----------------------------------------------------------
def extract_php_version(headers: dict[str, str]) -> str | None:
    for header in ("x-powered-by", "server"):
        if m := re.search(r"PHP/(\d+\.\d+\.\d+)", headers.get(header, ""), re.IGNORECASE):
            return m.group(1)
    return None


def php_is_present(headers: dict[str, str], body: str) -> bool:
    """True if the host looks PHP-backed even when the version is hidden."""
    blob = " ".join(headers.get(h, "") for h in ("server", "x-powered-by", "set-cookie"))
    if re.search(r"\bPHP\b|PHPSESSID", blob, re.IGNORECASE):
        return True
    return bool(re.search(r"\.php(?:[\"'?/ >]|$)", body, re.IGNORECASE))


def detect_cms(headers: dict[str, str], body: str,
               signatures: list[CmsSignature]) -> tuple[str | None, str | None, str | None]:
    """Return (cms, cms_version, source) from headers + landing-page HTML."""
    haystack = body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
    for sig in signatures:
        for pat in sig.html_patterns:
            if m := re.search(pat, haystack, re.IGNORECASE):
                version = None
                if sig.version_pattern and (vm := re.search(sig.version_pattern, haystack, re.IGNORECASE)):
                    version = vm.group(1) or None
                elif m.groups() and m.group(1):
                    version = m.group(1)
                if version and not re.search(r"\d", version):  # reject e.g. "."
                    version = None
                return sig.name, version.strip(".") if version else None, "landing page"
    # Header hints whose mere presence implies a platform (value is not a name).
    for hdr, name in (("x-drupal-cache", "Drupal"), ("x-drupal-dynamic-cache", "Drupal")):
        if hdr in headers:
            return name, None, f"header {hdr}"
    # Headers whose value names the generator (e.g. "Drupal 10 (https://...)").
    for hdr in ("x-generator", "x-powered-cms"):
        if val := headers.get(hdr):
            # Name = leading words; version = a later space-separated X.Y token.
            if gm := re.match(r"([A-Za-z][\w.!-]*(?: [A-Za-z][\w.!-]*)*?)(?: +v?(\d[\d.]*))?(?:[ /(]|$)", val.strip()):
                return gm.group(1).strip(), gm.group(2) or None, f"header {hdr}"
    return None, None, None


def detect_cms_active(url: str, client: HttpClient,
                      signatures: list[CmsSignature]) -> tuple[str | None, str | None, str | None]:
    """Probe well-known CMS marker paths (non-destructive GETs)."""
    base = url.rstrip("/")
    for sig in signatures:
        for path in sig.active_paths:
            try:
                status, _, body = client.fetch(base + path, want_body=True)
            except RuntimeError:
                continue
            if status == 200 and body:
                version = None
                if sig.version_pattern and (vm := re.search(sig.version_pattern, body, re.IGNORECASE)):
                    version = vm.group(1)
                return sig.name, version, f"active path {path}"
    return None, None, None


def parse_version(ver: str) -> tuple[int, int, int] | None:
    parts = ver.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return int(parts[0]), int(parts[1]), int(parts[2])


def assess(version: str | None) -> tuple[str, str, str]:
    """Return (status, reason, recommendation) for a detected PHP version."""
    if version is None:
        return ("unknown", "PHP version could not be determined", "Fingerprint the host manually; assume exposed until confirmed.")

    parsed = parse_version(version)
    if parsed is None:
        return ("unknown", f"Unrecognized version string: {version}", "Verify the PHP version manually.")

    major, minor, _ = parsed
    branch = (major, minor)

    if major < 5 or (major == 5 and minor < 4):
        return ("unknown", f"PHP {version} predates the stated affected range (5.4+)", "Confirm the real version; very old banners are often spoofed.")

    if branch <= EOL_CEILING:
        return ("vulnerable", f"PHP {version} is on an end-of-life branch with no official fix", f"Upgrade to a supported, patched branch. Interim: {MITIGATION}.")

    fixed = FIXED_VERSIONS.get(branch)
    if fixed is None:
        if branch > max(FIXED_VERSIONS):
            return ("unknown", f"PHP {version} is newer than tracked branches; likely patched", "Confirm against the latest PHP advisory.")
        return ("unknown", f"No fixed-version data for branch {major}.{minor}", "Check the PHP advisory for this branch.")

    if parsed >= fixed:
        return ("patched", f"PHP {version} >= fixed {'.'.join(map(str, fixed))} for this branch", "No action for PHP2Shell; keep patching routine.")

    return ("vulnerable", f"PHP {version} < fixed {'.'.join(map(str, fixed))} for this branch", f"Upgrade to {'.'.join(map(str, fixed))} or later on branch {major}.{minor}.")


def _candidate_urls(url: str, scheme: str) -> list[str]:
    if "://" in url:
        return [url]
    if scheme == "http":
        return ["http://" + url]
    if scheme == "both":
        return ["https://" + url, "http://" + url]
    return ["https://" + url]


def check_url(url: str, client: HttpClient, active: bool, scheme: str,
              signatures: list[CmsSignature]) -> Result:
    res = Result(url=url, checked_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))

    status = headers = body = None
    last_exc = ""
    for candidate in _candidate_urls(url, scheme):
        try:
            status, headers, body = client.fetch(candidate, want_body=True)
            res.final_url = candidate
            break
        except RuntimeError as exc:
            last_exc = str(exc)
    if headers is None:
        res.status, res.reason = "error", f"request failed: {last_exc}"
        return res

    res.server = headers.get("server")
    res.php_detected = php_is_present(headers, body)

    # PHP version (passive)
    version = extract_php_version(headers)
    if version:
        res.version_source = "response headers"

    # CMS (passive)
    res.cms, res.cms_version, res.cms_source = detect_cms(headers, body, signatures)

    if active:
        if version is None:
            # Version-disclosure egg: non-destructive, returns a credits page.
            try:
                _, egg_headers, _ = client.fetch(res.final_url.rstrip("/") + "/" + PHP_EGG_QUERY, want_body=False)
                if egg_version := extract_php_version(egg_headers):
                    version, res.version_source = egg_version, "version-disclosure egg (active)"
                    res.php_detected = True
            except RuntimeError as exc:
                log.info("egg probe failed for %s: %s", res.final_url, exc)
        if res.cms is None:
            res.cms, res.cms_version, res.cms_source = detect_cms_active(res.final_url, client, signatures)

    # Evidence trail
    bits = []
    if res.server:
        bits.append(f"Server: {res.server}")
    if xp := headers.get("x-powered-by"):
        bits.append(f"X-Powered-By: {xp}")
    if res.version_source:
        bits.append(f"version via {res.version_source}")
    res.evidence = " | ".join(bits)

    res.php_version = version
    res.status, res.reason, res.recommendation = assess(version)

    # Refine the "unknown" message when PHP is clearly present but hidden.
    if version is None and res.php_detected:
        res.reason = "PHP detected but version hidden (expose_php off / stripped banner)"
        res.recommendation = "Confirm version out-of-band; treat as potentially exposed."
    return res


# --- Threat intel ------------------------------------------------------------
def fetch_intel(client: HttpClient, cache_ttl_hours: float = 6.0) -> Intel:
    """Correlate the two CVEs with CISA KEV presence and FIRST EPSS scores."""
    intel = Intel()
    notes = []

    # CISA KEV (cached), to see whether either CVE is known-exploited yet.
    cache = CACHE_DIR / "kev.json"
    kev_data = None
    try:
        if cache.exists() and time.time() - cache.stat().st_mtime < cache_ttl_hours * 3600:
            kev_data = json.loads(cache.read_text())
        else:
            kev_data = client.get_json(KEV_URL)
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(kev_data))
    except (RuntimeError, json.JSONDecodeError, OSError) as exc:
        notes.append(f"KEV unavailable ({exc})")
        if cache.exists():
            try:
                kev_data = json.loads(cache.read_text())
                notes.append("using stale KEV cache")
            except (json.JSONDecodeError, OSError):
                kev_data = None

    if kev_data:
        hits = [v for v in kev_data.get("vulnerabilities", []) if v.get("cveID") in CVES]
        intel.in_kev = bool(hits)
        if hits:
            intel.kev_date_added = min(h.get("dateAdded", "") for h in hits)
        notes.append("KEV: listed" if hits else "KEV: not yet listed")

    # FIRST EPSS exploitation-probability scores.
    try:
        rows = client.get_json(f"{EPSS_URL}?{urllib.parse.urlencode({'cve': ','.join(CVES)})}").get("data", [])
        intel.epss = {r["cve"]: float(r["epss"]) for r in rows}
        if intel.epss:
            notes.append("EPSS: " + ", ".join(f"{c}={s:.3f}" for c, s in intel.epss.items()))
    except (RuntimeError, json.JSONDecodeError, KeyError, ValueError) as exc:
        notes.append(f"EPSS unavailable ({exc})")

    intel.note = " | ".join(notes) if notes else "no intel returned"
    return intel


def intel_banner(intel: Intel) -> str:
    kev_raw = {True: "YES", False: "no", None: "?"}[intel.in_kev]
    kev = c(kev_raw, "red", "bold") if intel.in_kev else c(kev_raw, "green") if intel.in_kev is False else kev_raw
    epss = ", ".join(f"{cve.split('-')[-1]}={s:.3f}" for cve, s in intel.epss.items()) or "n/a"
    added = f" (added {intel.kev_date_added})" if intel.kev_date_added else ""
    return c("Intel", "bold") + f" — CISA KEV: {kev}{added} | EPSS: {epss}"


# --- Targets & output --------------------------------------------------------
def load_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.urls)
    if args.input:
        text = sys.stdin.read() if str(args.input) == "-" else args.input.read_text()
        targets += [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    seen, ordered = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            ordered.append(t)
    return ordered


def load_signatures(path: pathlib.Path) -> list[CmsSignature]:
    """Load CMS signatures from an external JSON file (list of objects)."""
    data = json.loads(path.read_text())
    sigs = []
    for item in data:
        sigs.append(CmsSignature(
            name=item["name"],
            html_patterns=list(item.get("html_patterns", [])),
            active_paths=list(item.get("active_paths", [])),
            version_pattern=item.get("version_pattern"),
        ))
    if not sigs:
        raise ValueError("signature file contained no entries")
    return sigs


def _cms_label(r: Result) -> str:
    if not r.cms:
        return "-"
    return f"{r.cms} {r.cms_version}" if r.cms_version else r.cms


def render_table(results: list[Result], intel: Intel | None) -> str:
    icon = {"vulnerable": "[VULN]", "patched": "[ ok ]", "unknown": "[ ?? ]", "error": "[err ]"}
    # Plain rows drive column widths (color codes must not count toward width).
    plain = [
        [icon.get(r.status, "[ ?? ]"), r.status.upper(), r.php_version or "-", _cms_label(r), r.url, r.reason]
        for r in results
    ]
    headers = ["", "STATUS", "PHP", "CMS", "URL", "REASON"]
    widths = [max(len(h), *(len(row[i]) for row in plain)) if plain else len(h) for i, h in enumerate(headers)]

    def fmt(cells: list[str], styles: list[tuple[str, ...]] | None = None) -> str:
        out = []
        for i, (val, w) in enumerate(zip(cells, widths)):
            cell = str(val).ljust(w)
            if styles and styles[i]:
                cell = c(cell, *styles[i])
            out.append(cell)
        return "  ".join(out)

    lines = [c(fmt(headers), "bold"), fmt(["-" * w for w in widths])]
    for r, row in zip(results, plain):
        st = STATUS_STYLE.get(r.status, ())
        styles = [st, st, (), (), ("cyan",), ()]
        lines.append(fmt(row, styles))

    out = []
    if intel:
        out += [intel_banner(intel), ""]
    out += lines
    return "\n".join(out)


def render_json(results: list[Result], intel: Intel | None) -> str:
    doc: dict = {"results": [asdict(r) for r in results]}
    if intel:
        doc["intel"] = asdict(intel)
    return json.dumps(doc, indent=2)


def render_csv(results: list[Result]) -> str:
    buf = io.StringIO()
    fields = list(asdict(results[0]).keys()) if results else [f.name for f in Result.__dataclass_fields__.values()]
    writer = csv.DictWriter(buf, fieldnames=fields)
    writer.writeheader()
    for r in results:
        row = asdict(r)
        row["cves"] = ",".join(row["cves"])
        writer.writerow(row)
    return buf.getvalue()


def render_markdown(results: list[Result], intel: Intel | None) -> str:
    today = datetime.now(timezone.utc).date().isoformat()
    lines = [
        "---",
        f"title: PHP2Shell Exposure Scan {today}",
        f"date: {today}",
        "tags: [threat-intel, cve, php, php2shell]",
        f"cves: [{', '.join(CVES)}]",
    ]
    if intel:
        lines.append(f"kev_listed: {intel.in_kev}")
        if intel.epss:
            lines.append(f"epss: {{{', '.join(f'{c}: {s}' for c, s in intel.epss.items())}}}")
    lines += [
        "---",
        "",
        f"# PHP2Shell Exposure Scan — {today}",
        "",
        f"Checking {', '.join(CVES)} (CVSS 9.2). Fixed: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.",
    ]
    if intel:
        lines += ["", f"> {intel_banner(intel)}"]
    lines += [
        "",
        "| Status | PHP | CMS | URL | Reason | Recommendation |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(f"| {r.status} | {r.php_version or '-'} | {_cms_label(r)} | {r.url} | {r.reason} | {r.recommendation} |")
    return "\n".join(lines) + "\n"


def summary(results: list[Result]) -> str:
    counts = {s: sum(r.status == s for r in results) for s in ("vulnerable", "patched", "unknown", "error")}
    return (f"{len(results)} target(s) | vulnerable: {counts['vulnerable']} | "
            f"patched: {counts['patched']} | unknown: {counts['unknown']} | error: {counts['error']}")


# fail-on severity: each level triggers a nonzero exit for its status + worse.
FAIL_LEVELS = {
    "never": set(),
    "vulnerable": {"vulnerable"},
    "unknown": {"vulnerable", "unknown"},
    "error": {"vulnerable", "unknown", "error"},
}


def should_fail(results: list[Result], fail_on: str) -> bool:
    trigger = FAIL_LEVELS[fail_on]
    return any(r.status in trigger for r in results)


def parse_headers(pairs: list[str]) -> dict[str, str]:
    headers = {}
    for item in pairs:
        if ":" not in item:
            raise argparse.ArgumentTypeError(f"bad header (want 'Name: value'): {item!r}")
        name, _, value = item.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="PHP2Shell exposure checker (CVE-2026-109618/109619).")
    p.add_argument("urls", nargs="*", help="target URLs")
    p.add_argument("-i", "--input", type=lambda s: s if s == "-" else pathlib.Path(s),
                   help="file with one URL per line ('-' for stdin)")
    p.add_argument("--no-safe-mode", dest="active", action="store_true",
                   help="active recon: version-disclosure egg + CMS marker paths (non-destructive)")
    p.add_argument("--workers", type=int, default=10, help="concurrent workers (default 10)")
    p.add_argument("--scheme", choices=["https", "http", "both"], default="https",
                   help="scheme to assume for bare hosts (default https)")
    p.add_argument("--timeout", type=float, default=15.0, help="per-request timeout (default 15s)")
    p.add_argument("--retries", type=int, default=2, help="transport-error retries (default 2)")
    p.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    p.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8080 (Burp/mitmproxy)")
    p.add_argument("-H", "--header", action="append", default=[], metavar="NAME: VALUE",
                   help="extra request header (repeatable)")
    p.add_argument("--user-agent", default=USER_AGENT, help="override the User-Agent")
    p.add_argument("--signatures", type=pathlib.Path, help="external CMS signature JSON to use instead of built-ins")
    p.add_argument("--no-intel", action="store_true", help="skip live CISA KEV / EPSS correlation")
    p.add_argument("--fail-on", choices=list(FAIL_LEVELS), default="vulnerable",
                   help="exit nonzero when a result at this severity or worse is found (default vulnerable)")
    p.add_argument("--format", choices=["table", "json", "csv", "md"], default="table")
    p.add_argument("--out", type=pathlib.Path, help="write output to a file")
    p.add_argument("--log", type=pathlib.Path, help="also write timestamped logs to this file")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    import os
    global _USE_COLOR
    _USE_COLOR = (not args.no_color and os.environ.get("NO_COLOR") is None and sys.stderr.isatty())

    if not args.no_banner:
        print(c(BANNER, "cyan"), file=sys.stderr)

    level = logging.INFO if args.verbose else logging.WARNING
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if args.log:
        handlers.append(logging.FileHandler(args.log))
    logging.basicConfig(level=level, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")

    try:
        extra_headers = parse_headers(args.header)
    except argparse.ArgumentTypeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    signatures = CMS_SIGNATURES
    if args.signatures:
        try:
            signatures = load_signatures(args.signatures)
            log.info("Loaded %d external CMS signatures from %s", len(signatures), args.signatures)
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
            print(f"error: could not load signatures: {exc}", file=sys.stderr)
            return 2

    targets = load_targets(args)
    if not targets:
        print("error: no targets given (pass URLs or -i FILE)", file=sys.stderr)
        return 2

    client = HttpClient(timeout=args.timeout, insecure=args.insecure, retries=max(0, args.retries),
                        proxy=args.proxy, extra_headers=extra_headers, user_agent=args.user_agent)

    mode = "ACTIVE (no-safe-mode)" if args.active else "SAFE (passive)"
    log.info("Mode: %s | targets: %d | workers: %d | scheme: %s", mode, len(targets), args.workers, args.scheme)

    intel = None
    if not args.no_intel:
        intel = fetch_intel(client)
        log.info(intel.note)

    def work(u: str) -> Result:
        return check_url(u, client, args.active, args.scheme, signatures)

    total = len(targets)
    show_progress = sys.stderr.isatty() and args.format == "table"

    def progress(done: int, r: Result) -> None:
        if not show_progress:
            return
        st = STATUS_STYLE.get(r.status, ())
        tag = c(r.status.upper(), *st) if st else r.status.upper()
        sys.stderr.write(f"\r\033[K[{done}/{total}] {tag}  {r.url}")
        sys.stderr.flush()
        if done == total:
            sys.stderr.write("\n")

    workers = max(1, min(args.workers, total))
    results: list[Result] = [None] * total  # type: ignore[list-item]
    if workers == 1:
        for idx, u in enumerate(targets):
            results[idx] = r = work(u)
            progress(idx + 1, r)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(work, u): idx for idx, u in enumerate(targets)}
            done = 0
            for fut in as_completed(futures):
                idx = futures[fut]
                results[idx] = r = fut.result()
                done += 1
                progress(done, r)

    match args.format:
        case "json":
            output = render_json(results, intel)
        case "csv":
            output = render_csv(results)
        case "md":
            output = render_markdown(results, intel)
        case _:
            output = render_table(results, intel)

    if args.out:
        args.out.write_text(output if output.endswith("\n") else output + "\n")
        print(f"Wrote report for {len(results)} target(s) to {args.out}", file=sys.stderr)
    else:
        print(output)

    print(summary(results), file=sys.stderr)
    return 1 if should_fail(results, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
