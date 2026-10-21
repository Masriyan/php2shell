# Research notes — PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

> Compiled from public reporting during the Oct 2026 advisory window.
> Everything below is what was **confirmed** at the time of writing — not vendor advisories.

---

## Status snapshot (as of Oct 21, 2026)

| Item | Status |
|------|--------|
| Official PHP advisory | **Not yet published** (fix scheduled 2026-10-21 14:00 UTC) |
| NVD entry (109618) | `totalResults: 0` |
| NVD entry (109619) | `totalResults: 0` |
| Public PoC for RCE | **None verified** — only screenshots / claims |
| Public primitive | **session-file poisoning** (documented) |
| CVSS | Reported ~**9.2** (v4.0) — not vendor-confirmed |

> ⚠️ Claims of "every PHP version from PHP 5 onward is affected" are
> **unconfirmed by the PHP project**. Treat them as provisional.

---

## What is confirmed

### 1. Two CVEs, core PHP

- **CVE-2026-109618** and **CVE-2026-109619**
- Reported as **unauthenticated RCE** in PHP core.
- Reported to affect PHP 5+ (scope **not** vendor-confirmed).

### 2. The documented mechanism: `session.upload_progress`

The only technically documented primitive across multiple independent sources
(Sansec, Huntress, watchTowr, PentestIT, syhunt, mikensec lab) is
**session-file poisoning**:

| Primitive | Description |
|-----------|-------------|
| **P1** | Set a session ID cookie-lessly via a `PHPSESSID` field in a multipart body. |
| **P2** | Inject arbitrary content into the session file via the `PHP_SESSION_UPLOAD_PROGRESS` field value **and** the uploaded filename, which PHP serializes verbatim into `sess_<id>`. |

The PHP manual itself warns that `session.upload_progress` does **not** validate
client-supplied file names or field names.

### 3. Code execution needs an app-side sink

> *"`session.upload_progress` content-injection only becomes code execution
> through an application-side `include()`/`require()` of the session file.
> Stock WordPress does not hand you that sink."*
> — `mikensec/php2shell-lab`

There is **no** automatic RCE, no gadget chain, no `system()` call. The earlier
`GenericClass` / `__destruct` / `system()` payload that circulated in some
"PoCs" was **fabricated** and has been removed from this tool.

### 4. Detection content (indicative)

Independent detection repos key on:

- **Network:** a multipart body that sets a session id from a field and/or
  carries the progress marker plus a `<?php` open tag.
- **File:** a `sess_*` file poisoned with `upload_progress_` + PHP tags.
- **Host:** PHP "Unknown on line 0" startup warning; web/php-fpm worker
  spawning a shell.

---

## Why no RCE exploit is shipped

A genuine RCE requires:

1. The `session.upload_progress` primitive (P1 + P2) — **observable**.
2. An application-side `include()`/`require()` of the session file — a **sink**
   that must be found (LFI, template include, plugin path).

Without a verified public gadget chain, any "RCE exploit" released today is
speculative. This tool therefore stops at:

- **primitive verification** (is the target affected at all?), and
- **sink enumeration** (does a plausible chain exist?).

That is the honest maximum that can be implemented with public information.

---

## Mitigation guidance

From public reporting, defensive recommendations converge on:

1. **Patch PHP** — apply the official fix for supported branches (8.2+).
2. **Disable `session.upload_progress`** where not needed:
   ```ini
   session.upload_progress.enabled = Off
   ```
   (The PHP manual already recommends this for apps without upload-progress bars.)
3. **Edge/WAF rules** — block multipart bodies that set a session id from a
   field and carry a `<?php` open tag (see syhunt's rules and the mikensec lab
   Suricata/Sigma/YARA content).
4. **Upgrade EOL PHP** — 5.x / 7.x / 8.0 / 8.1 will **not** receive a fix.

---

## Sources

- [Sansec — Critical PHP RCE](https://sansec.io/research/php2shell)
- [Huntress — Leaked critical PHP vulnerabilities](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities)
- [watchTowr — PHP RCE FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [PentestIT — What we know about php2shell](https://pentestit.com/php-cve-2026-109618-and-cve-2026-109619-what-we-know-about-php2shell/)
- [syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection)
- [mikensec/php2shell-lab](https://github.com/mikensec/php2shell-lab)
- [Penligent — What is confirmed about the two PHP RCEs](https://www.penligent.ai/hackinglabs/php2shell-what-is-confirmed-about-the-two-php-rces/)
- [Aikido — Critical vulnerabilities in PHP](https://www.aikido.dev/blog/critical-vulnerabilities-in-php-php2shell)
- [SecurityWeek — Mass exploitation looms](https://www.securityweek.com/php2shell-mass-exploitation-looms-for-leaked-critical-php-flaws/)
