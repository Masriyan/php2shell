# How it works — step-by-step

This document explains the technical flow of `php2shell.py`, phase by phase,
mapped to the functions that implement each step.

---

## Phase 1 — Prompt / parse target

**Functions:** `prompt_url()`, `normalize_url()`, `make_session()`

- The target URL comes from `--url/-u` **or** an interactive prompt.
- `normalize_url()` strips whitespace, prepends `http://` if missing, and
  reduces the URL to `scheme://host` (dropping path/query).
- `make_session()` builds a `requests.Session` with:
  - a custom `User-Agent` (`sudo3rs-PHP2Shell-Checker/...`)
  - `verify=False` (deliberate — research against self-signed/misconfigured hosts)

---

## Phase 2 — CMS fingerprinting

**Function:** `detect_cms()` · **Data:** `CMS_SIGNATURES`

Three signal layers are combined, each contributing to a per-CMS **score**:

1. **Response headers** — e.g. `X-Generator: Drupal`, `X-Magento-*`, Laravel/Symfony headers.
2. **`<meta name="generator">`** in the homepage HTML body.
3. **Known path probes** — `wp-login.php`, `/administrator/`, `/user/login`, etc.,
   matched against status code + body regex.

The CMS with the highest score wins. Confidence is derived from score:

| Score | Confidence |
|-------|------------|
| ≥ 3   | high       |
| 2     | medium     |
| 1     | low        |

Recognized CMS: **WordPress, Joomla, Drupal, Magento, Laravel, CodeIgniter,
Symfony, phpBB, PrestaShop, OpenCart, Typo3** — falling back to
`Unknown (generic PHP?)`.

### Anti-false-positive guards

- **Needle is mandatory** — a bare HTTP `200` with no content match no longer
  counts (prevents soft-404 servers from matching everything).
- **404/error-page filter** — responses that look like `404 not found`,
  `no input file specified`, etc. are discarded before matching.

### Behavior / version probes (deep)

After the winning CMS is chosen, `detect_cms_behavior()` reads version-leaking
static files to pin the exact version:

- WordPress → `readme.html`, `wp-includes/version.php`, `wp-links-opml.php`, `wp-json/wp/v2/`
- Joomla → `language/en-GB/en-GB.xml`, `administrator/manifests/files/joomla.xml`
- Drupal → `CHANGELOG.txt`, `core/CHANGELOG.txt`
- Magento → `magento_version`, `RELEASE_NOTES.txt`
- PrestaShop / OpenCart / phpBB → version files

---

## Phase 3 — PHP version / type / support status

**Functions:** `detect_php()`, `php_support_status()` · **Data:** `PHP_SUPPORT`

- **Version** — parsed from `X-Powered-By: PHP/x.y.z` (fallback: generator meta).
- **Type** — `Server` header containing `fpm` ⇒ `PHP-FPM`.
- **Support status** — the detected version is mapped against `PHP_SUPPORT`:

| Branch      | Status      | PHP2Shell fix |
|-------------|-------------|----------------|
| 8.6         | active      | will get fix   |
| 8.5 / 8.4   | active      | will get fix   |
| 8.3 / 8.2   | security    | will get fix   |
| ≤ 8.1 / 7.x / 5.x | EOL   | **NO fix**     |

> The EOL distinction matters: research indicates only supported branches
> (8.2+) will receive an official fix.

---

## Phase 4 — Confirmation gate

Unless `--no-confirm` is passed, the user must approve before any multipart
probe is sent. Detection results are already printed at this point.

---

## Phase 5 — Poisoning primitive probe (P1 + P2)

**Functions:** `probe_upload_progress()`, `build_poison_body()`

A single multipart POST exercises both primitives with an **inert canary**:

```
Content-Disposition: form-data; name="PHPSESSID"
<sid>                                     # P1 — cookie-less session id

Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"
<?php /* php2shell inert canary ... */ ?>  # P2 — value injection

Content-Disposition: form-data; name="file1"; filename="<?php /* ... */ ?>"
CANARYDATA                                # P2 — filename injection
```

**The canary is a PHP *comment* — never a shell.** No code is executed.

**P1 is CONFIRMED** if PHP replies with `Set-Cookie: PHPSESSID` (or any session
cookie) — this proves PHP accepted the cookie-less session id.

---

## Phase 6 — Exposure verdict

**Function:** `assess_vulnerability()`

Combines the P1/P2 observation with the PHP support status:

| Verdict | Meaning |
|---------|---------|
| 🔴 `LIKELY AFFECTED`        | primitive confirmed **+** EOL PHP |
| 🟡 `POTENTIALLY AFFECTED`   | primitive confirmed, PHP supported |
| 🟡 `EOL PHP`                | EOL branch, primitive not observed |
| 🟢 `PRIMITIVE NOT OBSERVED` | likely mitigated / patched |
| 🔴 `UNREACHABLE`            | request failed / target filtered |

> This is an **estimate** only — official affected/fixed versions were still
> unpublished at the time of writing.

---

## Phase 7 — Optional sink scan

**Function:** `probe_include_sinks()` · **Data:** `CMS_SINK_SIGNATURES`

With `--sink-scan`, the tool probes per-CMS candidate `include()`/LFI endpoints
using read-only `/etc/passwd` checks (`root:x:0:0`). These are the endpoints an
operator would need to **chain** with a poisoned session file to achieve actual
RCE. None is a guaranteed sink.

### PEAR sink probe

`probe_pearcmd()` additionally checks for `pearcmd.php` (`/pearcmd.php`,
`/pear/pearcmd.php`, `/usr/share/php/pearcmd.php`) and looks for
`register_argc_argv` reflection. This is the well-documented PEAR LFI→RCE
escalation vector (cf. Patchstack's WordPress 7.1.2 / CVE-2026-87902 research).
Read-only presence check — nothing is executed.

## Defensive config exposure (Phase 2b)

**Function:** `detect_config_exposure()`

Before the probe, the tool assesses the *conditions* the memory-corruption
class needs, using only observable signals:

| Signal | Why it matters |
|--------|----------------|
| `session.upload_progress.enabled` | If Off, the primitive is closed (mitigated). |
| `session.upload_progress.cleanup` | If On (default), exploitation is a race. |
| `memory_limit` vs `post_max_size` | Small `memory_limit` relative to a large `post_max_size` is the OOM-bailout precondition for the UAF class. |
| SAPI hint | Apache/prefork child survives a pre-RINIT bailout; FPM/CGI/LSAPI typically exit. |

These are read from `phpinfo`-style reflection endpoints if the target exposes
one (absence is **not** a finding). This is **defensive intel only** — no
memory corruption is exercised.

---

## Why there is no RCE payload

A real RCE requires an application-side `include()`/`require()` of the poisoned
session file — a sink that stock CMS platforms do not provide. No verified
public gadget chain exists as of the advisory window, so this tool deliberately
**stops at primitive verification + sink enumeration** rather than fabricating
an unconfirmed exploit.
