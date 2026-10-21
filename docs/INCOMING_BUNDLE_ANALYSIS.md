# Analysis of incoming "php2shell" exploit bundle

> Date: 2026-10-21 · Author: sudo3rs (analysis) · Status: **DO NOT RUN — review only**

This document records the analysis of the files that arrived in
`research-incoming/`. Those files were **moved out of the repo root and are
NOT executed**. They describe and (attempt to) implement a memory-corruption
exploit chain, and are kept here solely for reference.

---

## What the files are

| File | Role |
|------|------|
| `readme baru` | Package README — labels a "reproducer" for two PHP 0-days |
| `ROOT_CAUSE.md` | Technical root-cause write-up (serialize/unserialize UAF) |
| `WEAPON_NOTES.md` | Lab receipts + "weapon completion path" (binary-corrupted) |
| `poc_serialize.py` | PoC for "Bug S" — `BG(serialize)` context orphan |
| `poc_unserialize.py` | PoC for "Bug U" — `BG(unserialize)` context orphan |
| `fast_fire.py` | Rapid reclaimer burst ("kill driver") |
| `php2shell_repro.sh` | Self-contained lab reproducer (builds lab in /tmp) |
| `lab_*.sh`, `weapon_*.sh`, `lab_index.php` | Development labs (gdb/strace/sweeps) |

## IOC scan result

Scanned all `.sh` / `.py` / `.md` for network exfil, reverse shells,
persistence, credential theft, and obfuscation markers.

**Result: clean.** All `curl` calls target `http://127.0.0.1` only (local
lab). No reverse shell, no `/dev/tcp`, no cron/authorized_keys, no token/API
key, no pastebin/ngrok. These are local exploit-development artifacts, **not
malware** — but they are **dangerous to run** against any vulnerable PHP.

---

## What the files CLAIM (and their internal contradictions)

The bundle claims two PHP 0-day RCEs via a pre-RINIT
`session.upload_progress` memory bug (a use-after-free of the serialize /
unserialize context globals). Two independent sub-claims exist:

1. **`ROOT_CAUSE.md` (corrected) says the RCE is NOT there:**
   - "Bug S (cached-pointer chain) … **DEAD at the addref** … no free, no
     RCE, **CVSS 0.0**".
   - "Bug U (serialize-state UAF) … memory-safety only, **NOT code
     execution**, **CVSS 5.3 Medium**".
   - "the final `system()` call requires a heap-groom + ASLR leak that
     **does not exist on this surface (no RCE path)**".

2. **`WEAPON_NOTES.md` / `poc_unserialize.py` claim the full RCE chain:**
   - arbitrary write → `zval_ptr_dtor` → forged `zend_object` →
     `zend_call_function` → `zif_system`.
   - But this is explicitly labeled **"TUNED DEMO / ASLR brute required"**
     and admits the `system()` stage needs a heap/ASLR leak that is
     "not reproduced" outside a specific glibc 2.39 build.

**Conclusion:** the two documents contradict each other. The strongest
internal statement is that this is a **memory-safety UAF (≈ CVSS 5.3)** that
is *prefixed toward* RCE but whose actual code-execution stage is not
reliably demonstrated. There is **no verified public RCE**.

---

## Why this is relevant to our tool (`php2shell.py`)

Our tool is **observational** — it fingerprints CMS/PHP and verifies the
*poisoning primitive* (P1 + P2) with an inert canary. It does **not** and
should **not** implement this memory-corruption chain, because:

1. It requires a specific vulnerable PHP build + glibc layout + ASLR leak —
   not a portable or honest "detection" capability.
2. It is a genuine remote **crash/RCE** primitive — shipping it would turn a
   research tool into a weapon and is out of scope for what we agreed.
3. The "proof" is internally inconsistent (CVSS 0.0 vs 5.3 vs "RCE").

## Recommendation

- **Keep `research-incoming/` quarantined.** Do not run any of its `.sh` or
  `.py` outside an isolated, disposable VM you own.
- **Do not merge** these into `php2shell.py`.
- If ever run for research, use the official isolated lab (`php2shell_repro.sh`
  builds its own `/tmp` lab) **only** against a containerized, throwaway
  vulnerable PHP that you fully own.
- Wait for the official PHP advisory (Oct 21, 2026 14:00 UTC) before drawing
  any conclusion about affected/fixed versions.
