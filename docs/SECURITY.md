# Security & responsible use

## Intended use

This project is a **security research and assessment tool**. It is intended
**exclusively** for:

- Authorized penetration tests and red-team engagements
- Vulnerability assessments of systems you own
- Internal security research on isolated lab environments

## Prohibited use

Do **not** use this tool against systems you do not own or lack explicit written
authorization to test. Unauthorized access to computer systems is illegal in
most jurisdictions (e.g. the U.S. CFAA, the U.K. Computer Misuse Act, Indonesia's
UU ITE).

## What the tool does on the wire

| Action | Detail |
|--------|--------|
| Homepage GET | Reads headers / HTML for fingerprinting |
| Path probes | GETs known CMS paths (login pages, manifest files) |
| Multipart probe | One POST with an **inert** canary (`<?php /* comment */ ?>`) |
| Sink scan | Read-only `/etc/passwd` LFI checks (only with `--sink-scan`) |

**No shell is uploaded, no code is executed, and no data is modified.**

## Data handling

- The tool sends only the request shapes described above.
- It does not exfiltrate or store any target data.
- Generated session IDs and canaries are random and per-run.

## Reporting a security issue in this tool

If you find a vulnerability **in this tool itself**, please open a private
security advisory on GitHub rather than a public issue.

## Disclaimer of warranty

```
THIS TOOL IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. THE AUTHOR ASSUMES
NO LIABILITY FOR DAMAGES ARISING FROM USE OR MISUSE. USE AT YOUR OWN RISK AND
ONLY WITH AUTHORIZATION.
```

The exposure verdicts produced by this tool are **estimates** based on publicly
available information and observable behavior; they are not a guarantee of
vulnerability or of safety.

---

Author: **sudo3rs** — [LinkedIn](https://www.linkedin.com/in/sudo3rs/) ·
[GitHub](https://github.com/masriyan/php2shell)
