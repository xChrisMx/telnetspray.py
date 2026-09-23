# telnetspray.py
Two-phase masscan + Python raw-socket Telnet sweep for internal subnets. Classifies auth posture into 5 buckets — critically distinguishing wide-open OS shells from SCPI test-instrument auto-logins (a real miscategorization bug in the prior tool). Live progress bar, CSV + 2-sheet Excel report.


# telnetspray.py

Subnet-wide Telnet authentication-posture sweep: masscan for
fast discovery, then a worker pool for the actual assessment, with the same
live progress bar / logging conventions. Single Python file — scan, parse,
CSV, and `.xlsx` are all in it. Rewritten from the original
`telnet_final_scan.sh`.

## What it finds

For every Telnet host in scope, one of five **Auth Category** buckets:

- 🔴 **No Auth - OS Shell (Critical)** — blank credentials produced a
  general-purpose interactive OS shell. Immediately exploitable.
- 🟠 **No Auth - SCPI/Instrument** — the device auto-connects straight to its
  SCPI command parser with no login, by instrument design. Still a finding,
  different remediation conversation than the shell case.
- 🟢 **Auth Required** — a login/username/password prompt was observed.
- 🟡 **Likely Auth Required (Unclassified Banner)** — got a response, but it
  didn't match anything above. Manual review recommended.
- ⚪ **Unknown / Silent** — masscan confirmed the port open, but the device
  never responded to the connection or either probe.

Plus, per host: hostname (reverse DNS), manufacturer (banner keyword match),
instrument model (parsed from a SCPI `*IDN?` reply when available), the raw
banner/probe/`*IDN?` response text, and a plain-English "Meaning" column.

## Why this rewrite exists: SCPI instruments were being miscategorized

`telnet_final_scan.sh`'s active-probe classifier treated **any** of
`# $ > shell busybox root@ /bin cmd.exe` appearing in the blank-credential
probe response as proof of a wide-open interactive shell. That's a
reasonable signal for a real OS shell — but it's also the single most common
thing a SCPI test instrument's Telnet interface prints: a bare `>` prompt.
SCPI instruments (oscilloscopes, power supplies, spectrum analyzers, etc.)
routinely auto-connect an incoming Telnet session straight to their command
parser with no login at all. A real capture from one:

```
Welcome to K-N1912A-56015 - SCPI parser.

SCPI>
```

That **is** a "no authentication required" finding worth reporting — but
it's not the same finding as a Linux root shell handed out for free, and
lumping both into one "CRITICAL, shell granted" bucket buried the signal a
pentester actually needs: which no-auth hosts are exploitable general-purpose
shells, and which are instruments behaving exactly as designed by their
manufacturer (still worth restricting at the network layer, but a different
conversation). This script fixes that with two independent SCPI signals,
both checked **before** the shell-prompt check ever runs:

1. **The literal word "SCPI"** appearing anywhere in the passive banner or
   the blank-probe response — catches self-announcing instruments like the
   one above directly, no active probing needed. High confidence: a device
   that isn't a SCPI parser has no reason to print that word.
2. **A `*IDN?` probe** — the standard IEEE-488.2 identification query almost
   every SCPI-compliant instrument answers, even if it stayed completely
   silent on connect. If the reply is shaped like the standard
   `Manufacturer,Model,Serial,Firmware` format, or names a known
   test-equipment vendor (Keysight, Agilent, Rohde & Schwarz, Tektronix,
   Anritsu, LeCroy, National Instruments, Fluke, Siglent, and others — see
   `INSTRUMENT_VENDOR_KEYWORDS` in the script), that's SCPI too. Lower
   confidence than signal 1, since it's inferring intent from shape rather
   than an explicit self-identification.

The shell-prompt regex itself was also tightened (`looks_like_shell()`): it
no longer treats a bare `>` occurring *anywhere* in the captured text as a
shell prompt — that was the original bug's actual root cause. It now
requires either an explicit OS marker (`busybox`, `root@`, `/bin/sh`,
`cmd.exe`, a Windows drive-letter prompt, or the ubiquitous `user@host:`
prefix) or the **last non-blank line** of the response to look like a CLI
prompt (`#`/`$`/`>`, with or without a hostname/username in front of it — a
bare `> ` alone counts too, since that's a common shape on printers and some
switches). What actually stops a SCPI instrument's bare `SCPI>` from landing
here isn't this regex at all — it's that the SCPI check above runs *first*
and already claims it via the literal `"SCPI"` keyword.

No credentials of any kind are ever sent. `*IDN?` is a standard, read-only
query defined for exactly this purpose — it does not change instrument
state, start/stop a measurement, or alter any setting.

## Why raw sockets instead of `nc`/nmap

A Telnet auth check is nothing more than "connect, read, maybe write, read
again" — there's no protocol-version enumeration or XML output to parse the
way TLS/SSH need. Plain Python sockets cover the whole job with no external
subprocess dependency for Phase 2 at all (unlike the SSH/TLS siblings, which
lean on `ssh-audit`/nmap+NSE for their own protocol-specific parsing).
`masscan` is still required for Phase 1 discovery, same as every sibling
script.

## Why two phases

The configured scope (`SUBNETS` below) includes a `/8`. Pointing per-host
probing at that much address space directly would dominate the entire run.
**Phase 1** uses masscan — a stateless SYN scanner — to find which hosts
across all configured subnets have a Telnet port open, in a fraction of the
time. **Phase 2** then only touches real hosts: a pool of worker threads
each run the 3-step raw-socket probe against one host.

## Scope

```python
SUBNETS: List[str] = [
    "156.141.0.0/16",
    "156.140.0.0/16",
    "146.208.0.0/16",
    "141.184.0.0/16",
    "141.183.0.0/16",
    # "141.121.0.0/16",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
]

TELNET_PORTS: List[int] = [23]
```

Edit either list in the script to change scope — same convention as the
sibling scripts. Add alternate Telnet ports (e.g. `2323`) to `TELNET_PORTS`;
masscan discovery, the port spec, and the "is this port in scope" check all
derive from that one list. A host with more than one configured port open
gets one row per port in the report.

## Requirements

- `masscan` on PATH (unless `--skip-masscan` with a valid `--masscan-output-file`) — needs root/administrator to run
- Python 3.8+
- `openpyxl` — only for the `.xlsx` step. If missing, the run degrades to CSV-only instead of failing.

```bash
pip install openpyxl
```

## Usage

```bash
sudo python telnet_spray.py
```

Common options:

| Flag | Default | Purpose |
|---|---|---|
| `--workers` | `30` | Concurrent raw-socket probes in Phase 2 |
| `--rate` | `25000` | masscan packets/sec |
| `--timeout` | `3.0` | Per read step (connect + each of the 3 probes), in seconds |
| `--retries` | `1` | Retries per host if a probe comes back with a timeout/connection error (not retried for a clean-but-empty response — see Architecture notes) |
| `--output-dir` | script's own directory | Where the log/CSV/xlsx are written |
| `--interface` | *(none)* | Passed to masscan's `-e` |
| `--skip-masscan` + `--masscan-output-file` | — | Reuse a previous masscan run instead of re-scanning |
| `--no-xlsx` | off | Stop after the CSV |
| `--from-csv FILE` | — | Skip scanning entirely; rebuild the `.xlsx` from an existing CSV |

Resume from a previous masscan run (e.g. discovery already done, iterating on Phase 2 only):

```bash
python telnet_spray.py --skip-masscan --masscan-output-file .masscan_output_2026-09-23.txt
```

Rebuild just the `.xlsx` from an existing CSV without re-scanning:

```bash
python telnet_spray.py --from-csv telnet_spray_2026-09-23.csv
```

## Output

Everything is timestamped and written to `--output-dir` (same convention as
the sibling scripts):

- `telnet_spray_<date>.log` — full run log (DEBUG-level to file, INFO-level to console)
- `telnet_spray_<date>.csv` — one row per host:port
- `telnet_spray_<date>.xlsx` — **Overview** + **Scan Results** sheets
- `.masscan_output_<date>.txt` — raw masscan hit list (hidden file, kept so `--skip-masscan` can reuse it)

### `telnet_spray_<date>.csv`

```
Scan Date,IP Address,Hostname,Subnet Range,Port,Banner,Probe Response,SCPI IDN Response,Manufacturer,Instrument Model,Auth Category,Notes,Probe Method,Meaning,Scan Status
```

### `telnet_spray_<date>.xlsx`

**Overview** — title/scan metadata, a "How to read this report" explainer
covering the shell-vs-SCPI split, the 5-category table (color + description),
methodology notes explaining the 3-step probe and detection ordering, scan
summary counts (total + per-category + combined no-auth %), and a subnet
breakdown.

**Scan Results** — one row per host:port, frozen header, autofilter, every
row colored by its Auth Category (same red/orange/green/yellow/gray palette
as the Overview table), `Banner`/`Probe Response`/`SCPI IDN Response`/
`Notes`/`Meaning` columns wrap-text enabled.

## What it checks, and how it's classified

Classification runs in a strict order per host — each step only evaluated if
the previous one didn't already produce a definitive answer:

1. **Login prompt** (`login:`, `username:`, `password:`, etc.) in the banner, the blank-probe response, or the `*IDN?` response → **Auth Required**. Later probe steps are skipped once this fires.
2. **SCPI signal** — `SCPI` keyword in banner/blank-probe/`*IDN?` response, or a SCPI-shaped `*IDN?` reply → **No Auth - SCPI/Instrument**.
3. **Shell prompt** (`looks_like_shell()`: explicit OS marker, or the response's last line ends in `#`/`$`/`>` — with or without a hostname/username in front of it) → **No Auth - OS Shell (Critical)**.
4. **Any non-empty response** that matched none of the above → **Likely Auth Required (Unclassified Banner)**.
5. **Total silence** across all three steps → **Unknown / Silent**.

Manufacturer is taken from the SCPI `*IDN?` parse when available (fields 1/2
of the standard `Manufacturer,Model,Serial,Firmware` reply), otherwise from a
banner keyword match against common network/embedded-device vendor strings
(ported from `telnet_final_scan.sh`), otherwise `Unknown` (or `Unknown (SCPI)`
specifically for a SCPI-classified host with no identifiable vendor name, per
the literal fallback string used in `probe_telnet()`).

## Architecture notes

**Phase 1 (masscan)** is ported near-verbatim from the sibling scripts — same
live progress bar (percent/ETA parsed from masscan's own stderr), same `-oL`
list-output parsing, same dedup-by-key approach. Only the port spec changed
(built from `TELNET_PORTS`).

**Phase 2** is a hand-rolled raw-socket probe (`probe_telnet()`), not a
subprocess — see "Why raw sockets" above. Each host's probe runs once per
configured port on that host, same one-row-per-endpoint shape as
`sslspray.py`.

**Retry logic** mirrors the sibling scripts' "only retry `No Response`"
pattern: a probe that hit a connection timeout or refusal (`scan_status`
`No Response`) is retried up to `--retries` times. A probe that completed
cleanly and simply got no data back (a deterministically silent device, not
a transient miss), or that failed with some other `OSError` (`scan_status`
`Error`, e.g. "No route to host" on a firewalled subnet), is **not**
retried — the former is a property of the host, not the network, and the
latter mirrors the sibling scripts' own "only `No Response` is retried" rule.

**One bad host can't take down the batch** — same per-host exception
guarding as the sibling scripts.

## Security notes

**CSV/Excel formula injection (CWE-1236) is neutralized.** `Hostname`,
`Banner`, `Probe Response`, `SCPI IDN Response`, `Manufacturer`,
`Instrument Model`, `Notes`, and `Meaning` are all sourced from (or built
from) whatever the scanned device presents — attacker-controlled by design,
since that's exactly what this tool audits. `_neutralize_formula()` prefixes
a single quote onto any such value starting with `=`, `+`, `-`, `@`, tab, or
CR before it reaches `csv.writer` or an openpyxl cell, in both
`write_csv_report()` and `build_workbook()`.

**A malicious or malformed device response can't crash `.xlsx` generation
or blow up the report.** Unlike the TLS/SSH siblings, nothing here is
XML-parsed first — banner/probe/`*IDN?` text is raw, untrusted bytes straight
off the wire. `_sanitize_text()` strips characters illegal in XML 1.0 (the
same category of character that crashes openpyxl with
`IllegalCharacterError`) and caps every field at 2000 characters before it's
used anywhere, applied at capture time in `probe_telnet()` — not just to the
reverse-DNS hostname the way the TLS sibling does it, since here *every*
free-text field is equally untrusted. The same sanitization is applied a
second time in `read_rows_from_csv()`, so a `--from-csv` rebuild from a
hand-edited or externally-produced CSV can't reach openpyxl with an illegal
character either — it isn't only the live-scan path that's untrusted.

**A hand-edited or stale `--from-csv` file can't crash the rebuild or produce
a self-contradictory report.** The `Auth Category` column is validated
against the five canonical buckets on load (an unrecognized value falls back
to `Likely Auth Required (Unclassified Banner)`, logged as a warning rather
than raising `KeyError` deep inside the `.xlsx` writer), and `Meaning` is
always re-derived from that validated category rather than read verbatim
from the CSV — so a row can't end up colored/labeled one way while its
`Meaning` text describes something else.

## Limitations

**Assumes one scan run per workbook.** Every Overview count aggregates over
the *entire* Scan Results table. Re-running into the same file would double count.

**SCPI detection via `*IDN?` response *format* is a secondary, lower-confidence signal** compared to the banner/response keyword check. A chatty
non-SCPI device that happens to echo back something comma-shaped in response
to an unrecognized command could false-positive here. Flag for
re-verification if a live run surfaces this.

**The tightened shell-prompt check still can't distinguish a real shell from
a device that happens to end its own (non-SCPI) banner in a
`#`/`$`/`>`-shaped line for unrelated reasons** — rare, but anything landing
in "No Auth - OS Shell" is still worth a human glance before treating it as
gospel; "Likely Auth Required" exists specifically for genuinely ambiguous
cases instead of forcing a guess. Note that the standard non-root
`user@host:path$`/`user@host:path#` shell prompt shape (two separators, a
path segment) is caught despite the line-shape regex only allowing one
separator — it's matched by the marker-based check (`_SHELL_MARKERS_RE`'s
`user@host:` alternative) instead.

**A bare prompt character with no hostname/username (e.g. a printer or
switch that just sends `> ` on connect) is classified as "No Auth - OS
Shell"** rather than "Likely Auth Required" — correct for the common
printer/network-gear case this was specifically broadened to catch, but it
means a genuine SCPI/test instrument that (a) never prints the word "SCPI"
anywhere and (b) doesn't answer `*IDN?` with anything vendor-shaped would
also land in the shell bucket instead of the instrument one. IEEE-488.2
compliance makes that combination rare (nearly every real SCPI instrument
answers `*IDN?` usefully), but it's the residual edge case this heuristic
can't resolve — what actually protects a self-identifying SCPI instrument's
bare `SCPI>` prompt from this bucket is `detect_scpi()` running first, not
anything in the shell-prompt check itself.

**This still does not catch every no-auth device.** A custom menu-driven
admin console (numbered options, no shell-style prompt character at all —
e.g. `1. Network Settings\n2. Reboot\nSelect an option:`) has no reliable
marker to match against and lands in "Likely Auth Required" for manual
review rather than being auto-flagged Critical. Broadening the match further
to catch these risks false-positiving on ordinary devices that simply have
an unusual banner — this is a deliberate "flag for a human" tradeoff, not an
oversight.

**A masscan hit only proves the port is open**, not that anything
Telnet-shaped is listening there. An unrelated service squatting on TCP/23
lands in "Unknown / Silent" or "Likely Auth Required" depending on what it
happens to send back.

**Reverse DNS depends on corporate DNS infrastructure**; failures resolve to
`""` (blank) and do not stop the scan.

**Masscan needs elevated privileges** (raw sockets) — run with `sudo` / as
Administrator.

**Ctrl+C behavior**: first interrupt finishes in-flight work and writes
partial reports; second interrupt force-exits. Same as the sibling scripts.

## Verification

This script was fully exercised locally before being handed off (Python 3.13
+ openpyxl available on this machine): `py_compile` for syntax; a 6-case
synthetic-TCP-server harness driving `probe_telnet()` directly — including
the exact `K-N1912A-56015` SCPI banner shown above, a SCPI instrument that
stays silent until it receives `*IDN?` (confirmed it correctly extracts
Manufacturer=`Keysight Technologies` / Model=`34461A` from a synthetic
`*IDN?` reply), a real no-auth BusyBox/`root@` shell, a login-required
device, a Cisco-style bare `>` prompt with **no** SCPI signal present
(confirmed it still correctly falls to "No Auth - OS Shell" rather than
over-correcting into treating every `>` as safe), and a totally silent port
— all 6 classified correctly. A full `--skip-masscan` end-to-end run against
a local synthetic SCPI server was then run through the complete pipeline
(Phase 2 → CSV → `.xlsx`), confirming the CSV row content, the two-sheet
(`Overview`, `Scan Results`) workbook structure, and that the SCPI row is
filled with the correct amber color (not the red "shell" color) in the
generated `.xlsx`. A `--from-csv` rebuild of that same CSV was also run and
confirmed to reproduce an equivalent workbook. The masscan-facing code path
(Phase 1 itself) is ported near-verbatim from the already-proven sibling
scripts and wasn't independently re-run here (no masscan binary on this
machine) — same caveat the sibling scripts' own READMEs carry for their own
untested pieces.

**2026-09-23 review pass:** five independent dimension reviews (correctness,
README-vs-code consistency, sibling-script convention drift, security,
data-model/schema consistency), each followed by adversarial verification —
against the live code, by actual execution, not re-reading — of anything
flagged before it counted. 13 findings were confirmed real and fixed
(1 plausible finding, about `DEFAULT_TIMEOUT` differing from
`quantum_readiness_spray.py`'s, was checked and its claimed failure scenario
didn't reproduce, so it was left as-is rather than changed cosmetically):

1. **(correctness, high)** `looks_like_shell()` was only checked against
   `banner` and `probe_response` in `probe_telnet()`, never `idn_response` —
   a real no-auth OS shell that only revealed itself in answer to the
   `*IDN?` probe was misclassified as "Likely Auth Required" instead of the
   Critical shell bucket. Fixed by including `idn_response` in that check.
2. **(correctness/security, high)** `read_rows_from_csv()` took the `Auth
   Category` CSV column verbatim with no validation; a hand-edited or
   stale value not exactly matching one of the five canonical strings
   crashed the entire `--from-csv` run with an uncaught `KeyError` deep
   inside the `.xlsx` writer (`compute_category_stats()` / `build_workbook()`
   both index fixed-key dicts with no fallback). Fixed by validating against
   `AUTH_ORDER` on load (falling back to "Likely Auth Required" with a
   logged warning) plus defense-in-depth `.get()`-style fallbacks at the two
   downstream indexing sites.
3. **(security, high)** Unlike every live-scan text field, `read_rows_from_csv()`
   never called `_sanitize_text()` — a CSV containing a raw XML-illegal
   control character (hand-edited, or from an older/forked version of this
   tool) crashed `.xlsx` generation with an uncaught `openpyxl.IllegalCharacterError`
   instead of degrading gracefully. Fixed by sanitizing every free-text field
   on the `--from-csv` path too, and by widening `write_xlsx_report()`'s
   exception handling beyond just `ImportError`.
4. **(schema-consistency, medium)** `read_rows_from_csv()` read the `Meaning`
   column verbatim instead of re-deriving it from the (validated)
   `Auth Category`, so a `--from-csv` rebuild could produce a row colored/
   labeled one way with `Meaning` text describing something else entirely
   (e.g. a blank Auth Category defaulting to "Unknown / Silent" next to a
   stale "CRITICAL — shell granted" Meaning). Fixed by always deriving
   `Meaning` from the validated category, matching how a live scan does it.
5. **(correctness, medium)** The shell-prompt fallback regex only permitted
   one `@`/`:` separator, missing the single most common real-world no-auth
   shell prompt shape, `user@host:path$ ` — a non-root no-auth shell using
   that ubiquitous format was downgraded to "Likely Auth Required" instead
   of the Critical bucket. Fixed by adding a `\S+@\S+:` marker to
   `_SHELL_MARKERS_RE` (verified it doesn't reintroduce a false positive on
   any SCPI/login-prompt/silent-port test case).
6. **(correctness, medium)** `_SCPI_ERROR_HINTS_RE` didn't catch common
   command-rejection phrasings like "command not recognized" or "bad
   command" — a plain non-SCPI device rejecting the `*IDN?` probe with that
   wording, and happening to include a comma, was misclassified as a SCPI
   instrument. Broadened the regex to close the gap.
7. **(security, medium)** `_recv_available()` applied its timeout per
   individual `recv()` call instead of as a cumulative deadline for the
   whole read step — a peer trickling data just under the timeout interval
   could hold a worker thread's socket read open far longer than
   `--timeout` (measured multiple seconds over the configured window in a
   synthetic test). Fixed with a `time.monotonic()`-based deadline shared
   across the whole loop.
8. **(readme-consistency, low)** and **9. (readme-consistency, low)** — two
   README wording fixes: the Architecture notes overstated what gets
   retried (generic `OSError` does not, only `No Response`/timeout does),
   and the Manufacturer paragraph didn't mention the `Unknown (SCPI)`
   fallback string that a SCPI-classified host with no identifiable vendor
   actually gets.
10. **(sibling-conventions, low)** `main()`'s Phase 2 dispatch omitted the
    explanatory comment two of the three sibling scripts' equivalent code
    carries (or, for the one sibling that also omits the `stop_event` gate,
    the comment justifying why) — added, to stop a future maintainer from
    "fixing" an apparent inconsistency by reintroducing an empty-report-on-
    interrupt bug a sibling script already fixed once.

**A second-order regression was caught by an independent final re-verification
pass** (a separate agent re-checking the fixes above against the live code
and its own fresh tests, not the same one that made them) **and fixed
immediately after**: fix #1 above (checking `idn_response` for a shell
prompt) exposed that `detect_scpi()`'s literal `"SCPI"` keyword check only
scanned `banner`/`probe_response`, never `idn_response` — so a SCPI
instrument that stays silent until `*IDN?` and replies with a bare,
non-comma-format prompt (e.g. `SCPI> `, the exact shape shown in this file's
own SCPI example) was newly misclassified as a Critical OS shell instead of
"No Auth - SCPI/Instrument" — precisely the failure mode this whole rewrite
exists to prevent, just reintroduced via a different code path. Fixed by
including `idn_response` in `detect_scpi()`'s keyword check too, then
independently re-verified with a fresh synthetic-server test for that exact
scenario (now correctly classified `No Auth - SCPI/Instrument`) alongside a
counterpart test confirming a real OS shell that only reveals itself via
`*IDN?` still correctly classifies as the Critical bucket — i.e. both
directions of the fix hold at once.
