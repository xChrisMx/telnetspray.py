#!/usr/bin/env python3
# =============================================================================
# telnet_spray.py
#
# AUTHORIZED INTERNAL SECURITY ASSESSMENT TOOL
# Scope: Telnet (TCP/23) discovery and authentication-posture assessment on
#        internal company networks. Same two-phase masscan + worker-pool
#        architecture as ssh_vuln_scan.py / quantum_readiness_spray.py /
#        sslspray.py, rewritten from the original telnet_final_scan.sh.
#
# -----------------------------------------------------------------------------
# WHAT THIS SCRIPT DOES
# -----------------------------------------------------------------------------
# Phase 1 (Discovery): Uses masscan to rapidly identify hosts on the
#   configured internal subnets with a Telnet port open (see TELNET_PORTS
#   below). Same rationale as the sibling scripts: the configured scope
#   includes a /8, and pointing per-host probing at that much address space
#   directly would dominate the whole run.
#
# Phase 2 (Assessment): For every host discovered in Phase 1, a pool of
#   worker threads each run a hand-rolled raw-socket probe against that
#   host's Telnet port -- no nmap/nc subprocess, just Python sockets, since
#   a Telnet auth check is nothing more than "connect, read, maybe write,
#   read again." Three steps, each only attempted if the previous one didn't
#   already produce a definitive answer:
#     1. Passive banner -- whatever the device sends unprompted on connect.
#     2. Blank-credential active probe (CRLF CRLF) -- mirrors a human
#        hitting Enter twice at a blank prompt. A real interactive shell
#        handed over with no credentials answers this with its own prompt.
#     3. SCPI '*IDN?' active probe -- the standard IEEE-488.2 identification
#        query almost every SCPI-compliant test instrument answers.
#
# -----------------------------------------------------------------------------
# WHY THIS REWRITE EXISTS: SCPI INSTRUMENTS WERE BEING MISCATEGORIZED
# -----------------------------------------------------------------------------
# telnet_final_scan.sh's active-probe classifier treated ANY of
# `# $ > shell busybox root@ /bin cmd.exe` appearing in the blank-probe
# response as proof of a wide-open interactive shell. That's a reasonable
# signal for a real OS shell, but it also matches the single most common
# thing a SCPI test instrument's Telnet interface prints: a bare `>` prompt.
# SCPI instruments (oscilloscopes, power supplies, spectrum analyzers, etc.)
# routinely auto-connect an incoming Telnet session straight to their SCPI
# command parser with no login at all -- e.g. a real capture from one:
#
#     Welcome to K-N1912A-56015 - SCPI parser.
#
#     SCPI>
#
# That IS a "no authentication required" finding worth reporting -- but it
# is not the same finding as a Linux root shell handed out for free, and
# lumping them into one "CRITICAL, shell granted" bucket buried the signal
# a pentester actually needs: which of these no-auth hosts are exploitable
# general-purpose shells, and which are instruments behaving exactly as
# designed by their manufacturer (still worth flagging/restricting at the
# network layer, but a different remediation conversation). This script
# fixes that by classifying every no-auth host into one of two distinct
# buckets -- see CATEGORY DEFINITIONS below -- using two independent SCPI
# signals evaluated BEFORE the shell-prompt check ever runs:
#   (a) the literal word "SCPI" appearing anywhere in the passive banner or
#       blank-probe response (catches self-announcing instruments like the
#       one above directly, no active probing needed), and
#   (b) the device's response to an actively-sent `*IDN?` query matching the
#       standard SCPI identification format (comma-delimited
#       Manufacturer,Model,Serial,Firmware) or naming a known test-equipment
#       vendor (catches instruments that stay silent until asked).
# The shell-prompt regex itself was also tightened: it no longer treats a
# bare `>` occurring ANYWHERE in the captured text as a shell prompt (that
# was the original bug's actual root cause). It now requires either an
# explicit OS marker (busybox, root@, /bin/sh, cmd.exe, a Windows drive-letter
# prompt) or the LAST non-blank line of the response to look like a CLI
# prompt (`#`/`$`/`>`, optionally preceded by a hostname/username, e.g.
# `hostname#` or a bare `> ` alone -- both count, since a bare prompt
# character with no hostname is common on printers and some switches). What
# stops a SCPI instrument's bare `SCPI>` from being caught here isn't the
# shell regex at all -- it's that detect_scpi() runs first and already
# claimed it via the "SCPI" keyword.
#
# -----------------------------------------------------------------------------
# CATEGORY DEFINITIONS (assessment buckets, not official standards terms)
# -----------------------------------------------------------------------------
# NO AUTH - OS SHELL (Critical) - Blank credentials produced what looks like
#                      a general-purpose interactive OS shell (busybox,
#                      root@, /bin/sh, cmd.exe, or a CLI-style prompt) with
#                      no SCPI signal present. Immediately exploitable.
# NO AUTH - SCPI/INSTRUMENT - The device identifies itself as a SCPI parser
#                      (banner keyword or a valid `*IDN?` response) and
#                      grants command access with no login. Still a finding
#                      -- anyone on the network segment can send SCPI
#                      commands to the instrument -- but expected behavior
#                      by instrument design, not an OS-level compromise.
# AUTH REQUIRED      - A login/username/password prompt was observed, either
#                      in the initial banner or after a blank-credential
#                      probe or the `*IDN?` probe.
# LIKELY AUTH REQUIRED (Unclassified Banner) - A banner/response was
#                      received but matched none of the above. Manual
#                      review recommended.
# UNKNOWN / SILENT   - masscan confirmed the port open, but the device sent
#                      no response to the connection or either probe.
#
# -----------------------------------------------------------------------------
# NON-DESTRUCTIVE / SAFETY GUARANTEES
# -----------------------------------------------------------------------------
# No credentials of any kind are ever sent -- the "blank-credential" probe
# is exactly two carriage-return/linefeed pairs, nothing else. `*IDN?` is a
# standard, read-only IEEE-488.2 query defined for exactly this purpose (it
# does not change instrument state, start/stop a measurement, or alter any
# setting). No brute-forcing, no command execution beyond that one query,
# no data modification.
#
# THIS TOOL MUST ONLY BE RUN AGAINST NETWORKS YOU ARE EXPLICITLY AUTHORIZED
# TO ASSESS. Confirm written authorization / an active engagement scope
# before running this script.
#
# -----------------------------------------------------------------------------
# LIMITATIONS AND ASSUMPTIONS
# -----------------------------------------------------------------------------
#   - Requires `masscan` on PATH (unless `--skip-masscan` with a valid
#     `--masscan-output-file`). No nmap dependency for Phase 2 -- everything
#     is a plain Python socket, matching this tool's own "connect, read,
#     write, read" scope rather than pulling in a subprocess for it.
#   - `openpyxl` is only needed for the `.xlsx` step; its absence degrades to
#     CSV-only rather than failing the run.
#   - A masscan hit only proves the port is open, not that anything Telnet-
#     shaped is listening there -- an unrelated service squatting on TCP/23
#     will simply land in "Unknown / Silent" or "Likely Auth Required"
#     depending on what it happens to send back.
#   - Reverse DNS depends on corporate DNS infrastructure; failures resolve
#     to "" (blank) and do not stop the scan.
#   - SCPI detection via banner keyword is high-confidence (an instrument
#     that isn't a SCPI parser has no reason to print that word). SCPI
#     detection via `*IDN?` response FORMAT (comma-delimited fields) is a
#     secondary, lower-confidence signal, since it's inferring intent from
#     shape rather than an explicit self-identification -- a chatty non-SCPI
#     device that happens to echo back something comma-shaped in response to
#     an unrecognized command could false-positive here. Flag for
#     re-verification if a live run surfaces this.
#   - The tightened shell-prompt check still can't distinguish a real shell
#     from a device that happens to end its own (non-SCPI) banner in a
#     `word#`/`word$`/`word>`-shaped line for unrelated reasons -- rare, but
#     "Likely Auth Required" exists specifically to catch genuinely
#     ambiguous cases instead of forcing a guess; anything landing in
#     "No Auth - OS Shell" is still worth a human glance before treating it
#     as gospel.
#   - A bare prompt character with no hostname/username (e.g. a printer or
#     switch that just sends "> " on connect) is now caught as "No Auth - OS
#     Shell" rather than falling through to "Likely Auth Required" -- correct
#     for the common printer/network-gear case, but a genuine SCPI/test
#     instrument that (a) never prints the word "SCPI" anywhere and (b)
#     doesn't answer '*IDN?' with anything vendor-shaped would also land in
#     the shell bucket instead of the instrument one. IEEE-488.2 compliance
#     makes that combination rare in practice (nearly every real SCPI
#     instrument answers '*IDN?' usefully), but it's the residual edge case
#     this heuristic can't resolve.
#   - This heuristic still does not catch every no-auth device: a custom
#     menu-driven admin console (numbered options, no shell-style prompt
#     character at all) has no reliable marker to match against and lands in
#     "Likely Auth Required" for manual review rather than being
#     auto-flagged Critical -- broadening the match further to catch these
#     risks false-positiving on ordinary devices with unusual banners.
# =============================================================================

import argparse
import csv
import ipaddress
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR: str = os.path.dirname(os.path.abspath(__file__))

# Same subnets in scope as the sibling sweep tools. Edit this list to change
# scope.
SUBNETS: List[str] = [
    "1.0.0.0/16",
    "2.0.0.0/16",
    "3.0.0.0/16",
    "4.0.0.0/16",
    "5.0.0.0/16",
    # "0.0.0.0/16",
    "7.0.0.0/16",
    "8.0.0.0/12",
    "9.0.0.0/8",
]

# Telnet ports in scope. Edit this list to add alternate Telnet ports (e.g.
# 2323) -- masscan discovery, the port spec, and the "is this port in scope"
# checks all derive from it, same "edit this list" convention as SUBNETS.
TELNET_PORTS: List[int] = [23]

DEFAULT_WORKERS = 30    # raw-socket probing is lightweight (a handful of
                          # short reads/writes per host), same order of
                          # magnitude as quantum_readiness_spray.py's SSH
                          # raw-socket fallback.
DEFAULT_RATE = 25000     # masscan packets/sec, same default as the sibling tools
DEFAULT_TIMEOUT = 3.0    # seconds, per read step (connect + each of the 3 probes)
DEFAULT_RETRIES = 1

# -----------------------------------------------------------------------------
# Auth category buckets
# -----------------------------------------------------------------------------
AUTH_NO_AUTH_SHELL = "No Auth - OS Shell (Critical)"
AUTH_NO_AUTH_SCPI = "No Auth - SCPI/Instrument"
AUTH_REQUIRED = "Auth Required"
AUTH_LIKELY_REQUIRED = "Likely Auth Required (Unclassified Banner)"
AUTH_UNKNOWN_SILENT = "Unknown / Silent"

AUTH_ORDER = [AUTH_NO_AUTH_SHELL, AUTH_NO_AUTH_SCPI, AUTH_REQUIRED,
              AUTH_LIKELY_REQUIRED, AUTH_UNKNOWN_SILENT]

AUTH_EMOJI = {
    AUTH_NO_AUTH_SHELL: "\U0001F534",       # red circle
    AUTH_NO_AUTH_SCPI: "\U0001F7E0",        # orange circle
    AUTH_REQUIRED: "\U0001F7E2",            # green circle
    AUTH_LIKELY_REQUIRED: "\U0001F7E1",     # yellow circle
    AUTH_UNKNOWN_SILENT: "⚪",          # white circle
}

AUTH_FILL_HEX = {
    AUTH_NO_AUTH_SHELL: "FFC7CE",
    AUTH_NO_AUTH_SCPI: "FCE4D6",
    AUTH_REQUIRED: "C6EFCE",
    AUTH_LIKELY_REQUIRED: "FFEB9C",
    AUTH_UNKNOWN_SILENT: "E7E6E6",
}

AUTH_FONT_HEX = {
    AUTH_NO_AUTH_SHELL: "922B21",
    AUTH_NO_AUTH_SCPI: "784212",
    AUTH_REQUIRED: "1E6B2E",
    AUTH_LIKELY_REQUIRED: "7D6608",
    AUTH_UNKNOWN_SILENT: "5D6D7E",
}

# One-line, per-row "Meaning" text.
AUTH_MEANING = {
    AUTH_NO_AUTH_SHELL: ("CRITICAL - Device grants an interactive shell with no credentials. "
                          "Immediately exploitable remotely. Disable Telnet or restrict access "
                          "at the firewall."),
    AUTH_NO_AUTH_SCPI: ("No authentication required - device auto-connects Telnet sessions "
                         "directly to its SCPI command parser, by instrument design. Anyone on "
                         "the network segment can send it commands; restrict access at the "
                         "firewall/VLAN even though this isn't an OS-level compromise."),
    AUTH_REQUIRED: ("Auth enforced - Telnet is active and prompts for credentials. Verify no "
                     "default or weak passwords are in use and consider replacing Telnet with SSH."),
    AUTH_LIKELY_REQUIRED: ("Probably protected - banner/response received but auth state could "
                            "not be determined automatically. Manual review required to confirm."),
    AUTH_UNKNOWN_SILENT: ("Inconclusive - port is open but the device sent no response to the "
                           "connection or either probe. May be a non-standard Telnet "
                           "implementation or traffic-filtered. Manual inspection required."),
}

# Longer, paragraph-length text for the Overview sheet's category table.
AUTH_DESCRIPTION = {
    AUTH_NO_AUTH_SHELL: (
        "Blank credentials produced what looks like a general-purpose interactive OS shell "
        "(busybox, root@, /bin/sh, cmd.exe, or a CLI-style hostname prompt), with no SCPI "
        "signal present. This is the immediately-exploitable case: full command access, no "
        "credentials, no instrument context excusing it."
    ),
    AUTH_NO_AUTH_SCPI: (
        "The device identifies itself as a SCPI parser -- either the literal word 'SCPI' "
        "appears in its banner/response, or it answered an actively-sent '*IDN?' query with a "
        "standard vendor/model/serial/firmware identification string -- and grants command "
        "access with no login. This is expected behavior for most test instruments' Telnet "
        "interfaces, not a bug in the device, but it is still a 'no authentication' finding: "
        "anyone who can reach the port can send it SCPI commands."
    ),
    AUTH_REQUIRED: (
        "A login/username/password prompt was observed, either unprompted in the banner or "
        "after a blank-credential probe or the SCPI '*IDN?' probe. Telnet's own lack of "
        "encryption is still a finding worth raising, but the host is not open to anonymous access."
    ),
    AUTH_LIKELY_REQUIRED: (
        "A banner or probe response was received but didn't match a login prompt, a SCPI "
        "signal, or a shell prompt. Likely still protected, but not automatically confirmed -- "
        "flagged for a human to glance at rather than guessed."
    ),
    AUTH_UNKNOWN_SILENT: (
        "masscan confirmed TCP/23 is open, but the device didn't respond to the connection or "
        "either probe within the configured timeout. Could be a filtered/rate-limited path, a "
        "non-standard Telnet implementation, or a service that only responds to a specific "
        "client it's expecting."
    ),
}

# -----------------------------------------------------------------------------
# Vendor keyword detection
# -----------------------------------------------------------------------------
# Network/embedded-device keywords (ported from telnet_final_scan.sh's
# banner-keyword manufacturer detection). Order matters -- first match wins.
NETWORK_VENDOR_PATTERNS: List[Tuple[List[str], str]] = [
    (["cisco"], "Cisco Systems"),
    (["juniper", "junos"], "Juniper Networks"),
    (["huawei", "vrp"], "Huawei"),
    (["hp procurve", "procurve", "aruba"], "HP / Aruba Networks"),
    (["simatic", "siemens"], "Siemens"),
    (["schneider", "apc", "symmetra"], "Schneider Electric / APC"),
    (["busybox"], "BusyBox (embedded Linux)"),
    (["hikvision"], "Hikvision"),
    (["dahua"], "Dahua Technology"),
    (["mikrotik", "routeros"], "MikroTik"),
    (["ubiquiti", "edgeos", "unifi"], "Ubiquiti"),
    (["dell"], "Dell"),
    (["netgear"], "Netgear"),
    (["d-link", "dlink"], "D-Link"),
    (["zyxel"], "Zyxel"),
    (["linux"], "Linux-based device"),
    (["windows"], "Microsoft Windows"),
    (["freebsd", "openbsd", "netbsd"], "BSD-based device"),
]

# Test-equipment vendor keywords, used as a secondary SCPI-identification
# signal (see parse_scpi_idn() below).
INSTRUMENT_VENDOR_KEYWORDS: List[str] = [
    "keysight", "agilent", "hewlett-packard", "hewlett packard",
    "rohde", "schwarz", "tektronix", "anritsu", "yokogawa",
    "lecroy", "teledyne", "national instruments", "fluke",
    "siglent", "anapico", "advantest", "keithley", "chroma",
    "spirent", "viavi", "exfo", "b&k precision", "gw instek",
]


def detect_network_vendor(text: str) -> str:
    lower = text.lower()
    for keywords, name in NETWORK_VENDOR_PATTERNS:
        if any(kw in lower for kw in keywords):
            return name
    return ""


# =============================================================================
# CLASSIFICATION REGEXES
# =============================================================================

LOGIN_PROMPT_RE = re.compile(
    r"login\s*:|user\s*name\s*:|username\s*:|user\s*:|password\s*:|enter\s+password",
    re.IGNORECASE,
)

SCPI_KEYWORD_RE = re.compile(r"\bSCPI\b", re.IGNORECASE)

_SCPI_ERROR_HINTS_RE = re.compile(
    r"invalid|unknown\s+command|unrecognized|not\s+recognized|"
    r"command\s+not\s+found|bad\s+command|not\s+a\s+valid\s+command|syntax\s+error",
    re.IGNORECASE,
)

# Standard SCPI '*IDN?' reply shape: Manufacturer,Model,Serial,Firmware (2-4
# comma-delimited fields on one line). Used only as a secondary signal --
# the SCPI_KEYWORD_RE banner/response check above is primary and catches
# self-announcing instruments (see module docstring) without needing this at
# all.
_SCPI_IDN_FORMAT_RE = re.compile(r"^[^,\r\n]{1,64},[^,\r\n]{0,64}(?:,[^,\r\n]{0,64}){0,2}\s*$")

_SHELL_MARKERS_RE = re.compile(
    r"busybox|root@|/bin/(ba)?sh\b|cmd\.exe|[A-Za-z]:\\\S*>|\S+@\S+:",
    re.IGNORECASE,
)
# The marker check above also matches the ubiquitous non-root bash prompt
# prefix `user@host:` (e.g. "admin@switch:~$ ") via the trailing `\S+@\S+:`
# alternative -- that shape has two separators ('@' then ':') and a path
# segment, so it's caught by the marker regex even though the line-shape
# regex below only allows one separator character.
#
# A bare ">"/"$"/"#" with no hostname/username in front of it is allowed to
# match here (leading token is 0-32 chars, not 1-32) -- that shape is common
# on printers, print servers, and some switches with no default hostname set.
# This is deliberately NOT what protects against the original bash script's
# bug (a bare `>` anywhere in the text catching SCPI prompts like "SCPI>" as
# readily as a real shell prompt): that protection comes from detect_scpi()
# running BEFORE looks_like_shell() is ever called in probe_telnet() below,
# using the literal "SCPI" keyword and/or a valid '*IDN?' reply. A device
# that both uses a bare prompt character AND never identifies itself as SCPI
# in any way (no "SCPI" text, no usable '*IDN?' reply) will be classified as
# a shell rather than an instrument -- see LIMITATIONS in the module
# docstring.
_SHELL_PROMPT_LINE_RE = re.compile(r"^[\w\-.]{0,32}[@:]?[\w\-.]{0,32}[#$>]\s*$")


def looks_like_shell(text: str) -> bool:
    if not text:
        return False
    if _SHELL_MARKERS_RE.search(text):
        return True
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        return bool(_SHELL_PROMPT_LINE_RE.match(line))
    return False


def parse_scpi_idn(response: str) -> Tuple[bool, str, str]:
    """Returns (is_scpi, manufacturer, model) from a '*IDN?' probe response.
    Primary signal: known test-equipment vendor name anywhere in the reply.
    Secondary signal: the reply is shaped like the standard comma-delimited
    Manufacturer,Model,Serial,Firmware format AND doesn't read like a
    rejection/error message. See LIMITATIONS in the module docstring for why
    the secondary signal alone is lower-confidence."""
    if not response:
        return False, "", ""
    first_line = response.strip().splitlines()[0].strip() if response.strip() else ""
    if not first_line:
        return False, "", ""
    lower = first_line.lower()
    vendor_hit = any(kw in lower for kw in INSTRUMENT_VENDOR_KEYWORDS)
    format_hit = (
        bool(_SCPI_IDN_FORMAT_RE.match(first_line))
        and first_line.count(",") >= 1
        and not _SCPI_ERROR_HINTS_RE.search(first_line)
    )
    if vendor_hit or format_hit:
        parts = [p.strip() for p in first_line.split(",")]
        manufacturer = parts[0] if parts else ""
        model = parts[1] if len(parts) > 1 else ""
        return True, manufacturer, model
    return False, "", ""


def detect_scpi(banner: str, probe_response: str, idn_response: str) -> Tuple[bool, str, str, str]:
    """Returns (is_scpi, manufacturer, model, signal_description). Checks the
    high-confidence banner/response keyword signal first (catches
    self-announcing instruments like the K-N1912A-56015 example in the module
    docstring with no active probing needed), then falls back to the
    lower-confidence '*IDN?' response-format signal."""
    combined_passive = f"{banner} {probe_response} {idn_response}"
    if SCPI_KEYWORD_RE.search(combined_passive):
        _, manufacturer, model = parse_scpi_idn(idn_response)
        return True, manufacturer, model, "banner/response self-identifies as a SCPI parser"
    is_fmt, manufacturer, model = parse_scpi_idn(idn_response)
    if is_fmt:
        return True, manufacturer, model, "'*IDN?' probe returned a SCPI identification string"
    return False, "", "", ""


# =============================================================================
# TEXT SANITIZATION
# =============================================================================
# Banner/probe/IDN text is raw, untrusted bytes straight from the scanned
# device -- unlike the sibling scripts' nmap-XML-sourced fields, nothing here
# is XML-parsed first, so a hostile or simply broken device could otherwise
# send characters illegal in XML 1.0 (crashing .xlsx generation the same way
# a malformed reverse-DNS PTR record could -- see resolve_hostname() below)
# or an unbounded amount of data.

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_text(value: str, max_len: int = 2000) -> str:
    if not value:
        return ""
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = _CONTROL_CHAR_RE.sub("", value)
    value = value.strip()
    if len(value) > max_len:
        value = value[:max_len] + " ...(truncated)"
    return value


# CSV/Excel formula injection (CWE-1236): every free-text field here is
# attacker-controlled by design (it's literally what this tool audits), and
# opening the report in Excel/LibreOffice/Google Sheets is the tool's whole
# purpose. Prefixing a leading quote onto any value starting with a
# formula-trigger character forces plain-text interpretation, matching the
# fix already applied in sslspray.py.
_FORMULA_TRIGGER_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _neutralize_formula(value):
    if isinstance(value, str) and value.startswith(_FORMULA_TRIGGER_CHARS):
        return "'" + value
    return value


# =============================================================================
# LOGGING / PROGRESS DISPLAY (ported near-verbatim from the sibling scripts)
# =============================================================================

_progress_lock = threading.Lock()
_last_progress_len = 0


class ProgressAwareHandler(logging.StreamHandler):
    def emit(self, record: logging.LogRecord) -> None:
        global _last_progress_len
        with _progress_lock:
            if _last_progress_len:
                sys.stdout.write("\r" + " " * _last_progress_len + "\r")
                sys.stdout.flush()
            super().emit(record)
            _last_progress_len = 0


def setup_logging(log_path: str) -> logging.Logger:
    logger = logging.getLogger("telnet_spray")
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
    console_handler = ProgressAwareHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def draw_progress_line(line: str) -> None:
    global _last_progress_len
    with _progress_lock:
        pad = max(0, _last_progress_len - len(line))
        sys.stdout.write("\r" + line + (" " * pad))
        sys.stdout.flush()
        _last_progress_len = len(line)


def finish_progress_line() -> None:
    global _last_progress_len
    with _progress_lock:
        if _last_progress_len:
            sys.stdout.write("\n")
            sys.stdout.flush()
        _last_progress_len = 0


def fmt_elapsed(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def render_bar(pct: Optional[float], width: int = 30) -> str:
    if pct is None:
        return "[" + "-" * width + "]  n/a"
    pct = max(0.0, min(100.0, pct))
    filled = int(width * pct / 100.0)
    return "[" + "#" * filled + "-" * (width - filled) + f"] {pct:5.1f}%"


# =============================================================================
# DEPENDENCY / VALIDATION HELPERS (mirrors the sibling scripts)
# =============================================================================

def check_external_tool(name: str) -> Optional[str]:
    return shutil.which(name)


def validate_subnets(raw_subnets: List[str], logger: logging.Logger) -> List[ipaddress.IPv4Network]:
    networks = []
    for entry in raw_subnets:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            logger.error(f"Skipping invalid CIDR '{entry}': {exc}")
    return networks


def subnet_for_ip(ip: str, networks: List[ipaddress.IPv4Network]) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "UNKNOWN"
    for net in networks:
        if addr in net:
            return str(net)
    return "UNKNOWN"


def resolve_hostname(ip: str, timeout: float) -> str:
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return _sanitize_text(name)
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)


# =============================================================================
# PHASE 1: MASSCAN DISCOVERY (ported near-verbatim from the sibling scripts)
# =============================================================================

class MasscanStatus:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.percent: Optional[float] = None
        self.eta: str = ""

    def update_from_line(self, line: str) -> None:
        m = re.search(r"(\d+(?:\.\d+)?)%\s+done", line)
        eta_m = re.search(r"done,\s*([\d:]+)\s*remaining", line)
        with self.lock:
            if m:
                try:
                    self.percent = float(m.group(1))
                except ValueError:
                    pass
            if eta_m:
                self.eta = eta_m.group(1)


def _masscan_stderr_reader(proc: subprocess.Popen, status: MasscanStatus) -> None:
    buf = b""
    stream = proc.stderr
    if stream is None:
        return
    try:
        while True:
            chunk = stream.read(256)
            if not chunk:
                break
            buf += chunk
            while True:
                idx_r = buf.find(b"\r")
                idx_n = buf.find(b"\n")
                candidates = [i for i in (idx_r, idx_n) if i != -1]
                if not candidates:
                    break
                idx = min(candidates)
                line = buf[:idx].decode(errors="ignore").strip()
                buf = buf[idx + 1:]
                if line:
                    status.update_from_line(line)
    except (ValueError, OSError):
        pass


def build_masscan_command(masscan_path: str, subnets: List[str], rate: int,
                           output_file: str, interface: Optional[str],
                           ports: List[int]) -> List[str]:
    port_spec = "T:" + ",".join(str(p) for p in ports)
    cmd = [masscan_path, "-p", port_spec, "--rate", str(rate), "-oL", output_file]
    if interface:
        cmd += ["-e", interface]
    cmd += subnets
    return cmd


def parse_masscan_list_output(path: str, start_offset: int = 0) -> Tuple[List[Tuple[str, int, str]], int]:
    records: List[Tuple[str, int, str]] = []
    if not os.path.exists(path):
        return records, start_offset
    with open(path, "rb") as f:
        f.seek(start_offset)
        chunk = f.read()
    if not chunk:
        return records, start_offset
    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        return records, start_offset
    usable, new_offset = chunk[:last_newline + 1], start_offset + last_newline + 1
    for raw_line in usable.split(b"\n"):
        line = raw_line.decode(errors="ignore").strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        status, proto, port_s, ip, _ts = parts[:5]
        if status != "open":
            continue
        try:
            port = int(port_s)
        except ValueError:
            continue
        records.append((ip, port, proto))
    return records, new_offset


def run_masscan_phase1(masscan_path: str, subnets: List[str], rate: int,
                        output_file: str, interface: Optional[str],
                        ports: List[int], logger: logging.Logger,
                        stop_event: threading.Event
                        ) -> List[Tuple[str, int, str]]:
    cmd = build_masscan_command(masscan_path, subnets, rate, output_file, interface, ports)
    logger.info("Phase 1 - DISCOVERY starting")
    logger.debug(f"Masscan command: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except FileNotFoundError:
        logger.error(f"masscan executable not found at '{masscan_path}'.")
        return []
    except PermissionError as exc:
        logger.error(f"Permission error launching masscan: {exc}. "
                      f"Masscan typically requires root/administrator privileges.")
        return []
    except OSError as exc:
        logger.error(f"Failed to launch masscan: {exc}")
        return []

    status = MasscanStatus()
    reader_thread = threading.Thread(target=_masscan_stderr_reader, args=(proc, status), daemon=True)
    reader_thread.start()

    port_set = set(ports)
    start_time = time.time()
    telnet_count = 0
    offset = 0
    seen: set = set()

    def _drain_new_records() -> None:
        nonlocal offset, telnet_count
        new_records, offset = parse_masscan_list_output(output_file, offset)
        for ip, port, _proto in new_records:
            key = (ip, port)
            if key in seen:
                continue
            seen.add(key)
            if port in port_set:
                telnet_count += 1

    try:
        while True:
            if stop_event.is_set():
                logger.warning("Interrupt received, terminating masscan...")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break

            retcode = proc.poll()
            _drain_new_records()

            elapsed = time.time() - start_time
            with status.lock:
                pct = status.percent
                eta = status.eta

            bar = render_bar(pct)
            eta_str = eta if eta else "n/a"
            line = (f"Phase 1 - DISCOVERY {bar} | Telnet hosts found: {telnet_count} | "
                     f"Elapsed: {fmt_elapsed(elapsed)} | ETA: {eta_str}")
            draw_progress_line(line)

            if retcode is not None:
                time.sleep(0.3)
                _drain_new_records()
                break
            time.sleep(0.5)
    finally:
        finish_progress_line()

    if proc.returncode not in (0, None) and not stop_event.is_set():
        logger.warning(f"masscan exited with return code {proc.returncode}. "
                        f"Results collected so far will still be used.")

    final_records, _ = parse_masscan_list_output(output_file, 0)
    logger.info(f"Phase 1 - DISCOVERY complete. Telnet-port hits: {telnet_count}, "
                f"elapsed: {fmt_elapsed(time.time() - start_time)}")
    return final_records


# =============================================================================
# PHASE 2: RAW-SOCKET TELNET AUTH PROBE
# =============================================================================

@dataclass
class DiscoveredHost:
    ip: str
    hostname: str = ""
    subnet: str = "UNKNOWN"
    ports: List[int] = field(default_factory=list)


@dataclass
class ProbeResult:
    auth_category: str
    banner: str = ""
    probe_response: str = ""
    idn_response: str = ""
    manufacturer: str = ""
    instrument_model: str = ""
    notes: str = ""
    probe_method: str = ""
    scan_status: str = "Completed"


@dataclass
class TelnetRecord:
    scan_date: str
    ip: str
    hostname: str
    subnet: str
    port: int
    banner: str
    probe_response: str
    idn_response: str
    manufacturer: str
    instrument_model: str
    auth_category: str
    notes: str
    probe_method: str
    meaning: str
    scan_status: str = "Completed"


CSV_FIELDS = ["Scan Date", "IP Address", "Hostname", "Subnet Range", "Port",
              "Banner", "Probe Response", "SCPI IDN Response", "Manufacturer",
              "Instrument Model", "Auth Category", "Notes", "Probe Method",
              "Meaning", "Scan Status"]


def record_to_row(r: TelnetRecord) -> Dict[str, object]:
    return {
        "Scan Date": r.scan_date, "IP Address": r.ip, "Hostname": r.hostname,
        "Subnet Range": r.subnet, "Port": r.port, "Banner": r.banner,
        "Probe Response": r.probe_response, "SCPI IDN Response": r.idn_response,
        "Manufacturer": r.manufacturer, "Instrument Model": r.instrument_model,
        "Auth Category": r.auth_category, "Notes": r.notes,
        "Probe Method": r.probe_method, "Meaning": r.meaning,
        "Scan Status": r.scan_status,
    }


def _recv_available(sock: socket.socket, window: float, max_bytes: int = 8192) -> bytes:
    # `window` is a wall-clock deadline for this whole read step, not a
    # per-recv() timeout -- a peer trickling single bytes just under the
    # timeout interval must not be able to keep the loop (and a worker
    # thread) alive indefinitely.
    deadline = time.monotonic() + window
    data = b""
    try:
        while len(data) < max_bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    except OSError:
        pass
    return data


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", errors="ignore")


def probe_telnet(ip: str, port: int, timeout: float) -> ProbeResult:
    """Raw-socket Telnet auth probe. See the module docstring's
    CATEGORY DEFINITIONS / WHY THIS REWRITE EXISTS sections for the full
    reasoning behind the classification order below."""
    sock = None
    banner = probe_response = idn_response = ""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)

        banner = _sanitize_text(_decode(_recv_available(sock, timeout)))
        login_found_in: Optional[str] = "banner" if LOGIN_PROMPT_RE.search(banner) else None

        if login_found_in is None:
            try:
                sock.sendall(b"\r\n\r\n")
            except OSError:
                pass
            probe_response = _sanitize_text(_decode(_recv_available(sock, timeout)))
            if LOGIN_PROMPT_RE.search(probe_response):
                login_found_in = "blank-credential probe"

        if login_found_in is None:
            try:
                sock.sendall(b"*IDN?\r\n")
            except OSError:
                pass
            idn_response = _sanitize_text(_decode(_recv_available(sock, timeout)))
            if LOGIN_PROMPT_RE.search(idn_response):
                login_found_in = "SCPI '*IDN?' probe"

        combined = " ".join(t for t in (banner, probe_response, idn_response) if t)
        vendor = detect_network_vendor(combined)

        if login_found_in:
            return ProbeResult(
                auth_category=AUTH_REQUIRED, banner=banner, probe_response=probe_response,
                idn_response=idn_response, manufacturer=vendor or "Unknown",
                notes=f"Login prompt detected ({login_found_in}).",
                probe_method="banner" if login_found_in == "banner" else "active-probe",
            )

        is_scpi, scpi_manuf, scpi_model, scpi_signal = detect_scpi(banner, probe_response, idn_response)
        if is_scpi:
            return ProbeResult(
                auth_category=AUTH_NO_AUTH_SCPI, banner=banner, probe_response=probe_response,
                idn_response=idn_response, manufacturer=scpi_manuf or "Unknown (SCPI)",
                instrument_model=scpi_model,
                notes=f"No login required - {scpi_signal}.",
                probe_method="scpi-probe",
            )

        if looks_like_shell(probe_response) or looks_like_shell(banner) or looks_like_shell(idn_response):
            return ProbeResult(
                auth_category=AUTH_NO_AUTH_SHELL, banner=banner, probe_response=probe_response,
                idn_response=idn_response, manufacturer=vendor or "Unknown",
                notes="Interactive shell prompt granted without credentials.",
                probe_method="active-probe",
            )

        if banner or probe_response or idn_response:
            return ProbeResult(
                auth_category=AUTH_LIKELY_REQUIRED, banner=banner, probe_response=probe_response,
                idn_response=idn_response, manufacturer=vendor or "Unknown",
                notes=("Banner/response received but matched neither a login prompt, SCPI "
                       "identification, nor a shell prompt - manual review recommended."),
                probe_method="banner",
            )

        return ProbeResult(
            auth_category=AUTH_UNKNOWN_SILENT, manufacturer="Unknown",
            notes="Port open but device sent no response to connection or probes.",
            probe_method="silent",
        )

    except socket.timeout:
        return ProbeResult(auth_category=AUTH_UNKNOWN_SILENT, notes="Connection/read timed out.",
                            probe_method="error", scan_status="No Response")
    except ConnectionRefusedError:
        return ProbeResult(auth_category=AUTH_UNKNOWN_SILENT, notes="Connection refused.",
                            probe_method="error", scan_status="No Response")
    except OSError as exc:
        return ProbeResult(auth_category=AUTH_UNKNOWN_SILENT, notes=f"Error during probe: {exc}",
                            probe_method="error", scan_status="Error")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def audit_one_port(host: DiscoveredHost, port: int, args: argparse.Namespace) -> TelnetRecord:
    scan_date = datetime.now().strftime("%Y-%m-%d")
    result = ProbeResult(auth_category=AUTH_UNKNOWN_SILENT, scan_status="No Response")
    # Only "No Response" (timeout/refused) is worth retrying -- a clean read
    # that simply came back empty is a deterministic property of the host,
    # not a transient miss, same "only retry No Response" rule the sibling
    # scripts use for their own retry loops.
    for _attempt in range(max(1, args.retries + 1)):
        try:
            result = probe_telnet(host.ip, port, args.timeout)
        except Exception as exc:  # noqa: BLE001 - one bad host must not kill the scan
            result = ProbeResult(auth_category=AUTH_UNKNOWN_SILENT, notes=f"Unhandled error: {exc}",
                                  probe_method="error", scan_status="Error")
        if result.scan_status != "No Response":
            break
    return TelnetRecord(
        scan_date=scan_date, ip=host.ip, hostname=host.hostname, subnet=host.subnet,
        port=port, banner=result.banner, probe_response=result.probe_response,
        idn_response=result.idn_response, manufacturer=result.manufacturer or "Unknown",
        instrument_model=result.instrument_model, auth_category=result.auth_category,
        notes=result.notes, probe_method=result.probe_method,
        meaning=AUTH_MEANING.get(result.auth_category, ""), scan_status=result.scan_status,
    )


def audit_one_host(host: DiscoveredHost, args: argparse.Namespace) -> List[TelnetRecord]:
    try:
        return [audit_one_port(host, port, args) for port in host.ports]
    except Exception as exc:  # noqa: BLE001
        return [TelnetRecord(
            scan_date=datetime.now().strftime("%Y-%m-%d"), ip=host.ip, hostname=host.hostname,
            subnet=host.subnet, port=host.ports[0] if host.ports else 0, banner="",
            probe_response="", idn_response="", manufacturer="Unknown", instrument_model="",
            auth_category=AUTH_UNKNOWN_SILENT, notes=f"audit_one_host failed unexpectedly: {exc}",
            probe_method="error", meaning=AUTH_MEANING[AUTH_UNKNOWN_SILENT], scan_status="Error",
        )]


@dataclass
class Phase2Stats:
    lock: threading.Lock = field(default_factory=threading.Lock)
    total: int = 0
    completed: int = 0
    active_workers: int = 0
    category_counts: Dict[str, int] = field(default_factory=lambda: {c: 0 for c in AUTH_ORDER})


def render_phase2_line(stats: Phase2Stats, start_time: float) -> str:
    with stats.lock:
        completed = stats.completed
        total = stats.total
        active = stats.active_workers
        rc = dict(stats.category_counts)
    pct = (completed / total * 100.0) if total else 0.0
    elapsed = time.time() - start_time
    if 0 < completed < total:
        eta = fmt_elapsed((elapsed / completed) * (total - completed))
    elif completed >= total and total > 0:
        eta = "00:00:00"
    else:
        eta = "n/a"
    bar = render_bar(pct)
    return (f"Phase 2 - TELNET AUDIT {bar} | Completed: {completed}/{total} | "
            f"Workers: {active} | Shell:{rc[AUTH_NO_AUTH_SHELL]} SCPI:{rc[AUTH_NO_AUTH_SCPI]} "
            f"Auth:{rc[AUTH_REQUIRED]} Likely:{rc[AUTH_LIKELY_REQUIRED]} "
            f"Unknown:{rc[AUTH_UNKNOWN_SILENT]} | Elapsed: {fmt_elapsed(elapsed)} | ETA: {eta}")


def run_phase2(hosts: List[DiscoveredHost], args: argparse.Namespace,
               logger: logging.Logger, stop_event: threading.Event) -> List[TelnetRecord]:
    stats = Phase2Stats()
    stats.total = len(hosts)
    records: List[TelnetRecord] = []
    start_time = time.time()
    logger.info(f"Phase 2 - TELNET AUDIT starting ({stats.total} hosts, {args.workers} workers)")

    def wrapped(host: DiscoveredHost) -> List[TelnetRecord]:
        with stats.lock:
            stats.active_workers += 1
        try:
            return audit_one_host(host, args)
        finally:
            with stats.lock:
                stats.active_workers -= 1

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {executor.submit(wrapped, host): host for host in hosts}
        try:
            for future in as_completed(futures):
                host_records = future.result()
                with stats.lock:
                    stats.completed += 1
                    for rec in host_records:
                        stats.category_counts[rec.auth_category] += 1
                records.extend(host_records)
                draw_progress_line(render_phase2_line(stats, start_time))
                if stop_event.is_set():
                    logger.warning("Interrupt received, cancelling remaining audits...")
                    for f in futures:
                        f.cancel()
                    break
        finally:
            finish_progress_line()

    logger.info(f"Phase 2 - TELNET AUDIT complete. {stats.completed}/{stats.total} hosts "
                f"probed, finished in {fmt_elapsed(time.time() - start_time)}.")
    return records


# =============================================================================
# CSV
# =============================================================================

def write_csv_report(records: List[TelnetRecord], path: str, logger: logging.Logger) -> None:
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for record in records:
                row = record_to_row(record)
                for key in ("Hostname", "Banner", "Probe Response", "SCPI IDN Response",
                            "Manufacturer", "Instrument Model", "Notes", "Meaning"):
                    row[key] = _neutralize_formula(row[key])
                writer.writerow(row)
        logger.info(f"CSV report written to {path}")
    except OSError as exc:
        logger.error(f"Failed to write CSV report to {path}: {exc}")


def _csv_field(r: dict, key: str, default: str = "") -> str:
    return r.get(key) or default


def read_rows_from_csv(csv_path: str, logger: logging.Logger) -> List[TelnetRecord]:
    records: List[TelnetRecord] = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            try:
                port = int(_csv_field(r, "Port", "23"))
            except ValueError:
                port = 23
            # A blank/missing cell defaults to AUTH_UNKNOWN_SILENT (already a
            # valid AUTH_ORDER bucket); a non-blank but unrecognized string
            # (hand-edit, typo, or a different tool version's category name)
            # is coerced to AUTH_LIKELY_REQUIRED and logged instead of being
            # stored verbatim, since it would otherwise crash
            # compute_category_stats()/build_workbook() with a KeyError.
            raw_auth_category = _csv_field(r, "Auth Category", AUTH_UNKNOWN_SILENT)
            if raw_auth_category not in AUTH_ORDER:
                logger.warning(
                    f"Unrecognized Auth Category '{raw_auth_category}' for "
                    f"{_csv_field(r, 'IP Address')} in {csv_path}; "
                    f"defaulting to '{AUTH_LIKELY_REQUIRED}'.")
                raw_auth_category = AUTH_LIKELY_REQUIRED
            records.append(TelnetRecord(
                scan_date=_csv_field(r, "Scan Date"), ip=_csv_field(r, "IP Address"),
                hostname=_sanitize_text(_csv_field(r, "Hostname")), subnet=_csv_field(r, "Subnet Range", "UNKNOWN"),
                port=port, banner=_sanitize_text(_csv_field(r, "Banner")),
                probe_response=_sanitize_text(_csv_field(r, "Probe Response")),
                idn_response=_sanitize_text(_csv_field(r, "SCPI IDN Response")),
                manufacturer=_sanitize_text(_csv_field(r, "Manufacturer", "Unknown")),
                instrument_model=_sanitize_text(_csv_field(r, "Instrument Model")),
                auth_category=raw_auth_category,
                notes=_sanitize_text(_csv_field(r, "Notes")), probe_method=_csv_field(r, "Probe Method"),
                meaning=AUTH_MEANING.get(raw_auth_category, _sanitize_text(_csv_field(r, "Meaning"))),
                scan_status=_csv_field(r, "Scan Status", "Completed"),
            ))
    return records


# =============================================================================
# XLSX
# =============================================================================

def compute_category_stats(records: List[TelnetRecord]) -> Dict[str, int]:
    counts = {c: 0 for c in AUTH_ORDER}
    for rec in records:
        counts[rec.auth_category if rec.auth_category in counts else AUTH_UNKNOWN_SILENT] += 1
    return counts


def build_workbook(records: List[TelnetRecord], networks: List[ipaddress.IPv4Network]):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    def fill(hex_color: str):
        return PatternFill("solid", fgColor=hex_color)

    def thin_border():
        s = Side(style="thin", color="D5D8DC")
        return Border(left=s, right=s, top=s, bottom=s)

    wb = Workbook()

    # --- Overview sheet ---
    ov = wb.active
    ov.title = "Overview"
    ov.sheet_view.showGridLines = False
    ov.column_dimensions["A"].width = 34
    ov.column_dimensions["B"].width = 70
    ov.column_dimensions["C"].width = 14

    ov.append(["Telnet Authentication-Posture Assessment"])
    ov["A1"].font = Font(bold=True, size=14)
    ov.append([f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M')}"])
    ov.append([f"Configured subnets in scope: {len(networks)}"])
    ov.append([f"Configured Telnet ports in scope: {', '.join(str(p) for p in TELNET_PORTS)}"])
    ov.append([])

    ov.append(["How to read this report"])
    ov[f"A{ov.max_row}"].font = Font(bold=True, size=12)
    ov.append(["No-authentication Telnet hosts are split into two categories on purpose: a "
               "general-purpose OS shell handed out for free is a different, more urgent "
               "problem than a test instrument auto-connecting to its own SCPI command parser "
               "(expected behavior by instrument design, but still worth restricting at the "
               "network layer). See the category table below."])
    ov.cell(row=ov.max_row, column=1).alignment = Alignment(wrap_text=True, vertical="top")
    ov.merge_cells(start_row=ov.max_row, start_column=1, end_row=ov.max_row, end_column=3)
    ov.row_dimensions[ov.max_row].height = 55
    ov.append([])

    ov.append(["Category", "What it means"])
    for cell in ov[ov.max_row]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = fill("2C3E50")
    for category in AUTH_ORDER:
        ov.append([f"{AUTH_EMOJI[category]} {category}", AUTH_DESCRIPTION[category]])
        row = ov.max_row
        ov.cell(row=row, column=1).fill = fill(AUTH_FILL_HEX[category])
        ov.cell(row=row, column=1).font = Font(color=AUTH_FONT_HEX[category], bold=True)
        ov.cell(row=row, column=2).alignment = Alignment(wrap_text=True, vertical="top")
        ov.row_dimensions[row].height = 60
    ov.append([])

    ov.append(["Methodology notes"])
    ov[f"A{ov.max_row}"].font = Font(bold=True, size=12)
    for note in [
        "Phase 1 (masscan) finds every host with a configured Telnet port open. Phase 2 runs a "
        "hand-rolled raw-socket probe against each one: read the initial banner; send a blank "
        "credential (CRLF CRLF) and read the response; send the standard SCPI '*IDN?' "
        "identification query and read the response. Each step only runs if the previous one "
        "didn't already reveal a login prompt.",
        "SCPI detection is checked BEFORE the shell-prompt check, using two signals: the word "
        "'SCPI' appearing in the banner or blank-probe response (high confidence -- catches "
        "self-announcing instruments immediately), or a '*IDN?' reply shaped like the standard "
        "Manufacturer,Model,Serial,Firmware format or naming a known test-equipment vendor "
        "(lower confidence). This ordering is what keeps a SCPI instrument's bare '>' prompt "
        "from being counted as a critical open shell.",
        "No credentials are ever sent. '*IDN?' is a standard, read-only IEEE-488.2 query that "
        "does not change instrument state.",
    ]:
        ov.append([note])
        ov.cell(row=ov.max_row, column=1).alignment = Alignment(wrap_text=True, vertical="top")
        ov.merge_cells(start_row=ov.max_row, start_column=1, end_row=ov.max_row, end_column=3)
        ov.row_dimensions[ov.max_row].height = 55
    ov.append([])

    total = len(records)
    counts = compute_category_stats(records)
    ov.append(["Scan Summary"])
    ov[f"A{ov.max_row}"].font = Font(bold=True, size=12)
    ov.append(["Total Telnet hosts found:", total])
    ov.append(["Category", "Count", "% of Total"])
    for cell in ov[ov.max_row]:
        cell.font = Font(bold=True)
    for category in AUTH_ORDER:
        pct = (counts[category] / total * 100.0) if total else 0.0
        ov.append([f"{AUTH_EMOJI[category]} {category}", counts[category], round(pct, 1)])
        ov.cell(row=ov.max_row, column=1).fill = fill(AUTH_FILL_HEX[category])
        ov.cell(row=ov.max_row, column=3).number_format = "0.0"
    no_auth_total = counts[AUTH_NO_AUTH_SHELL] + counts[AUTH_NO_AUTH_SCPI]
    no_auth_pct = (no_auth_total / total * 100.0) if total else 0.0
    ov.append([f"That means: {no_auth_pct:.1f}% of Telnet hosts found require no authentication "
               f"at all ({counts[AUTH_NO_AUTH_SHELL]} OS shell, {counts[AUTH_NO_AUTH_SCPI]} SCPI/instrument)."])
    ov.cell(row=ov.max_row, column=1).font = Font(bold=True, italic=True)
    ov.merge_cells(start_row=ov.max_row, start_column=1, end_row=ov.max_row, end_column=3)
    ov.append([])

    # Subnet breakdown
    def subnet_key(r: TelnetRecord) -> str:
        return r.subnet
    subnet_counts: Dict[str, int] = {}
    for r in records:
        subnet_counts[subnet_key(r)] = subnet_counts.get(subnet_key(r), 0) + 1
    ov.append(["Subnet Breakdown"])
    ov[f"A{ov.max_row}"].font = Font(bold=True, size=12)
    for subnet, count in sorted(subnet_counts.items()):
        ov.append([subnet, count])

    # --- Scan Results sheet ---
    wr = wb.create_sheet("Scan Results")
    wr.sheet_view.showGridLines = False
    wr.freeze_panes = "A2"

    widths = {"Scan Date": 12, "IP Address": 16, "Hostname": 26, "Subnet Range": 18,
              "Port": 7, "Banner": 34, "Probe Response": 30, "SCPI IDN Response": 30,
              "Manufacturer": 22, "Instrument Model": 18, "Auth Category": 30,
              "Notes": 40, "Probe Method": 16, "Meaning": 50, "Scan Status": 14}
    wrap_cols = {"Banner", "Probe Response", "SCPI IDN Response", "Notes", "Meaning"}

    for col_idx, col_name in enumerate(CSV_FIELDS, start=1):
        c = wr.cell(row=1, column=col_idx, value=col_name)
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = fill("2C3E50")
        c.alignment = Alignment(horizontal="center", vertical="center")
        c.border = thin_border()
        wr.column_dimensions[get_column_letter(col_idx)].width = widths.get(col_name, 16)
    wr.row_dimensions[1].height = 22

    auth_col = CSV_FIELDS.index("Auth Category") + 1
    for row_idx, record in enumerate(records, start=2):
        row = record_to_row(record)
        for col_idx, key in enumerate(CSV_FIELDS, start=1):
            val = row[key]
            if key in ("Hostname", "Banner", "Probe Response", "SCPI IDN Response",
                       "Manufacturer", "Instrument Model", "Notes", "Meaning"):
                val = _neutralize_formula(val)
            c = wr.cell(row=row_idx, column=col_idx, value=val)
            c.border = thin_border()
            c.alignment = Alignment(vertical="top", wrap_text=(key in wrap_cols), horizontal="left")
        cat = record.auth_category if record.auth_category in AUTH_ORDER else AUTH_UNKNOWN_SILENT
        cell = wr.cell(row=row_idx, column=auth_col)
        cell.value = f"{AUTH_EMOJI[cat]} {cat}"
        for col_idx in range(1, len(CSV_FIELDS) + 1):
            wr.cell(row=row_idx, column=col_idx).fill = fill(AUTH_FILL_HEX[cat])
        wr.row_dimensions[row_idx].height = 40

    if records:
        wr.auto_filter.ref = f"A1:{get_column_letter(len(CSV_FIELDS))}{len(records) + 1}"

    return wb


def write_xlsx_report(records: List[TelnetRecord], networks: List[ipaddress.IPv4Network],
                       path: str, logger: logging.Logger) -> None:
    try:
        wb = build_workbook(records, networks)
    except ImportError:
        logger.warning("openpyxl not installed - skipping .xlsx generation. "
                        "Install with: pip install openpyxl")
        return
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Failed to build XLSX workbook: {exc}")
        return
    try:
        wb.save(path)
        logger.info(f"XLSX report written to {path} ({len(records)} host(s))")
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Failed to write XLSX report to {path}: {exc}")


# =============================================================================
# MAIN
# =============================================================================

def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Authorized internal Telnet authentication-posture assessment.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--rate", type=int, default=DEFAULT_RATE)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                         help="Per read step (connect + each of the 3 probes), in seconds")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--output-dir", type=str, default=SCRIPT_DIR)
    parser.add_argument("--masscan-path", type=str, default="masscan")
    parser.add_argument("--interface", type=str, default=None)
    parser.add_argument("--skip-masscan", action="store_true")
    parser.add_argument("--masscan-output-file", type=str, default=None)
    parser.add_argument("--no-xlsx", action="store_true")
    parser.add_argument("--csv-out", type=str, default=None)
    parser.add_argument("--xlsx-out", type=str, default=None)
    parser.add_argument("--from-csv", metavar="FILE",
                         help="Skip scanning entirely; rebuild the .xlsx from an existing CSV")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    scan_date = datetime.now().strftime("%Y-%m-%d")
    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except OSError as exc:
        print(f"ERROR: Could not create output directory '{args.output_dir}': {exc}", file=sys.stderr)
        return 1

    log_path = os.path.join(args.output_dir, f"telnet_spray_{scan_date}.log")
    csv_path = args.csv_out or os.path.join(args.output_dir, f"telnet_spray_{scan_date}.csv")
    xlsx_path = args.xlsx_out or os.path.join(args.output_dir, f"telnet_spray_{scan_date}.xlsx")

    try:
        logger = setup_logging(log_path)
    except OSError as exc:
        print(f"ERROR: Could not open log file '{log_path}': {exc}", file=sys.stderr)
        return 1

    networks = validate_subnets(SUBNETS, logger)

    if args.from_csv:
        records = read_rows_from_csv(args.from_csv, logger)
        if not args.no_xlsx:
            write_xlsx_report(records, networks, xlsx_path, logger)
        return 0

    stop_event = threading.Event()

    def handle_sigint(signum, frame):  # noqa: ANN001
        if stop_event.is_set():
            logger.warning("Second interrupt received, forcing exit.")
            sys.exit(130)
        logger.warning("Ctrl+C received - finishing current work and writing "
                        "partial reports. Press Ctrl+C again to force exit.")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    logger.info("=" * 70)
    logger.info("AUTHORIZED TELNET AUTHENTICATION-POSTURE ASSESSMENT")
    logger.info("=" * 70)
    logger.info("Configured subnets in scope:")
    for s in SUBNETS:
        logger.info(f"  - {s}")
    logger.info(f"Configured Telnet ports in scope: {', '.join(str(p) for p in TELNET_PORTS)}")
    logger.info(f"Workers: {args.workers} | Masscan rate: {args.rate} | "
                f"Timeout: {args.timeout}s | Retries: {args.retries}")

    if not networks:
        logger.error("No valid subnets configured. Exiting.")
        return 1

    masscan_path = check_external_tool(args.masscan_path) or args.masscan_path
    if not args.skip_masscan and check_external_tool(args.masscan_path) is None:
        logger.error(f"Required tool '{args.masscan_path}' was not found on PATH.")
        return 1

    raw_records: List[Tuple[str, int, str]] = []
    if args.skip_masscan:
        if not args.masscan_output_file or not os.path.exists(args.masscan_output_file):
            logger.error("--skip-masscan requires a valid --masscan-output-file.")
            return 1
        raw_records, _ = parse_masscan_list_output(args.masscan_output_file, 0)
    else:
        masscan_out = args.masscan_output_file or os.path.join(
            args.output_dir, f".masscan_output_{scan_date}.txt")
        try:
            raw_records = run_masscan_phase1(masscan_path, SUBNETS, args.rate, masscan_out,
                                              args.interface, TELNET_PORTS, logger, stop_event)
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Phase 1 discovery failed unexpectedly: {exc}")
            raw_records = []

    port_set = set(TELNET_PORTS)
    ports_by_ip: Dict[str, set] = {}
    for ip, port, _proto in raw_records:
        if port not in port_set:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"Skipping malformed IP address from scan output: {ip}")
            continue
        ports_by_ip.setdefault(ip, set()).add(port)

    logger.info(f"Discovered {len(ports_by_ip)} unique host(s) with a Telnet port open after deduplication.")

    hosts: List[DiscoveredHost] = []
    for ip, ports in ports_by_ip.items():
        if stop_event.is_set():
            break
        hostname = resolve_hostname(ip, timeout=2.0)
        subnet = subnet_for_ip(ip, networks)
        hosts.append(DiscoveredHost(ip=ip, hostname=hostname, subnet=subnet, ports=sorted(ports)))

    records: List[TelnetRecord] = []
    if hosts:
        # Deliberately not gated on "and not stop_event.is_set()" - Ctrl+C
        # during the hostname-resolution loop above can set stop_event
        # while hosts is already non-empty, and run_phase2() itself already
        # honors stop_event correctly (cancels remaining futures, returns
        # whatever completed). Gating here too meant those already-resolved
        # hosts were silently dropped and Phase 2 never ran at all, so a
        # scan interrupted at exactly that point wrote an empty report -
        # contradicting the SIGINT handler's own "finishing current work
        # and writing partial reports" message.
        records = run_phase2(hosts, args, logger, stop_event)
    else:
        logger.info("No hosts with a Telnet port open discovered; skipping Phase 2 audit.")

    write_csv_report(records, csv_path, logger)
    if not args.no_xlsx:
        write_xlsx_report(records, networks, xlsx_path, logger)

    counts = compute_category_stats(records)
    logger.info("=" * 70)
    logger.info("SCAN SUMMARY")
    logger.info(f"  Telnet hosts found: {len(records)} | "
                f"No Auth - OS Shell: {counts[AUTH_NO_AUTH_SHELL]} | "
                f"No Auth - SCPI/Instrument: {counts[AUTH_NO_AUTH_SCPI]} | "
                f"Auth Required: {counts[AUTH_REQUIRED]} | "
                f"Likely Auth Required: {counts[AUTH_LIKELY_REQUIRED]} | "
                f"Unknown/Silent: {counts[AUTH_UNKNOWN_SILENT]}")
    logger.info("=" * 70)
    logger.info(f"Reports written to: {os.path.abspath(args.output_dir)}")

    if stop_event.is_set():
        logger.warning("Scan was interrupted by user; reports reflect partial results.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
