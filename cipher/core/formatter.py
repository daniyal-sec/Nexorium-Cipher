"""
formatter.py

Presentation layer for Nexorium-Cipher.

This module turns the analysis result dictionary produced by
identify_file() (and the Finding dicts inside it) into a readable,
professional, cybersecurity-analyst-style terminal report.

It does not perform any hashing, file identification, or evidence
analysis itself, and it never changes the data it is given. Its only
job is to present result["..."] fields more clearly.

Public API (unchanged from the previous version):
    format_timestamp(timestamp) -> str
    format_finding(finding)     -> str
    format_analysis(result)     -> str

format_finding() also accepts an optional `index` keyword
(format_finding(finding, index=1)); calling it with just one
argument still works exactly as before.
"""

import os
import sys
import textwrap
from datetime import datetime


# ---------------------------------------------------------------------------
# Terminal colour support
# ---------------------------------------------------------------------------
# Nexorium-Cipher is a security tool first and a pretty terminal UI second.
# Colour is only ever a bonus layer on top of plain, readable text: every
# coloured element has a plain-text form (e.g. "[MATCH]") that is shown
# exactly the same way whether or not colour is available.

class _Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_CYAN = "\033[96m"


def _enable_windows_ansi():
    """
    On Windows, calling os.system("") is a long-standing,
    dependency-free trick that switches the console into a mode
    that understands ANSI escape codes (Windows 10+). It is a
    harmless no-op on every other platform.
    """
    if os.name == "nt":
        os.system("")


_enable_windows_ansi()

# None = auto-detect (default). Set to True/False with set_color_mode()
# to force colour on or off regardless of the terminal, e.g. when a
# report is being written straight to a file rather than printed.
_color_override = None


def set_color_mode(enabled):
    """
    Force colour output on (True), off (False), or back to
    auto-detection (None).

    Example: call set_color_mode(False) before saving a report to
    disk, so the saved .txt file never contains raw escape codes,
    then call set_color_mode(None) afterwards to resume normal
    auto-detected console output.
    """
    global _color_override
    _color_override = enabled


def _color_supported():
    if _color_override is not None:
        return _color_override
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _c(text, *styles):
    """Wrap text in ANSI styles if colour is supported, else return it unchanged."""
    if not styles or not _color_supported():
        return text
    return "".join(styles) + str(text) + _Ansi.RESET


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
# Standard box-drawing characters only (U+2500 block) — these render
# correctly in Windows Terminal, PowerShell 7+, and virtually every
# Linux terminal font, unlike rarer symbol ranges that can show as
# blank boxes on older setups.

WIDTH = 60
RULE_HEAVY = "\u2550" * WIDTH   # ═
RULE_LIGHT = "\u2500" * WIDTH   # ─

_CHECK = "\u2713"               # ✓
_WARN = "\u26a0"                # ⚠
_LENS = "\u25c6"                # ◆


def _emblem_lines():
    """
    Nexorium-Cipher's visual mark: the wordmark held inside a small
    scan/viewport frame, with a single lens glyph marking the point
    of inspection. This is deliberately compact (no full-width ASCII
    art) — the frame itself reads as "targeting / inspecting"
    without drawing a literal magnifying glass.
    """
    texts = [
        f"{_LENS}  N E X O R I U M",
        f"{_LENS}  C I P H E R",
    ]
    # Left-justify to a common width first so the lens glyph lines up
    # vertically between rows, then centre that uniform block in the frame.
    text_width = max(len(t) for t in texts)
    justified = [t.ljust(text_width) for t in texts]
    inner = text_width + 4
    top = "\u250c" + "\u2500" * inner + "\u2510"      # ┌───┐
    bottom = "\u2514" + "\u2500" * inner + "\u2518"   # └───┘
    body = ["\u2502" + j.center(inner) + "\u2502" for j in justified]  # │ … │
    return [top] + body + [bottom]


def _banner():
    lines = [RULE_HEAVY, ""]
    for line in _emblem_lines():
        lines.append(_c(line.center(WIDTH), _Ansi.CYAN))
    lines.append("")
    lines.append(_c("NEXORIUM-CIPHER".center(WIDTH), _Ansi.BOLD, _Ansi.BRIGHT_CYAN))
    lines.append("Explainable Static File & Threat Analysis".center(WIDTH))
    lines.append(_c("Inspect . Identify . Explain.".center(WIDTH), _Ansi.DIM))
    lines.append(RULE_HEAVY)
    return lines


def _section(title):
    return [_c(title, _Ansi.BOLD, _Ansi.CYAN), RULE_LIGHT]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime("%d %b %Y %H:%M:%S")


def _status_badge(status):
    """
    Render the file-identification status (MATCH / MISMATCH / UNKNOWN)
    as a clearly labelled, colour-coded badge. Unrecognised values are
    shown plainly rather than guessed at, so nothing is ever hidden.

    Semantics are unchanged from the analysis engine:
      MATCH    -> clean / positive
      MISMATCH -> a warning worth a look, not a verdict of malicious
      UNKNOWN  -> identification could not be resolved either way
    """
    normalized = str(status).strip().upper()

    if normalized == "MATCH":
        return _c(f"{_CHECK} [MATCH]", _Ansi.BOLD, _Ansi.GREEN)
    if normalized == "MISMATCH":
        return _c(f"{_WARN} [MISMATCH]", _Ansi.BOLD, _Ansi.YELLOW)
    if normalized == "UNKNOWN":
        return _c("[UNKNOWN]", _Ansi.BOLD, _Ansi.CYAN)

    return f"[{normalized}]"


def _level_tag(level):
    """Colour-code a severity/confidence level; unknown levels are
    shown plainly in brackets instead of being forced into a colour."""
    normalized = str(level).strip().upper()
    color = {
        "CRITICAL": _Ansi.BRIGHT_RED,
        "HIGH": _Ansi.RED,
        "MEDIUM": _Ansi.YELLOW,
        "LOW": _Ansi.GREEN,
    }.get(normalized)

    text = f"[{normalized}]"
    return _c(text, _Ansi.BOLD, color) if color else text


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def format_finding(finding, index=None):
    field_indent = "  "
    body_indent = "    "
    body_width = WIDTH - len(body_indent)

    wrapped_evidence = textwrap.fill(
        str(finding["evidence"]), width=body_width,
        initial_indent=body_indent, subsequent_indent=body_indent,
    )
    wrapped_explanation = textwrap.fill(
        str(finding["explanation"]), width=body_width,
        initial_indent=body_indent, subsequent_indent=body_indent,
    )

    number = f"{_c(f'{index:02d}', _Ansi.DIM)}  " if index is not None else ""
    heading = f"{number}{_level_tag(finding['severity'])} {_c(finding['finding'], _Ansi.BOLD)}"

    lines = [heading]
    lines.append(f"{field_indent}Category   : {finding['category']}")
    lines.append(f"{field_indent}Confidence : {_level_tag(finding['confidence'])}")
    lines.append("")
    lines.append(_c(f"{field_indent}Evidence:", _Ansi.DIM))
    lines.append(wrapped_evidence)
    lines.append("")
    lines.append(_c(f"{field_indent}Explanation:", _Ansi.DIM))
    lines.append(wrapped_explanation)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------

def format_analysis(result):
    lines = []

    # --- Header -----------------------------------------------------------
    lines.extend(_banner())

    # --- Target -------------------------------------------------------
    lines.append("")
    lines.extend(_section("TARGET"))
    lines.append(f"File          : {result['file_name']}")
    lines.append(f"Size          : {result['file_size']} bytes")

    # --- Identification -----------------------------------------------
    lines.append("")
    lines.extend(_section("IDENTIFICATION"))
    lines.append(f"Extension     : {result['extension']}")
    lines.append(f"Detected      : {result['detected_format']}")
    lines.append(f"Valid Ext.    : {result['valid_extensions']}")
    lines.append(f"Status        : {_status_badge(result['status'])}")

    # --- Timeline -----------------------------------------------------
    lines.append("")
    lines.extend(_section("TIMELINE"))
    lines.append(f"Created       : {format_timestamp(result['created_time'])}")
    lines.append(f"Modified      : {format_timestamp(result['modified_time'])}")
    lines.append(f"Accessed      : {format_timestamp(result['accessed_time'])}")

    # --- Hashes ---------------------------------------------------------
    lines.append("")
    lines.extend(_section("HASHES"))
    lines.append(f"MD5           : {result['md5']}")
    lines.append(f"SHA-1         : {result['sha1']}")
    lines.append(f"SHA-256       : {result['sha256']}")

    # --- Findings ---------------------------------------------------------
    findings = result["findings"]
    lines.append("")
    lines.extend(_section(f"FINDINGS ({len(findings)})"))

    if not findings:
        lines.append(_c(f"{_CHECK} No findings detected.", _Ansi.GREEN))
    else:
        for number, finding in enumerate(findings, start=1):
            lines.append("")
            lines.append(format_finding(finding, index=number))

    lines.append("")
    lines.append(RULE_HEAVY)

    return "\n".join(lines)