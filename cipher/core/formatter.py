"""
Presentation layer for Nexorium-Cipher.

This module turns the analysis result dictionary produced by
analyze_file() into a readable, professional cybersecurity-analyst-style
terminal report.

It does not perform any hashing, file identification, or evidence analysis
itself. Its only job is to present the analysis data clearly.

Public API:
    format_timestamp(timestamp) -> str
    format_finding(finding)     -> str
    format_analysis(result)     -> str
"""

import os
import sys
import textwrap
from datetime import datetime


# ---------------------------------------------------------------------------
# Terminal colour support
# ---------------------------------------------------------------------------

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
    Enable ANSI escape-code support on Windows terminals.
    """
    if os.name == "nt":
        os.system("")


_enable_windows_ansi()

_color_override = None


def set_color_mode(enabled):
    """
    Force colour output on (True), off (False), or auto-detection (None).
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
    """
    Apply ANSI styles when terminal colour is supported.
    """
    if not styles or not _color_supported():
        return text

    return "".join(styles) + str(text) + _Ansi.RESET


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

WIDTH = 60

RULE_HEAVY = "\u2550" * WIDTH
RULE_LIGHT = "\u2500" * WIDTH

_CHECK = "\u2713"
_WARN = "\u26a0"
_LENS = "\u25c6"


def _emblem_lines():
    """
    Nexorium-Cipher visual mark.
    """
    texts = [
        f"{_LENS}  N E X O R I U M",
        f"{_LENS}  C I P H E R",
    ]

    text_width = max(len(t) for t in texts)
    justified = [t.ljust(text_width) for t in texts]

    inner = text_width + 4

    top = "\u250c" + "\u2500" * inner + "\u2510"
    bottom = "\u2514" + "\u2500" * inner + "\u2518"

    body = [
        "\u2502" + j.center(inner) + "\u2502"
        for j in justified
    ]

    return [top] + body + [bottom]


def _banner():
    lines = [RULE_HEAVY, ""]

    for line in _emblem_lines():
        lines.append(
            _c(line.center(WIDTH), _Ansi.CYAN)
        )

    lines.append("")

    lines.append(
        _c(
            "NEXORIUM-CIPHER".center(WIDTH),
            _Ansi.BOLD,
            _Ansi.BRIGHT_CYAN
        )
    )

    lines.append(
        "Explainable Static File & Threat Analysis".center(WIDTH)
    )

    lines.append(
        _c(
            "Inspect . Identify . Explain.".center(WIDTH),
            _Ansi.DIM
        )
    )

    lines.append(RULE_HEAVY)

    return lines


def _section(title):
    return [
        _c(title, _Ansi.BOLD, _Ansi.CYAN),
        RULE_LIGHT
    ]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime(
        "%d %b %Y %H:%M:%S"
    )


def _status_badge(status):
    """
    Render MATCH / MISMATCH / UNKNOWN as a status badge.
    """

    normalized = str(status).strip().upper()

    if normalized == "MATCH":
        return _c(
            f"{_CHECK} [MATCH]",
            _Ansi.BOLD,
            _Ansi.GREEN
        )

    if normalized == "MISMATCH":
        return _c(
            f"{_WARN} [MISMATCH]",
            _Ansi.BOLD,
            _Ansi.YELLOW
        )

    if normalized == "UNKNOWN":
        return _c(
            "[UNKNOWN]",
            _Ansi.BOLD,
            _Ansi.CYAN
        )

    return f"[{normalized}]"


def _level_tag(level):
    """
    Colour-code severity and confidence levels.
    """

    normalized = str(level).strip().upper()

    color = {
        "CRITICAL": _Ansi.BRIGHT_RED,
        "HIGH": _Ansi.RED,
        "MEDIUM": _Ansi.YELLOW,
        "LOW": _Ansi.GREEN,
    }.get(normalized)

    text = f"[{normalized}]"

    return (
        _c(text, _Ansi.BOLD, color)
        if color
        else text
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def format_finding(finding, index=None):

    field_indent = "  "
    body_indent = "    "
    body_width = WIDTH - len(body_indent)

    wrapped_evidence = textwrap.fill(
        str(finding["evidence"]),
        width=body_width,
        initial_indent=body_indent,
        subsequent_indent=body_indent,
    )

    wrapped_explanation = textwrap.fill(
        str(finding["explanation"]),
        width=body_width,
        initial_indent=body_indent,
        subsequent_indent=body_indent,
    )

    number = (
        f"{_c(f'{index:02d}', _Ansi.DIM)}  "
        if index is not None
        else ""
    )

    heading = (
        f"{number}"
        f"{_c(finding['finding'], _Ansi.BOLD)}"
    )

    lines = [heading]

    lines.append(
        f"{field_indent}Category   : {finding['category']}"
    )

    lines.append(
        f"{field_indent}Severity   : "
        f"{_level_tag(finding['severity'])}"
    )

    lines.append(
        f"{field_indent}Confidence : "
        f"{_level_tag(finding['confidence'])}"
    )

    lines.append("")

    lines.append(
        _c(
            f"{field_indent}Evidence:",
            _Ansi.DIM
        )
    )

    lines.append(wrapped_evidence)

    lines.append("")

    lines.append(
        _c(
            f"{field_indent}Explanation:",
            _Ansi.DIM
        )
    )

    lines.append(wrapped_explanation)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML Analysis
# ---------------------------------------------------------------------------

def _format_html_analysis(html_analysis):

    if not html_analysis:
        return []

    lines = []

    lines.append("")
    lines.extend(_section("HTML ANALYSIS"))

    # --- Forms -----------------------------------------------------------

    forms_detected = html_analysis.get(
        "forms_detected",
        False
    )

    lines.append(
        f"Forms detected          : {forms_detected}"
    )

    forms = html_analysis.get("forms", [])

    lines.append("Forms                    :")

    if forms:
        for form in forms:
            lines.append(f"  {form}")
    else:
        lines.append("  None")

    # --- Password inputs -------------------------------------------------

    password_inputs_detected = html_analysis.get(
        "password_inputs_detected",
        False
    )

    lines.append(
        f"Password inputs detected : "
        f"{password_inputs_detected}"
    )

    password_inputs = html_analysis.get(
        "password_inputs",
        []
    )

    lines.append("Password inputs          :")

    if password_inputs:
        for password_input in password_inputs:
            lines.append(f"  {password_input}")
    else:
        lines.append("  None")

    # --- Form actions ----------------------------------------------------

    actions = html_analysis.get(
        "form_actions",
        []
    )

    lines.append("Form actions             :")

    if actions:
        for action in actions:
            lines.append(f"  {action}")
    else:
        lines.append("  None")

    # --- Form methods ----------------------------------------------------

    methods = html_analysis.get(
        "form_methods",
        []
    )

    lines.append("Form methods             :")

    if methods:
        for method in methods:
            lines.append(f"  {method}")
    else:
        lines.append("  None")

    return lines


# ---------------------------------------------------------------------------
# JavaScript Analysis
# ---------------------------------------------------------------------------

def _format_javascript_analysis(javascript_analysis):

    if not javascript_analysis:
        return []

    lines = []

    lines.append("")
    lines.extend(_section("JAVASCRIPT ANALYSIS"))

    # --- Functions -------------------------------------------------------

    functions = javascript_analysis.get(
        "functions",
        {}
    )

    named_functions = functions.get(
        "named",
        []
    )

    anonymous_count = functions.get(
        "anonymous_count",
        0
    )

    arrow_count = functions.get(
        "arrow_count",
        0
    )

    total_functions = functions.get(
        "total",
        0
    )

    lines.append(
        f"Functions detected      : {total_functions > 0}"
    )

    lines.append(
        f"Total functions         : {total_functions}"
    )

    lines.append(
        f"Named functions        : {len(named_functions)}"
    )

    if named_functions:
        lines.append("Named function names    :")

        for function in named_functions:
            lines.append(f"  {function}")

    lines.append(
        f"Anonymous functions     : {anonymous_count}"
    )

    lines.append(
        f"Arrow functions         : {arrow_count}"
    )

    # --- Variables ------------------------------------------------------

    variables = javascript_analysis.get(
        "variables",
        []
    )

    lines.append("")
    lines.append(
        f"Variables detected      : {len(variables) > 0}"
    )

    lines.append(
        f"Variable count          : {len(variables)}"
    )

    if variables:
        lines.append("Variables               :")

        for variable in variables:
            lines.append(
                f"  {variable['declaration']} "
                f"{variable['name']}"
            )

    # --- Console APIs ---------------------------------------------------

    console_apis = javascript_analysis.get(
        "console_apis",
        []
    )

    lines.append("")
    lines.append(
        f"Console APIs detected   : {len(console_apis) > 0}"
    )

    lines.append(
        f"Console APIs            :"
    )

    if console_apis:
        for api in console_apis:
            lines.append(f"  console.{api}")
    else:
        lines.append("  None")

    # --- Browser APIs ---------------------------------------------------

    browser_apis = javascript_analysis.get(
        "browser_apis",
        []
    )

    lines.append("")
    lines.append(
        f"Browser APIs detected   : {len(browser_apis) > 0}"
    )

    lines.append(
        f"Browser APIs            :"
    )

    if browser_apis:
        for api in browser_apis:
            lines.append(f"  {api}")
    else:
        lines.append("  None")

    # --- DOM APIs -------------------------------------------------------

    dom_apis = javascript_analysis.get(
        "dom_apis",
        []
    )

    lines.append("")
    lines.append(
        f"DOM APIs detected       : {len(dom_apis) > 0}"
    )

    lines.append(
        f"DOM APIs                :"
    )

    if dom_apis:
        for api in dom_apis:
            lines.append(f"  {api}")
    else:
        lines.append("  None")

    # --- Input value access ---------------------------------------------

    input_value_access = javascript_analysis.get(
        "input_value_access",
        False
    )

    lines.append("")
    lines.append(
        f"Input value access      : {input_value_access}"
    )

    # --- Network APIs ---------------------------------------------------

    network_apis = javascript_analysis.get(
        "network_apis",
        []
    )

    lines.append("")
    lines.append(
        f"Network APIs detected   : {len(network_apis) > 0}"
    )

    lines.append(
        f"Network APIs            :"
    )

    if network_apis:
        for api in network_apis:
            lines.append(f"  {api}")
    else:
        lines.append("  None")

    # --- Storage APIs ---------------------------------------------------

    storage_apis = javascript_analysis.get(
        "storage_apis",
        []
    )

    lines.append("")
    lines.append(
        f"Storage APIs detected   : {len(storage_apis) > 0}"
    )

    lines.append(
        f"Storage APIs            :"
    )

    if storage_apis:
        for api in storage_apis:
            lines.append(f"  {api}")
    else:
        lines.append("  None")

    # --- Dynamic execution ----------------------------------------------

    dynamic_execution = javascript_analysis.get(
        "dynamic_execution",
        []
    )

    lines.append("")
    lines.append(
        f"Dynamic execution       : "
        f"{len(dynamic_execution) > 0}"
    )

    lines.append(
        f"Execution mechanisms    :"
    )

    if dynamic_execution:
        for mechanism in dynamic_execution:
            lines.append(f"  {mechanism}")
    else:
        lines.append("  None")

    # --- URLs -----------------------------------------------------------

    urls = javascript_analysis.get(
        "urls",
        []
    )

    lines.append("")
    lines.append(
        f"JavaScript URLs         : {len(urls)}"
    )

    if urls:
        lines.append("URLs                    :")

        for url in urls:
            lines.append(f"  {url}")

    # --- Obfuscation ----------------------------------------------------

    obfuscation = javascript_analysis.get(
        "obfuscation",
        {}
    )

    lines.append("")
    lines.append(
        "OBFUSCATION INDICATORS"
    )

    lines.append(
        f"Long strings            : "
        f"{obfuscation.get('long_string_count', 0)}"
    )

    lines.append(
        f"Hex escapes             : "
        f"{obfuscation.get('hex_escape_count', 0)}"
    )

    lines.append(
        f"Unicode escapes         : "
        f"{obfuscation.get('unicode_escape_count', 0)}"
    )

    return lines


# ---------------------------------------------------------------------------
# Content Analysis
# ---------------------------------------------------------------------------

def _format_content_analysis(result):

    content = result.get("content_analysis")

    if not content:
        return []

    lines = []

    # --- Content classification -----------------------------------------

    lines.append("")
    lines.extend(_section("CONTENT ANALYSIS"))

    content_type = content.get(
        "content_type",
        content.get("type", "unknown")
    )

    lines.append(
        f"Type          : {str(content_type).upper()}"
    )

    lines.append(
        f"Confidence    : "
        f"{_level_tag(content.get('classification_confidence', 'unknown'))}"
    )

    lines.append(
        f"Reason        : "
        f"{content.get('classification_reason', 'N/A')}"
    )

    # --- Statistics -----------------------------------------------------

    statistics = content.get("statistics", {})

    lines.append("")
    lines.extend(_section("STATISTICS"))

    lines.append(
        f"Characters    : {statistics.get('characters', 0)}"
    )

    lines.append(
        f"Lines         : {statistics.get('lines', 0)}"
    )

    lines.append(
        f"Words         : {statistics.get('words', 0)}"
    )

    lines.append(
        f"Empty         : {statistics.get('empty', False)}"
    )

    # --- Indicators -----------------------------------------------------

    indicators = content.get("indicators", {})

    urls = indicators.get("urls", [])
    ipv4_addresses = indicators.get("ipv4_addresses", [])
    domains = indicators.get("domains", [])

    lines.append("")
    lines.extend(_section("INDICATORS"))

    lines.append(
        f"URLs          : {len(urls)}"
    )

    lines.append(
        f"IPv4          : {len(ipv4_addresses)}"
    )

    lines.append(
        f"Domains       : {len(domains)}"
    )

    # --- HTML analysis --------------------------------------------------

    html_analysis = content.get(
        "html_analysis",
        {}
    )

    lines.extend(
        _format_html_analysis(html_analysis)
    )

    # --- JavaScript analysis --------------------------------------------

    javascript_analysis = content.get(
        "javascript_analysis",
        {}
    )

    lines.extend(
        _format_javascript_analysis(
            javascript_analysis
        )
    )

    return lines


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------

def format_analysis(result):

    lines = []

    # --- Header ----------------------------------------------------------

    lines.extend(_banner())

    # --- Target ----------------------------------------------------------

    lines.append("")
    lines.extend(_section("TARGET"))

    lines.append(
        f"File          : {result['file_name']}"
    )

    lines.append(
        f"Size          : {result['file_size']} bytes"
    )

    # --- Identification --------------------------------------------------

    lines.append("")
    lines.extend(_section("IDENTIFICATION"))

    lines.append(
        f"Extension     : {result['extension']}"
    )

    lines.append(
        f"Binary Format : {result['detected_format']}"
    )

    lines.append(
        f"Valid Ext.    : {result['valid_extensions']}"
    )

    lines.append(
        f"Format Status : {_status_badge(result['status'])}"
    )

    # --- Timeline --------------------------------------------------------

    lines.append("")
    lines.extend(_section("TIMELINE"))

    lines.append(
        f"Created       : "
        f"{format_timestamp(result['created_time'])}"
    )

    lines.append(
        f"Modified      : "
        f"{format_timestamp(result['modified_time'])}"
    )

    lines.append(
        f"Accessed      : "
        f"{format_timestamp(result['accessed_time'])}"
    )

    # --- Hashes ----------------------------------------------------------

    lines.append("")
    lines.extend(_section("HASHES"))

    lines.append(
        f"MD5           : {result['md5']}"
    )

    lines.append(
        f"SHA-1         : {result['sha1']}"
    )

    lines.append(
        f"SHA-256       : {result['sha256']}"
    )

    # --- Phase 2 Content Analysis ---------------------------------------

    lines.extend(
        _format_content_analysis(result)
    )

    # --- Findings --------------------------------------------------------

    findings = result.get("findings", [])

    lines.append("")
    lines.extend(
        _section(f"FINDINGS ({len(findings)})")
    )

    if not findings:

        lines.append(
            _c(
                f"{_CHECK} No findings detected.",
                _Ansi.GREEN
            )
        )

    else:

        for number, finding in enumerate(
            findings,
            start=1
        ):

            lines.append("")

            lines.append(
                format_finding(
                    finding,
                    index=number
                )
            )

    lines.append("")
    lines.append(RULE_HEAVY)

    return "\n".join(lines)