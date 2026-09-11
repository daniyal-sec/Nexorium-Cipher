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


def _format_evidence(evidence, indent="    "):
    """
    Format evidence while preserving meaningful multiline structure.

    HTML tags and other multiline evidence are kept line-by-line
    instead of having their internal whitespace collapsed.
    """

    evidence = str(evidence)

    if not evidence.strip():
        return [f"{indent}None"]

    lines = evidence.splitlines()

    formatted = []

    for line in lines:

        if not line.strip():
            formatted.append("")
            continue

        stripped = line.strip()

        wrapped = textwrap.wrap(
            stripped,
            width=WIDTH - len(indent),
            
            break_long_words=False if False else False,
            break_on_hyphens=False,
        )

        if not wrapped:
            formatted.append(indent)
            continue

        for wrapped_line in wrapped:
            formatted.append(
                f"{indent}{wrapped_line}"
            )

    return formatted


def _format_text_block(text, indent="    "):
    """
    Wrap a normal prose block for terminal display.
    """

    return textwrap.fill(
        str(text),
        width=WIDTH - len(indent),
        initial_indent=indent,
        subsequent_indent=indent,
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def format_finding(finding, index=None):

    field_indent = "  "

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

    lines.extend(
        _format_evidence(
            finding["evidence"]
        )
    )

    lines.append("")

    lines.append(
        _c(
            f"{field_indent}Explanation:",
            _Ansi.DIM
        )
    )

    lines.append(
        _format_text_block(
            finding["explanation"]
        )
    )

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
            lines.extend(
                _format_evidence(
                    form,
                    indent="  "
                )
            )
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
            lines.extend(
                _format_evidence(
                    password_input,
                    indent="  "
                )
            )
    else:
        lines.append("  None")

    # --- Hidden inputs ---------------------------------------------------

    hidden_inputs_detected = html_analysis.get(
        "hidden_inputs_detected",
        False
    )

    lines.append(
        f"Hidden inputs detected   : "
        f"{hidden_inputs_detected}"
    )

    hidden_inputs = html_analysis.get(
        "hidden_inputs",
        []
    )

    lines.append("Hidden inputs            :")

    if hidden_inputs:
        for hidden_input in hidden_inputs:
            lines.extend(
                _format_evidence(
                    hidden_input,
                    indent="  "
                )
            )
    else:
        lines.append("  None")

    # --- Script tags -----------------------------------------------------

    script_tags_detected = html_analysis.get(
        "script_tags_detected",
        False
    )

    lines.append(
        f"Script tags detected     : "
        f"{script_tags_detected}"
    )

    script_tags = html_analysis.get(
        "script_tags",
        []
    )

    lines.append("Script tags              :")

    if script_tags:
        for script_tag in script_tags:
            lines.extend(
                _format_evidence(
                    script_tag,
                    indent="  "
                )
            )
    else:
        lines.append("  None")

    # --- External JavaScript --------------------------------------------

    external_javascript_sources = html_analysis.get(
        "external_javascript_sources",
        []
    )

    lines.append(
        f"External JavaScript     : "
        f"{len(external_javascript_sources) > 0}"
    )

    lines.append(
        "JavaScript sources      :"
    )

    if external_javascript_sources:
        for source in external_javascript_sources:
            lines.append(f"  {source}")
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

    # --- Form destinations ----------------------------------------------

    form_destinations = html_analysis.get(
        "form_destinations",
        {}
    )

    http_destinations = form_destinations.get(
        "http_destinations",
        []
    )

    https_destinations = form_destinations.get(
        "https_destinations",
        []
    )

    ip_destinations = form_destinations.get(
        "ip_destinations",
        []
    )

    relative_destinations = form_destinations.get(
        "relative_destinations",
        []
    )

    unusual_scheme_destinations = form_destinations.get(
        "unusual_scheme_destinations",
        []
    )

    lines.append("")
    lines.append("FORM DESTINATION ANALYSIS")

    lines.append(
        f"HTTP destinations       : "
        f"{len(http_destinations)}"
    )

    if http_destinations:
        for destination in http_destinations:
            lines.append(f"  {destination}")

    lines.append(
        f"HTTPS destinations      : "
        f"{len(https_destinations)}"
    )

    if https_destinations:
        for destination in https_destinations:
            lines.append(f"  {destination}")

    lines.append(
        f"IP destinations         : "
        f"{len(ip_destinations)}"
    )

    if ip_destinations:
        for destination in ip_destinations:
            lines.append(f"  {destination}")

    lines.append(
        f"Relative destinations   : "
        f"{len(relative_destinations)}"
    )

    if relative_destinations:
        for destination in relative_destinations:
            lines.append(f"  {destination}")

    lines.append(
        f"Unusual schemes         : "
        f"{len(unusual_scheme_destinations)}"
    )

    if unusual_scheme_destinations:
        for destination in unusual_scheme_destinations:
            lines.append(f"  {destination}")

    # --- Iframes ---------------------------------------------------------

    iframes_detected = html_analysis.get(
        "iframes_detected",
        False
    )

    iframes = html_analysis.get(
        "iframes",
        []
    )

    iframe_sources = html_analysis.get(
        "iframe_sources",
        []
    )

    lines.append("")
    lines.append("IFRAME ANALYSIS")

    lines.append(
        f"Iframes detected        : {iframes_detected}"
    )

    lines.append(
        f"Iframe count            : {len(iframes)}"
    )

    lines.append("Iframe sources          :")

    if iframe_sources:
        for source in iframe_sources:
            lines.append(f"  {source}")
    else:
        lines.append("  None")

    # --- HTML resources --------------------------------------------------

    image_sources = html_analysis.get(
        "image_sources",
        []
    )

    link_resources = html_analysis.get(
        "link_resources",
        []
    )

    html_resources = html_analysis.get(
        "html_resources",
        {}
    )

    external_iframes = html_resources.get(
        "external_iframes",
        []
    )

    external_images = html_resources.get(
        "external_images",
        []
    )

    external_links = html_resources.get(
        "external_links",
        []
    )

    unusual_iframes = html_resources.get(
        "unusual_iframes",
        []
    )

    unusual_images = html_resources.get(
        "unusual_images",
        []
    )

    unusual_links = html_resources.get(
        "unusual_links",
        []
    )

    lines.append("")
    lines.append("HTML RESOURCE ANALYSIS")

    lines.append(
        f"Image resources         : "
        f"{len(image_sources)}"
    )

    if image_sources:
        for source in image_sources:
            lines.append(f"  {source}")
    else:
        lines.append("  None")

    lines.append(
        f"External images         : "
        f"{len(external_images)}"
    )

    if external_images:
        for source in external_images:
            lines.append(f"  {source}")
    else:
        lines.append("  None")

    lines.append(
        f"Link resources          : "
        f"{len(link_resources)}"
    )

    if link_resources:
        for resource in link_resources:
            lines.append(f"  {resource}")
    else:
        lines.append("  None")

    lines.append(
        f"External links          : "
        f"{len(external_links)}"
    )

    if external_links:
        for resource in external_links:
            lines.append(f"  {resource}")
    else:
        lines.append("  None")

    lines.append(
        f"External iframes       : "
        f"{len(external_iframes)}"
    )

    if external_iframes:
        for source in external_iframes:
            lines.append(f"  {source}")
    else:
        lines.append("  None")

    lines.append(
        f"Unusual iframe schemes : "
        f"{len(unusual_iframes)}"
    )

    if unusual_iframes:
        for source in unusual_iframes:
            lines.append(f"  {source}")
    else:
        lines.append("  None")

    lines.append(
        f"Unusual image schemes  : "
        f"{len(unusual_images)}"
    )

    if unusual_images:
        for source in unusual_images:
            lines.append(f"  {source}")
    else:
        lines.append("  None")

    lines.append(
        f"Unusual link schemes   : "
        f"{len(unusual_links)}"
    )

    if unusual_links:
        for resource in unusual_links:
            lines.append(f"  {resource}")
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
        f"Named functions         : {len(named_functions)}"
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
        "Console APIs            :"
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
        "Browser APIs            :"
    )

    if browser_apis:
        for api in browser_apis:
            lines.append(f"  {api}")
    else:
        lines.append("  None")

    # --- DOM APIs --------------------------------------------------------

    dom_apis = javascript_analysis.get(
        "dom_apis",
        []
    )

    lines.append("")
    lines.append(
        f"DOM APIs detected       : {len(dom_apis) > 0}"
    )

    lines.append(
        "DOM APIs                :"
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

    # --- Event handlers -------------------------------------------------

    event_handlers = javascript_analysis.get(
        "event_handlers",
        []
    )

    lines.append("")
    lines.append(
        f"Event handlers detected : "
        f"{len(event_handlers) > 0}"
    )

    lines.append(
        f"Event handler count     : "
        f"{len(event_handlers)}"
    )

    lines.append(
        "Event handlers          :"
    )

    if event_handlers:
        for event in event_handlers:
            lines.append(f"  {event}")
    else:
        lines.append("  None")

    # --- Input collection events ----------------------------------------

    input_collection_events = javascript_analysis.get(
        "input_collection_events",
        []
    )

    lines.append("")
    lines.append(
        f"Input collection events : "
        f"{len(input_collection_events)}"
    )

    lines.append(
        "Input-related events    :"
    )

    if input_collection_events:
        for event in input_collection_events:
            lines.append(f"  {event}")
    else:
        lines.append("  None")

    # --- Form submission events -----------------------------------------

    form_submission_events = javascript_analysis.get(
        "form_submission_events",
        False
    )

    lines.append("")
    lines.append(
        f"Form submission events  : "
        f"{form_submission_events}"
    )

    # --- Sensitive data -------------------------------------------------

    sensitive_data = javascript_analysis.get(
        "sensitive_data",
        []
    )

    lines.append("")
    lines.append(
        f"Sensitive data detected : "
        f"{len(sensitive_data) > 0}"
    )

    lines.append(
        f"Sensitive references    : "
        f"{len(sensitive_data)}"
    )

    lines.append(
        "Sensitive categories    :"
    )

    if sensitive_data:
        for category in sensitive_data:
            lines.append(f"  {category}")
    else:
        lines.append("  None")

    # --- Cookie access --------------------------------------------------

    cookie_access = javascript_analysis.get(
        "cookie_access",
        False
    )

    lines.append("")
    lines.append(
        f"Cookie access           : {cookie_access}"
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
        "Network APIs            :"
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
        "Storage APIs            :"
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
        "Execution mechanisms    :"
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

    lines.append("URLs                    :")

    if urls:
        for url in urls:
            lines.append(f"  {url}")
    else:
        lines.append("  None")

    # --- Obfuscation ----------------------------------------------------

    obfuscation = javascript_analysis.get(
        "obfuscation",
        {}
    )

    long_string_count = obfuscation.get(
        "long_string_count",
        0
    )

    hex_escape_count = obfuscation.get(
        "hex_escape_count",
        0
    )

    unicode_escape_count = obfuscation.get(
        "unicode_escape_count",
        0
    )

    base64_like_string_count = obfuscation.get(
        "base64_like_string_count",
        0
    )

    encoded_string_count = obfuscation.get(
        "encoded_string_count",
        0
    )

    obfuscation_score = obfuscation.get(
        "score",
        0
    )

    obfuscation_assessment = obfuscation.get(
        "assessment",
        "NONE"
    )

    lines.append("")
    lines.append(
        "OBFUSCATION INDICATORS"
    )

    lines.append(
        f"Long strings            : "
        f"{long_string_count}"
    )

    lines.append(
        f"Hex escapes             : "
        f"{hex_escape_count}"
    )

    lines.append(
        f"Unicode escapes         : "
        f"{unicode_escape_count}"
    )

    lines.append(
        f"Base64-like strings     : "
        f"{base64_like_string_count}"
    )

    lines.append(
        f"Encoded strings         : "
        f"{encoded_string_count}"
    )

    lines.append(
        f"Obfuscation score       : "
        f"{obfuscation_score}"
    )

    lines.append(
        f"Assessment              : "
        f"{obfuscation_assessment}"
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