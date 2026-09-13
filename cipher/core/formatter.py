"""
Presentation layer for Nexorium-Cipher.

This module turns the analysis result dictionary produced by
analyze_file() into a compact, professional cybersecurity analyst
terminal report.

The formatter does not perform analysis. It only presents the data.

Design goals:
    - Preserve important analysis details.
    - Reduce unnecessary vertical scrolling.
    - Keep related information on compact lines.
    - Wrap long values intelligently.
    - Remain readable on small terminal windows.
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
        return str(text)

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
        "",
        _c(title, _Ansi.BOLD, _Ansi.CYAN),
        RULE_LIGHT
    ]


# ---------------------------------------------------------------------------
# Small formatting helpers
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


def _risk_assessment_tag(assessment):
    """
    Colour-code the overall Phase 4 risk assessment.
    """

    normalized = str(assessment).strip().upper()

    color = {
        "LIKELY MALICIOUS": _Ansi.BRIGHT_RED,
        "HIGH": _Ansi.RED,
        "SUSPICIOUS": _Ansi.YELLOW,
        "LOW": _Ansi.GREEN,
        "BENIGN": _Ansi.GREEN,
    }.get(normalized)

    text = f"[{normalized}]"

    return (
        _c(text, _Ansi.BOLD, color)
        if color
        else text
    )


def _compact_value(value):
    """
    Convert a value into a compact one-line representation.
    """

    if value is None:
        return "None"

    if isinstance(value, bool):
        return "YES" if value else "NO"

    if isinstance(value, list):
        if not value:
            return "None"

        return ", ".join(str(item) for item in value)

    return str(value)


def _format_compact_field(label, value, label_width=14):
    """
    Format a simple field as:

        Label       : value
    """

    return (
        f"{label:<{label_width}}: "
        f"{_compact_value(value)}"
    )


def _format_inline_fields(fields):
    """
    Put several short fields on one terminal line.

    Example:

        URLs: 2    Domains: 1    IPv4: 0
    """

    parts = []

    for label, value in fields:
        parts.append(
            f"{label}: {_compact_value(value)}"
        )

    return "    ".join(parts)


def _format_wrapped_value(
    label,
    value,
    label_width=14,
    indent="    "
):
    """
    Compactly wrap a long value while keeping the label aligned.
    """

    prefix = f"{indent}{label:<{label_width}}: "
    available = WIDTH - len(prefix)

    text = _compact_value(value)

    if available <= 10:
        return [prefix + text]

    wrapped = textwrap.wrap(
        text,
        width=WIDTH - len(indent) - label_width - 2,
        break_long_words=False,
        break_on_hyphens=False,
    )

    if not wrapped:
        return [prefix]

    lines = [prefix + wrapped[0]]

    continuation_indent = (
        " " * (len(indent) + label_width + 2)
    )

    for item in wrapped[1:]:
        lines.append(
            continuation_indent + item
        )

    return lines


def _format_list_compact(
    label,
    values,
    label_width=14,
    indent="    "
):
    """
    Format a list compactly.

    Small lists are kept on one or two wrapped lines.
    """

    if not values:
        return [
            f"{indent}{label:<{label_width}}: None"
        ]

    return _format_wrapped_value(
        label,
        values,
        label_width=label_width,
        indent=indent,
    )


def _format_evidence(evidence, indent="    "):
    """
    Format multiline evidence while preserving meaningful lines.
    """

    evidence = str(evidence)

    if not evidence.strip():
        return [f"{indent}None"]

    lines = evidence.splitlines()
    formatted = []

    for line in lines:

        if not line.strip():
            continue

        stripped = line.strip()

        wrapped = textwrap.wrap(
            stripped,
            width=WIDTH - len(indent),
            break_long_words=False,
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
    Wrap normal prose for compact terminal display.
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
    """
    Format one finding in a compact analyst-friendly layout.

    The finding still contains:
        - category
        - severity
        - confidence
        - evidence
        - explanation

    but avoids excessive blank lines.
    """

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
        "  "
        + _format_inline_fields(
            [
                ("Category", finding.get("category", "N/A")),
                (
                    "Severity",
                    _level_tag(
                        finding.get("severity", "UNKNOWN")
                    )
                ),
                (
                    "Confidence",
                    _level_tag(
                        finding.get("confidence", "UNKNOWN")
                    )
                ),
            ]
        )
    )

    evidence = finding.get(
        "evidence",
        "None"
    )

    lines.append(
        "  "
        + _c("Evidence: ", _Ansi.DIM)
        + str(evidence).splitlines()[0]
        if str(evidence).splitlines()
        else "  Evidence: None"
    )

    evidence_lines = str(evidence).splitlines()

    if len(evidence_lines) > 1:

        for line in evidence_lines[1:]:

            if not line.strip():
                continue

            wrapped = textwrap.wrap(
                line.strip(),
                width=WIDTH - 4,
                break_long_words=False,
                break_on_hyphens=False,
            )

            for wrapped_line in wrapped:
                lines.append(
                    f"             {wrapped_line}"
                )

    explanation = finding.get(
        "explanation",
        "N/A"
    )

    lines.append(
        "  "
        + _c("Why: ", _Ansi.DIM)
        + str(explanation)
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML Analysis
# ---------------------------------------------------------------------------

def _format_html_analysis(html_analysis):

    if not html_analysis:
        return []

    lines = []
    lines.extend(_section("HTML ANALYSIS"))

    forms = html_analysis.get("forms", [])
    password_inputs = html_analysis.get(
        "password_inputs",
        []
    )
    hidden_inputs = html_analysis.get(
        "hidden_inputs",
        []
    )
    script_tags = html_analysis.get(
        "script_tags",
        []
    )

    lines.append(
        _format_inline_fields(
            [
                (
                    "Forms",
                    len(forms)
                ),
                (
                    "Password inputs",
                    len(password_inputs)
                ),
                (
                    "Hidden inputs",
                    len(hidden_inputs)
                ),
                (
                    "Script tags",
                    len(script_tags)
                ),
            ]
        )
    )

    external_javascript_sources = html_analysis.get(
        "external_javascript_sources",
        []
    )

    lines.extend(
        _format_list_compact(
            "External JS",
            external_javascript_sources
        )
    )

    actions = html_analysis.get(
        "form_actions",
        []
    )

    methods = html_analysis.get(
        "form_methods",
        []
    )

    lines.extend(
        _format_list_compact(
            "Form actions",
            actions
        )
    )

    lines.extend(
        _format_list_compact(
            "Form methods",
            methods
        )
    )

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

    lines.append(
        _c(
            "FORM DESTINATIONS",
            _Ansi.DIM
        )
    )

    lines.append(
        _format_inline_fields(
            [
                ("HTTP", len(http_destinations)),
                ("HTTPS", len(https_destinations)),
                ("IP", len(ip_destinations)),
                ("Relative", len(relative_destinations)),
                (
                    "Unusual",
                    len(unusual_scheme_destinations)
                ),
            ]
        )
    )

    if http_destinations:
        lines.extend(
            _format_list_compact(
                "HTTP",
                http_destinations
            )
        )

    if https_destinations:
        lines.extend(
            _format_list_compact(
                "HTTPS",
                https_destinations
            )
        )

    if ip_destinations:
        lines.extend(
            _format_list_compact(
                "IP",
                ip_destinations
            )
        )

    if relative_destinations:
        lines.extend(
            _format_list_compact(
                "Relative",
                relative_destinations
            )
        )

    if unusual_scheme_destinations:
        lines.extend(
            _format_list_compact(
                "Unusual",
                unusual_scheme_destinations
            )
        )

    iframes = html_analysis.get(
        "iframes",
        []
    )

    iframe_sources = html_analysis.get(
        "iframe_sources",
        []
    )

    lines.append(
        _c(
            "IFRAMES",
            _Ansi.DIM
        )
    )

    lines.append(
        _format_inline_fields(
            [
                ("Detected", len(iframes) > 0),
                ("Count", len(iframes)),
            ]
        )
    )

    if iframe_sources:
        lines.extend(
            _format_list_compact(
                "Sources",
                iframe_sources
            )
        )

    html_resources = html_analysis.get(
        "html_resources",
        {}
    )

    image_sources = html_analysis.get(
        "image_sources",
        []
    )

    link_resources = html_analysis.get(
        "link_resources",
        []
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

    lines.append(
        _c(
            "RESOURCES",
            _Ansi.DIM
        )
    )

    lines.append(
        _format_inline_fields(
            [
                ("Images", len(image_sources)),
                ("External images", len(external_images)),
                ("Links", len(link_resources)),
                ("External links", len(external_links)),
                ("External iframes", len(external_iframes)),
            ]
        )
    )

    if unusual_iframes:
        lines.extend(
            _format_list_compact(
                "Unusual iframes",
                unusual_iframes
            )
        )

    if unusual_images:
        lines.extend(
            _format_list_compact(
                "Unusual images",
                unusual_images
            )
        )

    if unusual_links:
        lines.extend(
            _format_list_compact(
                "Unusual links",
                unusual_links
            )
        )

    return lines


# ---------------------------------------------------------------------------
# JavaScript Analysis
# ---------------------------------------------------------------------------

def _format_javascript_analysis(javascript_analysis):

    if not javascript_analysis:
        return []

    lines = []
    lines.extend(_section("JAVASCRIPT ANALYSIS"))

    functions = javascript_analysis.get(
        "functions",
        {}
    )

    named_functions = functions.get(
        "named",
        []
    )

    total_functions = functions.get(
        "total",
        0
    )

    anonymous_count = functions.get(
        "anonymous_count",
        0
    )

    arrow_count = functions.get(
        "arrow_count",
        0
    )

    lines.append(
        _format_inline_fields(
            [
                ("Functions", total_functions),
                ("Named", len(named_functions)),
                ("Anonymous", anonymous_count),
                ("Arrow", arrow_count),
            ]
        )
    )

    if named_functions:
        lines.extend(
            _format_list_compact(
                "Function names",
                named_functions
            )
        )

    variables = javascript_analysis.get(
        "variables",
        []
    )

    variable_names = [
        f"{item.get('declaration', '')} {item.get('name', '')}".strip()
        for item in variables
    ]

    lines.append(
        _format_inline_fields(
            [
                ("Variables", len(variables)),
            ]
        )
    )

    if variable_names:
        lines.extend(
            _format_list_compact(
                "Declarations",
                variable_names
            )
        )

    console_apis = javascript_analysis.get(
        "console_apis",
        []
    )

    browser_apis = javascript_analysis.get(
        "browser_apis",
        []
    )

    dom_apis = javascript_analysis.get(
        "dom_apis",
        []
    )

    lines.append(
        _format_inline_fields(
            [
                ("Console", console_apis or "None"),
                ("Browser", browser_apis or "None"),
                ("DOM", dom_apis or "None"),
            ]
        )
    )

    input_value_access = javascript_analysis.get(
        "input_value_access",
        False
    )

    event_handlers = javascript_analysis.get(
        "event_handlers",
        []
    )

    input_collection_events = javascript_analysis.get(
        "input_collection_events",
        []
    )

    form_submission_events = javascript_analysis.get(
        "form_submission_events",
        False
    )

    lines.append(
        _format_inline_fields(
            [
                ("Input value", input_value_access),
                ("Events", len(event_handlers)),
                ("Input events", len(input_collection_events)),
                ("Form submit", form_submission_events),
            ]
        )
    )

    if event_handlers:
        lines.extend(
            _format_list_compact(
                "Event handlers",
                event_handlers
            )
        )

    sensitive_data = javascript_analysis.get(
        "sensitive_data",
        []
    )

    cookie_access = javascript_analysis.get(
        "cookie_access",
        False
    )

    lines.append(
        _format_inline_fields(
            [
                ("Sensitive data", sensitive_data or "None"),
                ("Cookies", cookie_access),
            ]
        )
    )

    network_apis = javascript_analysis.get(
        "network_apis",
        []
    )

    storage_apis = javascript_analysis.get(
        "storage_apis",
        []
    )

    dynamic_execution = javascript_analysis.get(
        "dynamic_execution",
        []
    )

    lines.append(
        _format_inline_fields(
            [
                ("Network", network_apis or "None"),
                ("Storage", storage_apis or "None"),
                ("Dynamic exec", dynamic_execution or "None"),
            ]
        )
    )

    urls = javascript_analysis.get(
        "urls",
        []
    )

    lines.extend(
        _format_list_compact(
            "JS URLs",
            urls
        )
    )

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

    lines.append(
        _c(
            "OBFUSCATION",
            _Ansi.DIM
        )
    )

    lines.append(
        _format_inline_fields(
            [
                ("Long", long_string_count),
                ("Hex", hex_escape_count),
                ("Unicode", unicode_escape_count),
                ("Base64", base64_like_string_count),
                ("Encoded", encoded_string_count),
            ]
        )
    )

    lines.append(
        _format_inline_fields(
            [
                ("Score", obfuscation_score),
                ("Assessment", obfuscation_assessment),
            ]
        )
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

    lines.extend(
        _section("CONTENT ANALYSIS")
    )

    content_type = content.get(
        "content_type",
        content.get("type", "unknown")
    )

    classification_confidence = content.get(
        "classification_confidence",
        "unknown"
    )

    classification_reason = content.get(
        "classification_reason",
        "N/A"
    )

    lines.append(
        _format_inline_fields(
            [
                ("Type", str(content_type).upper()),
                (
                    "Confidence",
                    _level_tag(classification_confidence)
                ),
            ]
        )
    )

    lines.extend(
        _format_wrapped_value(
            "Reason",
            classification_reason,
            indent="    "
        )
    )

    statistics = content.get(
        "statistics",
        {}
    )

    lines.append(
        _format_inline_fields(
            [
                ("Characters", statistics.get("characters", 0)),
                ("Lines", statistics.get("lines", 0)),
                ("Words", statistics.get("words", 0)),
                ("Empty", statistics.get("empty", False)),
            ]
        )
    )

    indicators = content.get(
        "indicators",
        {}
    )

    urls = indicators.get(
        "urls",
        []
    )

    ipv4_addresses = indicators.get(
        "ipv4_addresses",
        []
    )

    domains = indicators.get(
        "domains",
        []
    )

    lines.append(
        _format_inline_fields(
            [
                ("URLs", len(urls)),
                ("IPv4", len(ipv4_addresses)),
                ("Domains", len(domains)),
            ]
        )
    )

    lines.extend(
        _format_html_analysis(
            content.get("html_analysis", {})
        )
    )

    lines.extend(
        _format_javascript_analysis(
            content.get("javascript_analysis", {})
        )
    )

    return lines


# ---------------------------------------------------------------------------
# Risk Assessment — Phase 4
# ---------------------------------------------------------------------------

def _format_risk_assessment(result):
    """
    Format the overall Phase 4 risk assessment.

    The formatter only presents the values calculated by the
    risk engine. It does not perform any risk calculations.
    """

    risk = result.get("risk_assessment")

    if not risk:
        return []

    lines = []

    lines.extend(
        _section("RISK ASSESSMENT")
    )

    score = risk.get("score", 0)
    assessment = risk.get(
        "assessment",
        "UNKNOWN"
    )
    confidence = risk.get(
        "confidence",
        "UNKNOWN"
    )

    lines.append(
        _format_inline_fields(
            [
                ("Score", f"{score} / 100"),
                (
                    "Assessment",
                    _risk_assessment_tag(assessment)
                ),
                (
                    "Confidence",
                    _level_tag(confidence)
                ),
            ]
        )
    )

    risk_factors = risk.get(
        "risk_factors",
        []
    )

    lines.append(
        _c(
            "RISK FACTORS",
            _Ansi.DIM
        )
    )

    if not risk_factors:
        lines.append(
            f"    {_CHECK} None identified."
        )
    else:
        for factor in risk_factors:
            lines.extend(
                _format_wrapped_value(
                    "•",
                    factor,
                    label_width=2,
                    indent="    "
                )
            )

    contributions = risk.get(
        "contributions",
        []
    )

    if contributions:
        lines.append(
            _c(
                "TOP CONTRIBUTIONS",
                _Ansi.DIM
            )
        )

        for contribution in contributions[:5]:
            finding_name = contribution.get(
                "finding",
                "Unknown finding"
            )

            value = contribution.get(
                "contribution",
                0
            )

            correlation = contribution.get(
                "correlation",
                False
            )

            marker = "◆" if correlation else "•"

            lines.append(
                f"    {marker} "
                f"{finding_name}: "
                f"+{value:.2f}"
            )

    return lines


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------

def format_analysis(result):

    lines = []

    lines.extend(_banner())

    # ------------------------------------------------------------------
    # Target
    # ------------------------------------------------------------------

    lines.extend(_section("TARGET"))

    lines.append(
        _format_inline_fields(
            [
                ("File", result.get("file_name", "N/A")),
                ("Size", f"{result.get('file_size', 0)} bytes"),
            ]
        )
    )

    # ------------------------------------------------------------------
    # Identification
    # ------------------------------------------------------------------

    lines.extend(_section("IDENTIFICATION"))

    lines.append(
        _format_inline_fields(
            [
                ("Extension", result.get("extension", "N/A")),
                ("Format", result.get("detected_format", "unknown")),
                ("Status", _status_badge(result.get("status", "UNKNOWN"))),
            ]
        )
    )

    valid_extensions = result.get(
        "valid_extensions",
        []
    )

    if valid_extensions:
        lines.extend(
            _format_list_compact(
                "Valid extensions",
                valid_extensions
            )
        )

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    lines.extend(_section("TIMELINE"))

    lines.append(
        _format_inline_fields(
            [
                (
                    "Created",
                    format_timestamp(
                        result["created_time"]
                    )
                ),
                (
                    "Modified",
                    format_timestamp(
                        result["modified_time"]
                    )
                ),
            ]
        )
    )

    lines.append(
        _format_inline_fields(
            [
                (
                    "Accessed",
                    format_timestamp(
                        result["accessed_time"]
                    )
                ),
            ]
        )
    )

    # ------------------------------------------------------------------
    # Hashes
    # ------------------------------------------------------------------

    lines.extend(_section("HASHES"))

    lines.extend(
        _format_wrapped_value(
            "MD5",
            result.get("md5", "N/A"),
            indent="    "
        )
    )

    lines.extend(
        _format_wrapped_value(
            "SHA-1",
            result.get("sha1", "N/A"),
            indent="    "
        )
    )

    lines.extend(
        _format_wrapped_value(
            "SHA-256",
            result.get("sha256", "N/A"),
            indent="    "
        )
    )

    # ------------------------------------------------------------------
    # Content analysis
    # ------------------------------------------------------------------

    lines.extend(
        _format_content_analysis(result)
    )

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    findings = result.get(
        "findings",
        []
    )

    lines.extend(
        _section(
            f"FINDINGS ({len(findings)})"
        )
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

            if number > 1:
                lines.append("")

            lines.append(
                format_finding(
                    finding,
                    index=number
                )
            )

    # ------------------------------------------------------------------
    # Phase 4 — Risk Assessment
    # ------------------------------------------------------------------

    lines.extend(
        _format_risk_assessment(result)
    )

    lines.append("")
    lines.append(RULE_HEAVY)

    return "\n".join(lines)