from cipher.core.content_classifier import classify_content
from cipher.core.content_reader import read_text_file
from cipher.core.content_stats import analyze_text_content
from cipher.core.content_type_detector import detect_content_type
from cipher.core.indicators import (
    extract_domains,
    extract_ipv4_addresses,
    extract_urls,
)
from cipher.core.indicator_analysis import analyze_indicators
from cipher.core.html_analyzer import analyze_html
from cipher.core.javascript_analyzer import analyze_javascript
from cipher.core.javascript_analysis import analyze_javascript_findings


def analyze_content(file_path):
    """
    Run the Phase 2 static content-analysis pipeline.

    The function first determines whether the file is text or binary.
    Text files are then classified into a more specific content type.

    HTML and JavaScript content are passed to their respective
    static analyzers.

    JavaScript observations are additionally converted into
    structured findings.

    Returns:
        dict: Structured Phase 2 content-analysis result.
    """

    classification = classify_content(file_path)

    result = {
        "type": classification["type"],
        "content_type": classification["content_type"],
        "classification_confidence": classification["confidence"],
        "classification_reason": classification["reason"],
        "statistics": {},
        "indicators": {
            "urls": [],
            "ipv4_addresses": [],
            "domains": [],
        },
        "html_analysis": {},
        "javascript_analysis": {},
        "findings": [],
    }

    # -----------------------------------------------------------------------
    # Binary content
    # -----------------------------------------------------------------------

    if classification["type"] != "text":
        return result

    # -----------------------------------------------------------------------
    # Text content
    # -----------------------------------------------------------------------

    content = read_text_file(file_path)

    result["statistics"] = analyze_text_content(content)

    # -----------------------------------------------------------------------
    # Content type detection
    # -----------------------------------------------------------------------

    content_type = detect_content_type(
        content,
        file_path
    )

    result["content_type"] = content_type["type"]
    result["classification_confidence"] = content_type["confidence"]
    result["classification_reason"] = content_type["reason"]

    # -----------------------------------------------------------------------
    # Network indicators
    # -----------------------------------------------------------------------

    urls = extract_urls(content)
    ipv4_addresses = extract_ipv4_addresses(content)
    domains = extract_domains(content)

    result["indicators"] = {
        "urls": urls,
        "ipv4_addresses": ipv4_addresses,
        "domains": domains,
    }

    result["findings"] = analyze_indicators(
        urls=urls,
        ipv4_addresses=ipv4_addresses,
        domains=domains,
    )

    # -----------------------------------------------------------------------
    # HTML analysis
    # -----------------------------------------------------------------------

    if content_type["type"] == "html":

        result["html_analysis"] = analyze_html(content)

    # -----------------------------------------------------------------------
    # JavaScript analysis
    # -----------------------------------------------------------------------

    elif content_type["type"] == "javascript":

        javascript_analysis = analyze_javascript(content)

        result["javascript_analysis"] = javascript_analysis

        javascript_findings = analyze_javascript_findings(
            javascript_analysis
        )

        result["findings"].extend(
            javascript_findings
        )

    return result