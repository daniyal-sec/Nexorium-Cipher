from cipher.core.content_analyzer import analyze_content
from cipher.core.correlation_engine import correlate_findings
from cipher.core.file_identifier import identify_file
from cipher.core.risk_engine import calculate_risk


def analyze_file(file_path):
    """
    Run the complete Nexorium-Cipher analysis pipeline.

    Phase 1:
        File identification, metadata, and hashing.

    Phase 2:
        Content classification, text analysis, indicators,
        and static content findings.

    Phase 3:
        Correlation of independent findings into higher-level
        behavioral findings.

    Phase 4:
        Aggregate findings into an overall risk score,
        assessment, confidence, and explainable risk factors.

    Returns:
        dict: Complete analysis result.
    """

    # Phase 1 — File identification
    result = identify_file(file_path)

    # Phase 2 — Static content analysis
    content_result = analyze_content(file_path)
    result["content_analysis"] = content_result

    result["findings"].extend(
        content_result["findings"]
    )

    # Phase 3 — Behavioral correlation
    correlated_findings = correlate_findings(
        result["findings"]
    )

    result["findings"].extend(
        correlated_findings
    )

    # Phase 4 — Risk assessment
    result["risk_assessment"] = calculate_risk(
        result["findings"]
    )

    return result