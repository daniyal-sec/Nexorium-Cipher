from cipher.core.content_analyzer import analyze_content
from cipher.core.correlation_engine import correlate_findings
from cipher.core.file_identifier import identify_file


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

    Returns:
        dict: Complete analysis result.
    """

    result = identify_file(file_path)

    content_result = analyze_content(file_path)

    result["content_analysis"] = content_result

    result["findings"].extend(
        content_result["findings"]
    )

    correlated_findings = correlate_findings(
        result["findings"]
    )

    result["findings"].extend(
        correlated_findings
    )

    return result