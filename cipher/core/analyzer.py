from cipher.core.archive_analyzer import analyze_archive
from cipher.core.archive_pipeline import (
    analyze_archive_contents,
    collect_archive_findings,
)
from cipher.core.content_analyzer import analyze_content
from cipher.core.correlation_engine import correlate_findings
from cipher.core.file_identifier import identify_file
from cipher.core.risk_engine import calculate_risk


def _deduplicate_findings(findings):
    """
    Remove exact duplicate findings while preserving order.

    Findings are considered duplicates when they have the same:
        - category
        - finding
        - evidence
        - archive_path

    archive_path is included so identical findings from different
    files inside an archive remain distinct.
    """

    unique_findings = []
    seen = set()

    for finding in findings:

        key = (
            finding.get("category"),
            finding.get("finding"),
            finding.get("evidence"),
            finding.get("archive_path"),
        )

        if key in seen:
            continue

        seen.add(key)
        unique_findings.append(finding)

    return unique_findings


def _get_parent_correlation_findings(findings):
    """
    Select findings that belong to the parent file for
    behavioral correlation.

    Archive-derived findings already contain an archive_path.
    Their behavioral correlations were produced while analyzing
    the corresponding child file, so they must not be
    re-correlated at the parent level.

    Findings without archive_path belong to the current file
    being analyzed and are eligible for Phase 3 correlation.
    """

    return [
        finding
        for finding in findings
        if not finding.get("archive_path")
    ]


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

    Phase 5:
        Static archive inspection, safe extraction, recursive
        content analysis, and archive-level findings.

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

    # Phase 5 — Archive analysis
    #
    # Only process the archive pipeline when Cipher's file
    # identification layer has confirmed that the detected
    # format is ZIP.
    detected_format = result.get(
        "detected_format",
        ""
    )

    if detected_format.lower() == "zip":

        # Archive-level inspection
        archive_result = analyze_archive(
            file_path
        )

        result["archive_analysis"] = archive_result

        result["findings"].extend(
            archive_result["findings"]
        )

        # Analyze files contained inside the archive.
        #
        # The archive pipeline performs safe extraction,
        # recursive archive handling, and controlled analysis.
        archive_content_result = analyze_archive_contents(
            file_path,
            analyze_file,
        )

        result["archive_content_analysis"] = (
            archive_content_result
        )

        # Promote important findings discovered inside
        # archive contents to the parent archive analysis.
        promoted_archive_findings = collect_archive_findings(
            archive_content_result
        )

        result["findings"].extend(
            promoted_archive_findings
        )

    # Remove exact duplicate findings.
    result["findings"] = _deduplicate_findings(
        result["findings"]
    )

    # Phase 3 — Behavioral correlation
    #
    # Only findings belonging to the current file are sent
    # through the parent correlation engine.
    #
    # Findings originating from archive contents already passed
    # through correlation during child-file analysis and carry
    # an archive_path. Re-correlating them here would duplicate
    # behavioral findings and artificially increase the risk score.
    parent_findings = _get_parent_correlation_findings(
        result["findings"]
    )

    correlated_findings = correlate_findings(
        parent_findings
    )

    result["findings"].extend(
        correlated_findings
    )

    # Remove any exact duplicates introduced by correlation.
    result["findings"] = _deduplicate_findings(
        result["findings"]
    )

    # Phase 4 — Risk assessment
    result["risk_assessment"] = calculate_risk(
        result["findings"]
    )

    return result