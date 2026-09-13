"""
Cipher Phase 4 — Risk Engine

Converts structured findings produced by the earlier analysis stages
into an overall risk assessment.

The risk engine does not inspect files directly. It consumes findings
from the analysis and correlation layers.
"""


SEVERITY_BASE_RISK = {
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 30,
    "CRITICAL": 40,
}

CONFIDENCE_MULTIPLIER = {
    "LOW": 0.5,
    "MEDIUM": 0.75,
    "HIGH": 1.0,
}

CORRELATION_MULTIPLIER = 1.5
SUPPORTING_EVIDENCE_MULTIPLIER = 0.25


def _normalize(value):
    """Normalize a finding value for consistent comparisons."""

    if value is None:
        return ""

    return str(value).strip().upper()


def _is_correlation(finding):
    """
    Determine whether a finding was produced by the Phase 3
    behavioral correlation engine.

    Correlation findings are identified by the presence of an
    evidence_chain field.
    """

    return bool(finding.get("evidence_chain"))


def _calculate_contribution(finding):
    """
    Calculate the raw risk contribution of a single finding.

    Formula:

        severity base
        × confidence multiplier
        × correlation multiplier (when applicable)
    """

    severity = _normalize(finding.get("severity"))
    confidence = _normalize(finding.get("confidence"))

    base_risk = SEVERITY_BASE_RISK.get(severity, 0)
    confidence_multiplier = CONFIDENCE_MULTIPLIER.get(
        confidence,
        0.5,
    )

    contribution = base_risk * confidence_multiplier

    if _is_correlation(finding):
        contribution *= CORRELATION_MULTIPLIER

    return round(contribution, 2)


def _has_credential_correlation(findings):
    """
    Check whether credential collection or data transmission
    was identified through behavioral correlation.
    """

    return any(
        "behavior.credential_collection" in finding.get("tags", [])
        or "behavior.data_transmission" in finding.get("tags", [])
        for finding in findings
    )


def _has_obfuscated_execution_correlation(findings):
    """
    Check whether obfuscated execution was identified through
    behavioral correlation.
    """

    return any(
        "behavior.obfuscated_execution" in finding.get("tags", [])
        for finding in findings
    )


def _is_supporting_finding(
    finding,
    has_credential_correlation,
    has_obfuscated_execution,
):
    """
    Identify low-level findings that directly support an existing
    behavioral correlation.

    A finding is NOT considered supporting evidence merely because
    it has a potentially relevant tag.

    The corresponding correlation must actually exist.
    """

    tags = set(finding.get("tags", []))

    credential_support = (
        has_credential_correlation
        and bool(
            tags
            & {
                "javascript.input.value",
                "javascript.sensitive_data",
                "javascript.network",
                "javascript.network.url",
                "network.external_destination",
            }
        )
    )

    obfuscation_support = (
        has_obfuscated_execution
        and bool(
            tags
            & {
                "javascript.obfuscation",
                "javascript.dynamic_execution",
            }
        )
    )

    return credential_support or obfuscation_support


def _get_adjusted_contribution(
    finding,
    has_credential_correlation,
    has_obfuscated_execution,
):
    """
    Calculate the actual contribution used by the overall risk score.

    Correlation findings receive their full contribution.

    Low-level findings that directly support an existing correlation
    are reduced to avoid excessive double-counting.
    """

    contribution = _calculate_contribution(finding)

    if _is_correlation(finding):
        return contribution

    if _is_supporting_finding(
        finding,
        has_credential_correlation,
        has_obfuscated_execution,
    ):
        contribution *= SUPPORTING_EVIDENCE_MULTIPLIER

    return round(contribution, 2)


def _calculate_total_score(findings):
    """
    Calculate the overall numeric risk score.

    Correlation findings receive their full contribution.

    Low-level findings that directly support a correlation are
    reduced to avoid excessive double-counting.

    LOW-only findings may contribute to the numeric score, but
    cannot independently elevate the overall assessment above
    BENIGN.
    """

    if not findings:
        return 0

    has_credential_correlation = _has_credential_correlation(
        findings
    )

    has_obfuscated_execution = _has_obfuscated_execution_correlation(
        findings
    )

    total = 0.0

    for finding in findings:
        contribution = _get_adjusted_contribution(
            finding,
            has_credential_correlation,
            has_obfuscated_execution,
        )

        total += contribution

    return min(round(total), 100)


def _get_strongest_severity(findings):
    """
    Return the strongest severity present in the findings.

    Severity ordering:

        LOW < MEDIUM < HIGH < CRITICAL
    """

    severity_rank = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    strongest = ""

    for finding in findings:
        severity = _normalize(finding.get("severity"))

        if severity_rank.get(severity, 0) > severity_rank.get(
            strongest,
            0,
        ):
            strongest = severity

    return strongest


def _has_meaningful_risk(findings):
    """
    Determine whether the findings contain evidence strong enough
    to move the assessment above BENIGN.

    LOW findings are contextual observations and cannot
    independently elevate the assessment.
    """

    return any(
        _normalize(finding.get("severity"))
        in {"MEDIUM", "HIGH", "CRITICAL"}
        for finding in findings
    )


def _get_assessment(score, findings):
    """
    Convert the numeric risk score and strongest evidence severity
    into an overall risk assessment.

    Rules:

        LOW-only evidence
            -> BENIGN

        MEDIUM evidence
            -> minimum LOW

        HIGH evidence
            -> minimum SUSPICIOUS

        CRITICAL evidence
            -> minimum HIGH

        Aggregate score can raise the assessment further.
    """

    if not _has_meaningful_risk(findings):
        return "BENIGN"

    strongest_severity = _get_strongest_severity(findings)

    if score >= 85:
        return "LIKELY MALICIOUS"

    if score >= 65:
        return "HIGH"

    if score >= 40:
        return "SUSPICIOUS"

    if strongest_severity == "CRITICAL":
        return "HIGH"

    if strongest_severity == "HIGH":
        return "SUSPICIOUS"

    if strongest_severity == "MEDIUM":
        return "LOW"

    return "BENIGN"


def _calculate_overall_confidence(findings, score):
    """
    Calculate confidence for the overall assessment.

    Confidence reflects the strength and consistency of the evidence,
    not the probability that the file is malicious.

    LOW-only observations do not produce HIGH overall confidence
    because they are contextual rather than meaningful risk evidence.
    """

    if not findings:
        return "LOW"

    meaningful_findings = [
        finding
        for finding in findings
        if _normalize(finding.get("severity"))
        in {"MEDIUM", "HIGH", "CRITICAL"}
    ]

    if not meaningful_findings:
        return "LOW"

    high_confidence = sum(
        1
        for finding in meaningful_findings
        if _normalize(finding.get("confidence")) == "HIGH"
    )

    medium_or_high_confidence = sum(
        1
        for finding in meaningful_findings
        if _normalize(finding.get("confidence"))
        in {"MEDIUM", "HIGH"}
    )

    correlation_count = sum(
        1
        for finding in meaningful_findings
        if _is_correlation(finding)
    )

    if correlation_count >= 2 and high_confidence >= 2:
        return "HIGH"

    if correlation_count >= 1 and high_confidence >= 1:
        return "HIGH"

    if high_confidence >= 3:
        return "HIGH"

    if medium_or_high_confidence >= 2:
        return "MEDIUM"

    return "LOW"


def _build_risk_factors(findings):
    """
    Extract the most meaningful risk factors.

    Correlation findings are prioritized because they represent
    higher-level behavioral conclusions.

    HIGH and CRITICAL non-correlation findings are also included.
    """

    factors = []

    correlation_findings = [
        finding
        for finding in findings
        if _is_correlation(finding)
    ]

    other_findings = [
        finding
        for finding in findings
        if not _is_correlation(finding)
        and _normalize(finding.get("severity"))
        in {"HIGH", "CRITICAL"}
    ]

    for finding in correlation_findings:
        finding_name = finding.get("finding")

        if finding_name and finding_name not in factors:
            factors.append(finding_name)

    for finding in other_findings:
        finding_name = finding.get("finding")

        if finding_name and finding_name not in factors:
            factors.append(finding_name)

    return factors[:6]


def _build_contributions(findings):
    """
    Build a machine-readable list of risk contributions.

    The reported contribution is the actual contribution used by
    the final risk score.

    This includes supporting-evidence reduction where applicable,
    keeping the explanation consistent with the final score.
    """

    contributions = []

    has_credential_correlation = _has_credential_correlation(
        findings
    )

    has_obfuscated_execution = _has_obfuscated_execution_correlation(
        findings
    )

    for finding in findings:
        contribution = _get_adjusted_contribution(
            finding,
            has_credential_correlation,
            has_obfuscated_execution,
        )

        if contribution <= 0:
            continue

        contributions.append(
            {
                "finding": finding.get(
                    "finding",
                    "Unknown finding",
                ),
                "severity": finding.get(
                    "severity",
                    "UNKNOWN",
                ),
                "confidence": finding.get(
                    "confidence",
                    "UNKNOWN",
                ),
                "contribution": contribution,
                "correlation": _is_correlation(finding),
                "supporting_evidence": (
                    _is_supporting_finding(
                        finding,
                        has_credential_correlation,
                        has_obfuscated_execution,
                    )
                    and not _is_correlation(finding)
                ),
            }
        )

    contributions.sort(
        key=lambda item: item["contribution"],
        reverse=True,
    )

    return contributions


def calculate_risk(findings):
    """
    Calculate the overall Cipher risk assessment.

    Parameters
    ----------
    findings : list[dict]
        Structured findings produced by Cipher's analysis pipeline.

    Returns
    -------
    dict
        Structured risk assessment containing:

        - score
        - assessment
        - confidence
        - risk_factors
        - contributions
    """

    if not findings:
        return {
            "score": 0,
            "assessment": "BENIGN",
            "confidence": "LOW",
            "risk_factors": [],
            "contributions": [],
        }

    score = _calculate_total_score(findings)

    assessment = _get_assessment(
        score,
        findings,
    )

    confidence = _calculate_overall_confidence(
        findings,
        score,
    )

    risk_factors = _build_risk_factors(
        findings
    )

    contributions = _build_contributions(
        findings
    )

    return {
        "score": score,
        "assessment": assessment,
        "confidence": confidence,
        "risk_factors": risk_factors,
        "contributions": contributions,
    }