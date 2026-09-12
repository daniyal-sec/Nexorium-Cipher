from cipher.core.evidence import build_finding


def _get_tags(finding):
    """
    Return the machine-readable evidence tags attached to a finding.
    """

    return set(finding.get("tags", []))


def _find_findings_by_tag(findings, tag):
    """
    Return all findings containing the supplied evidence tag.
    """

    return [
        finding
        for finding in findings
        if tag in _get_tags(finding)
    ]


def _build_evidence_chain(source_findings):
    """
    Build a structured representation of the findings that
    contributed to a correlated finding.
    """

    chain = []

    for finding in source_findings:
        chain.append(
            {
                "category": finding.get("category"),
                "finding": finding.get("finding"),
                "evidence": finding.get("evidence"),
                "tags": finding.get("tags", []),
            }
        )

    return chain


def _correlation_identity(finding):
    """
    Build a stable identity for a correlated finding.
    """

    tags = finding.get("tags", [])

    return tuple(sorted(tags))


def _deduplicate_correlated_findings(findings):
    """
    Remove duplicate correlated findings.

    Source findings are never removed.
    """

    unique_findings = []
    seen = set()

    for finding in findings:

        identity = _correlation_identity(finding)

        if not identity:
            unique_findings.append(finding)
            continue

        if identity in seen:
            continue

        seen.add(identity)
        unique_findings.append(finding)

    return unique_findings


# ---------------------------------------------------------------------------
# Correlation strength
# ---------------------------------------------------------------------------

def _calculate_correlation_strength(
    strong_evidence_count,
    supporting_evidence_count=0,
    rule_strength="normal"
):
    """
    Calculate the strength of a behavioral correlation.

    strong_evidence_count:
        Number of independent strong evidence groups.

    supporting_evidence_count:
        Additional evidence that strengthens an existing correlation.

    rule_strength:
        Optional rule-level weighting.

        normal:
            Standard correlation.

        strong:
            The combination itself is considered a strong behavioral
            pattern when the required evidence groups are present.
    """

    score = (
        strong_evidence_count
        + supporting_evidence_count
    )

    if rule_strength == "strong" and strong_evidence_count >= 2:
        severity = "HIGH"
        confidence = "HIGH"

    elif strong_evidence_count >= 3:
        severity = "HIGH"
        confidence = "HIGH"

    elif strong_evidence_count >= 2:
        severity = "MEDIUM"
        confidence = "HIGH"

    elif strong_evidence_count >= 1:
        severity = "LOW"
        confidence = "HIGH"

    else:
        severity = "LOW"
        confidence = "LOW"

    return {
        "score": score,
        "severity": severity,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Credential / data transmission
# ---------------------------------------------------------------------------

def _build_credential_transmission_correlation(findings):
    """
    Detect potential credential/data transmission from correlated
    input, sensitive-data and network observations.
    """

    input_access_findings = _find_findings_by_tag(
        findings,
        "javascript.input.value"
    )

    sensitive_data_findings = _find_findings_by_tag(
        findings,
        "javascript.sensitive_data"
    )

    network_findings = _find_findings_by_tag(
        findings,
        "javascript.network"
    )

    external_destination_findings = _find_findings_by_tag(
        findings,
        "network.external_destination"
    )

    if not (
        input_access_findings
        and sensitive_data_findings
        and network_findings
    ):
        return None

    strong_evidence_count = 3

    supporting_evidence_count = (
        1
        if external_destination_findings
        else 0
    )

    strength = _calculate_correlation_strength(
        strong_evidence_count=strong_evidence_count,
        supporting_evidence_count=supporting_evidence_count,
        rule_strength="strong"
    )

    source_findings = (
        input_access_findings
        + sensitive_data_findings
        + network_findings
        + external_destination_findings
    )

    evidence_lines = []

    for finding in input_access_findings:
        evidence_lines.append(
            f"Input evidence: {finding['evidence']}"
        )

    for finding in sensitive_data_findings:
        evidence_lines.append(
            f"Sensitive data evidence: {finding['evidence']}"
        )

    for finding in network_findings:
        evidence_lines.append(
            f"Network evidence: {finding['evidence']}"
        )

    for finding in external_destination_findings:
        evidence_lines.append(
            "External destination evidence: "
            f"{finding['evidence']}"
        )

    explanation = (
        "Cipher correlated multiple independent observations: "
        "the file accesses user input values, references sensitive "
        "data, and contains network communication. Together, these "
        "signals indicate potential credential or sensitive-data "
        "collection followed by transmission."
    )

    if external_destination_findings:
        explanation += (
            " An external destination strengthens the correlation "
            "because the collected data may be intended for transfer "
            "outside the local application context."
        )

    correlated_finding = build_finding(
        "Behavioral Correlation",
        "Potential credential/data transmission",
        "\n".join(evidence_lines),
        explanation,
        strength["severity"],
        strength["confidence"],
        tags=[
            "behavior.credential_collection",
            "behavior.data_transmission",
            "correlation.input_to_network",
        ]
    )

    correlated_finding["correlation_score"] = strength["score"]

    correlated_finding["evidence_chain"] = (
        _build_evidence_chain(source_findings)
    )

    return correlated_finding


# ---------------------------------------------------------------------------
# Obfuscated execution
# ---------------------------------------------------------------------------

def _build_obfuscated_execution_correlation(findings):
    """
    Detect potential obfuscated code execution from correlated
    obfuscation and dynamic-execution observations.
    """

    obfuscation_findings = _find_findings_by_tag(
        findings,
        "javascript.obfuscation"
    )

    dynamic_execution_findings = _find_findings_by_tag(
        findings,
        "javascript.dynamic_execution"
    )

    if not (
        obfuscation_findings
        and dynamic_execution_findings
    ):
        return None

    strong_evidence_count = 2

    strength = _calculate_correlation_strength(
        strong_evidence_count=strong_evidence_count,
        supporting_evidence_count=0,
        rule_strength="strong"
    )

    source_findings = (
        obfuscation_findings
        + dynamic_execution_findings
    )

    evidence_lines = []

    for finding in obfuscation_findings:
        evidence_lines.append(
            f"Obfuscation evidence: {finding['evidence']}"
        )

    for finding in dynamic_execution_findings:
        evidence_lines.append(
            f"Dynamic execution evidence: {finding['evidence']}"
        )

    explanation = (
        "Cipher correlated obfuscation indicators with a dynamic "
        "code-execution mechanism. This combination can indicate "
        "that code or payload content is being concealed and then "
        "executed dynamically."
    )

    correlated_finding = build_finding(
        "Behavioral Correlation",
        "Potential obfuscated code execution",
        "\n".join(evidence_lines),
        explanation,
        strength["severity"],
        strength["confidence"],
        tags=[
            "behavior.obfuscated_execution",
            "correlation.obfuscation_to_execution",
        ]
    )

    correlated_finding["correlation_score"] = (
        strength["score"]
    )

    correlated_finding["evidence_chain"] = (
        _build_evidence_chain(source_findings)
    )

    return correlated_finding


# ---------------------------------------------------------------------------
# Main correlation pipeline
# ---------------------------------------------------------------------------

def correlate_findings(findings):
    """
    Run all currently available Phase 3 behavioral correlation rules.

    Correlation rules operate on machine-readable evidence tags.

    Correlated findings are deduplicated before being returned.
    """

    findings = findings or []

    correlated_findings = []

    credential_transmission = (
        _build_credential_transmission_correlation(
            findings
        )
    )

    if credential_transmission:
        correlated_findings.append(
            credential_transmission
        )

    obfuscated_execution = (
        _build_obfuscated_execution_correlation(
            findings
        )
    )

    if obfuscated_execution:
        correlated_findings.append(
            obfuscated_execution
        )

    return _deduplicate_correlated_findings(
        correlated_findings
    )