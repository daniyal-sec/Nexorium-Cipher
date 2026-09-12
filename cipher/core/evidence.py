def build_finding(
    category,
    finding,
    evidence,
    explanation,
    severity,
    confidence,
    tags=None
):
    """
    Build a structured Cipher finding.

    Tags provide machine-readable evidence identifiers that can be
    consumed by later analysis stages such as the Phase 3 correlation
    engine.

    Existing findings remain compatible because tags are optional.
    """

    return {
        "category": category,
        "finding": finding,
        "evidence": evidence,
        "explanation": explanation,
        "severity": severity,
        "confidence": confidence,
        "tags": tags or []
    }


def create_finding(extension, detected_format, valid_extensions):

    if detected_format == "unknown":
        return [
            build_finding(
                "File Identification",
                "Unknown file format",
                "No known file-format signature matched the beginning of the file.",
                (
                    "Cipher could not identify the file format using its current "
                    "signature database. This does not indicate that the file is malicious."
                ),
                "LOW",
                "HIGH"
            )
        ]

    if extension not in valid_extensions:
        return [
            build_finding(
                "File Identification",
                "Extension mismatch",
                f"Extension '{extension}' does not match detected format '{detected_format}'.",
                (
                    "The file extension does not match the detected file format. "
                    "This may be benign, accidental, or potentially suspicious."
                ),
                "LOW",
                "HIGH"
            )
        ]

    return []