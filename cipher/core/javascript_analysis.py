from cipher.core.evidence import build_finding


def analyze_javascript_findings(javascript_analysis):
    """
    Convert JavaScript analysis observations into structured findings.

    Severity describes the significance of an observed behavior.
    Confidence describes how strongly the analyzer detected that behavior.

    This function does not determine whether the file is malicious.
    """

    if not javascript_analysis:
        return []

    findings = []

    # -----------------------------------------------------------------------
    # Network communication
    # -----------------------------------------------------------------------

    network_apis = javascript_analysis.get("network_apis", [])

    if network_apis:
        evidence = ", ".join(network_apis)

        findings.append(
            build_finding(
                "JavaScript Behavior",
                "Network communication detected",
                evidence,
                (
                    "The JavaScript contains APIs capable of communicating "
                    "with remote systems. Network communication is common in "
                    "legitimate applications but can also be used to send "
                    "or retrieve data."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # -----------------------------------------------------------------------
    # Input value access
    # -----------------------------------------------------------------------

    if javascript_analysis.get("input_value_access"):
        findings.append(
            build_finding(
                "JavaScript Behavior",
                "Input value access detected",
                "Element value property access",
                (
                    "The JavaScript accesses the value of an input-related "
                    "element. This can be legitimate application behavior, "
                    "but it may also be relevant when investigating forms "
                    "or potential credential collection."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # -----------------------------------------------------------------------
    # Browser storage
    # -----------------------------------------------------------------------

    storage_apis = javascript_analysis.get("storage_apis", [])

    if storage_apis:
        evidence = ", ".join(storage_apis)

        findings.append(
            build_finding(
                "JavaScript Behavior",
                "Browser storage access detected",
                evidence,
                (
                    "The JavaScript accesses browser storage mechanisms. "
                    "Storage access can be legitimate, but stored data may "
                    "include application state, identifiers, or other "
                    "information depending on the application."
                ),
                "LOW",
                "HIGH"
            )
        )

    # -----------------------------------------------------------------------
    # Dynamic execution
    # -----------------------------------------------------------------------

    dynamic_execution = javascript_analysis.get(
        "dynamic_execution",
        []
    )

    if dynamic_execution:
        evidence = ", ".join(dynamic_execution)

        findings.append(
            build_finding(
                "JavaScript Behavior",
                "Dynamic code execution detected",
                evidence,
                (
                    "The JavaScript contains constructs capable of executing "
                    "code dynamically. Dynamic execution can be legitimate, "
                    "but it is also commonly investigated because it can "
                    "hide or generate code at runtime."
                ),
                "HIGH",
                "HIGH"
            )
        )

    # -----------------------------------------------------------------------
    # Browser APIs
    # -----------------------------------------------------------------------

    browser_apis = javascript_analysis.get(
        "browser_apis",
        []
    )

    if browser_apis:
        evidence = ", ".join(browser_apis)

        findings.append(
            build_finding(
                "JavaScript Behavior",
                "Browser API usage detected",
                evidence,
                (
                    "The JavaScript interacts with browser-provided APIs. "
                    "These APIs are commonly used by normal web applications "
                    "to access browser functionality."
                ),
                "LOW",
                "HIGH"
            )
        )

    # -----------------------------------------------------------------------
    # DOM APIs
    # -----------------------------------------------------------------------

    dom_apis = javascript_analysis.get(
        "dom_apis",
        []
    )

    if dom_apis:
        evidence = ", ".join(dom_apis)

        findings.append(
            build_finding(
                "JavaScript Behavior",
                "DOM manipulation detected",
                evidence,
                (
                    "The JavaScript interacts with the document structure "
                    "through DOM APIs. This is common in interactive web "
                    "applications."
                ),
                "LOW",
                "HIGH"
            )
        )

    # -----------------------------------------------------------------------
    # Console APIs
    # -----------------------------------------------------------------------

    console_apis = javascript_analysis.get(
        "console_apis",
        []
    )

    if console_apis:
        evidence = ", ".join(
            f"console.{method}"
            for method in console_apis
        )

        findings.append(
            build_finding(
                "JavaScript Behavior",
                "Console API usage detected",
                evidence,
                (
                    "The JavaScript uses browser console APIs. This is "
                    "normally a development or debugging behavior and "
                    "is not inherently suspicious."
                ),
                "LOW",
                "HIGH"
            )
        )

    # -----------------------------------------------------------------------
    # JavaScript URLs
    # -----------------------------------------------------------------------

    urls = javascript_analysis.get(
        "urls",
        []
    )

    if urls:
        evidence = "\n".join(urls)

        findings.append(
            build_finding(
                "JavaScript Network Indicator",
                "JavaScript URL detected",
                evidence,
                (
                    "The JavaScript contains one or more HTTP or HTTPS "
                    "URLs. The presence of a URL alone does not indicate "
                    "malicious behavior."
                ),
                "LOW",
                "HIGH"
            )
        )

    # -----------------------------------------------------------------------
    # Obfuscation indicators
    # -----------------------------------------------------------------------

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

    if (
        long_string_count > 0
        or hex_escape_count > 0
        or unicode_escape_count > 0
    ):
        evidence_parts = []

        if long_string_count > 0:
            evidence_parts.append(
                f"long strings: {long_string_count}"
            )

        if hex_escape_count > 0:
            evidence_parts.append(
                f"hex escapes: {hex_escape_count}"
            )

        if unicode_escape_count > 0:
            evidence_parts.append(
                f"unicode escapes: {unicode_escape_count}"
            )

        evidence = ", ".join(evidence_parts)

        findings.append(
            build_finding(
                "JavaScript Analysis",
                "Potential obfuscation indicators detected",
                evidence,
                (
                    "The JavaScript contains patterns that can be associated "
                    "with obfuscated code. These indicators do not prove "
                    "that the code is malicious or intentionally obfuscated."
                ),
                "MEDIUM",
                "MEDIUM"
            )
        )

    return findings