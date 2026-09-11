from cipher.core.evidence import build_finding


def analyze_javascript_findings(javascript_analysis):
    """
    Convert JavaScript analyzer observations into structured findings.

    This layer interprets observations and assigns severity/confidence.
    It does not make an overall malware verdict.
    """

    if not javascript_analysis:
        return []

    findings = []

    # --------------------------------------------------------------
    # Network communication
    # --------------------------------------------------------------

    network_apis = javascript_analysis.get(
        "network_apis",
        []
    )

    if network_apis:
        findings.append(
            build_finding(
                "JavaScript Behavior",
                "Network communication detected",
                ", ".join(network_apis),
                (
                    "The JavaScript contains APIs capable of "
                    "communicating with remote systems. Network "
                    "communication is common in legitimate applications "
                    "but can also be used to send or retrieve data."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Input value access
    # --------------------------------------------------------------

    if javascript_analysis.get("input_value_access"):

        findings.append(
            build_finding(
                "JavaScript Behavior",
                "Input value access detected",
                "Element value property access",
                (
                    "The JavaScript accesses the value of an "
                    "input-related element. This can be legitimate "
                    "application behavior, but it may also be relevant "
                    "when investigating forms or potential credential "
                    "collection."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # User input events
    # --------------------------------------------------------------

    input_collection_events = javascript_analysis.get(
        "input_collection_events",
        []
    )

    if input_collection_events:

        findings.append(
            build_finding(
                "JavaScript Input Analysis",
                "User input event handlers detected",
                ", ".join(input_collection_events),
                (
                    "The JavaScript registers event handlers associated "
                    "with user input or form submission. These events "
                    "are commonly used by legitimate web applications, "
                    "but they are also relevant when investigating how "
                    "user-entered data may be collected or processed."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Sensitive data references
    # --------------------------------------------------------------

    sensitive_data = javascript_analysis.get(
        "sensitive_data",
        []
    )

    if sensitive_data:

        findings.append(
            build_finding(
                "JavaScript Data Access",
                "Sensitive data references detected",
                ", ".join(sensitive_data),
                (
                    "The JavaScript contains references to data "
                    "categories that may represent credentials, "
                    "authentication data, identifiers, or other "
                    "sensitive information. These references alone "
                    "do not prove that sensitive data is being "
                    "collected or transmitted."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Cookie access
    # --------------------------------------------------------------

    if javascript_analysis.get("cookie_access"):

        findings.append(
            build_finding(
                "JavaScript Data Access",
                "Browser cookie access detected",
                "document.cookie",
                (
                    "The JavaScript accesses browser cookies through "
                    "document.cookie. Cookies can contain session "
                    "identifiers, preferences, or other application "
                    "data."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Browser storage
    # --------------------------------------------------------------

    storage_apis = javascript_analysis.get(
        "storage_apis",
        []
    )

    if storage_apis:

        findings.append(
            build_finding(
                "JavaScript Behavior",
                "Browser storage access detected",
                ", ".join(storage_apis),
                (
                    "The JavaScript accesses browser storage mechanisms. "
                    "Storage access can be legitimate, but stored data "
                    "may include application state, identifiers, or "
                    "other information depending on the application."
                ),
                "LOW",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Dynamic execution
    # --------------------------------------------------------------

    dynamic_execution = javascript_analysis.get(
        "dynamic_execution",
        []
    )

    if dynamic_execution:

        findings.append(
            build_finding(
                "JavaScript Behavior",
                "Dynamic code execution detected",
                ", ".join(dynamic_execution),
                (
                    "The JavaScript contains constructs capable of "
                    "executing code dynamically. Dynamic execution "
                    "can be legitimate, but it is also commonly "
                    "investigated because it can hide or generate "
                    "code at runtime."
                ),
                "HIGH",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Browser APIs
    # --------------------------------------------------------------

    browser_apis = javascript_analysis.get(
        "browser_apis",
        []
    )

    if browser_apis:

        findings.append(
            build_finding(
                "JavaScript Behavior",
                "Browser API usage detected",
                ", ".join(browser_apis),
                (
                    "The JavaScript interacts with browser-provided "
                    "APIs. These APIs are commonly used by normal "
                    "web applications to access browser functionality."
                ),
                "LOW",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # DOM APIs
    # --------------------------------------------------------------

    dom_apis = javascript_analysis.get(
        "dom_apis",
        []
    )

    if dom_apis:

        findings.append(
            build_finding(
                "JavaScript Behavior",
                "DOM manipulation detected",
                ", ".join(dom_apis),
                (
                    "The JavaScript interacts with the document "
                    "structure through DOM APIs. This is common "
                    "in interactive web applications."
                ),
                "LOW",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Console APIs
    # --------------------------------------------------------------

    console_apis = javascript_analysis.get(
        "console_apis",
        []
    )

    if console_apis:

        findings.append(
            build_finding(
                "JavaScript Behavior",
                "Console API usage detected",
                ", ".join(console_apis),
                (
                    "The JavaScript uses browser console APIs. "
                    "This is normally a development or debugging "
                    "behavior and is not inherently suspicious."
                ),
                "LOW",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # JavaScript URLs
    # --------------------------------------------------------------

    urls = javascript_analysis.get(
        "urls",
        []
    )

    if urls:

        findings.append(
            build_finding(
                "JavaScript Network Indicator",
                "JavaScript URL detected",
                "\n".join(urls),
                (
                    "The JavaScript contains one or more HTTP, "
                    "HTTPS, WS, or WSS URLs. The presence of a URL "
                    "alone does not indicate malicious behavior."
                ),
                "LOW",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Improved obfuscation analysis
    # --------------------------------------------------------------

    obfuscation = javascript_analysis.get(
        "obfuscation",
        {}
    )

    obfuscation_score = obfuscation.get(
        "score",
        0
    )

    obfuscation_assessment = obfuscation.get(
        "assessment",
        "NONE"
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

    if obfuscation_score > 0:

        evidence_parts = []

        if long_string_count:
            evidence_parts.append(
                f"long strings: {long_string_count}"
            )

        if hex_escape_count:
            evidence_parts.append(
                f"hex escapes: {hex_escape_count}"
            )

        if unicode_escape_count:
            evidence_parts.append(
                f"unicode escapes: {unicode_escape_count}"
            )

        if base64_like_string_count:
            evidence_parts.append(
                (
                    "base64-like strings: "
                    f"{base64_like_string_count}"
                )
            )

        evidence = ", ".join(evidence_parts)

        if obfuscation_assessment == "HIGH":
            severity = "HIGH"
            confidence = "HIGH"

        else:
            severity = "MEDIUM"
            confidence = "MEDIUM"

        findings.append(
            build_finding(
                "JavaScript Analysis",
                "Potential obfuscation indicators detected",
                evidence,
                (
                    "The JavaScript contains multiple patterns "
                    "associated with encoded or obfuscated content. "
                    "The finding is based on stronger encoding "
                    "indicators rather than string length alone."
                ),
                severity,
                confidence
            )
        )

    return findings