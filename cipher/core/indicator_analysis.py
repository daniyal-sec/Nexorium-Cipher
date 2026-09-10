from cipher.core.evidence import build_finding


def analyze_indicators(
    urls=None,
    ipv4_addresses=None,
    domains=None
):
    """
    Convert extracted network indicators into structured findings.

    This module observes indicators. It does not determine whether
    an indicator is malicious.
    """

    urls = urls or []
    ipv4_addresses = ipv4_addresses or []
    domains = domains or []

    findings = []

    for url in urls:
        findings.append(
            build_finding(
                "Network Indicator",
                "External URL detected",
                url,
                (
                    "The file contains an HTTP or HTTPS URL. "
                    "The presence of a URL alone does not indicate "
                    "that the file is malicious."
                ),
                "LOW",
                "HIGH"
            )
        )

    for address in ipv4_addresses:
        findings.append(
            build_finding(
                "Network Indicator",
                "IPv4 address detected",
                address,
                (
                    "The file contains an IPv4 address. "
                    "The presence of an IP address alone does not "
                    "indicate that the file is malicious."
                ),
                "LOW",
                "HIGH"
            )
        )

    for domain in domains:
        findings.append(
            build_finding(
                "Network Indicator",
                "Domain detected",
                domain,
                (
                    "The file contains a domain name. "
                    "The presence of a domain alone does not indicate "
                    "that the file is malicious."
                ),
                "LOW",
                "HIGH"
            )
        )

    return findings