import re
import ipaddress


URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE
)


# Common real-world top-level domains.
# This prevents JavaScript properties such as console.log
# from being incorrectly classified as domains.
COMMON_TLDS = (
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "mil",
    "io",
    "co",
    "uk",
    "de",
    "pk",
    "us",
    "info",
    "biz",
    "xyz",
    "site",
    "online",
    "app",
    "dev",
    "tech",
)


DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:"
    + "|".join(COMMON_TLDS)
    + r")\b",
    re.IGNORECASE
)


def extract_urls(content):
    """
    Extract HTTP and HTTPS URLs from text content.

    Returns:
        list[str]: Unique URLs found in the content.
    """

    urls = URL_PATTERN.findall(content)

    return list(dict.fromkeys(urls))


def extract_ipv4_addresses(content):
    """
    Extract valid IPv4 addresses from text content.

    Returns:
        list[str]: Unique IPv4 addresses found in the content.
    """

    candidates = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        content
    )

    addresses = []

    for candidate in candidates:

        try:
            address = ipaddress.ip_address(candidate)

            if address.version == 4:
                addresses.append(str(address))

        except ValueError:
            continue

    return list(dict.fromkeys(addresses))


def extract_domains(content):
    """
    Extract domain-like names from text content.

    Returns:
        list[str]: Unique domain names found in the content.
    """

    domains = DOMAIN_PATTERN.findall(content)

    return list(dict.fromkeys(domains))