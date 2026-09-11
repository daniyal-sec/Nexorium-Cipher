import re
import ipaddress
from urllib.parse import urlparse


def detect_html_forms(content):
    """
    Detect whether HTML content contains a form element.

    Returns:
        bool: True if a form element is detected, otherwise False.
    """

    return "<form" in content.lower()


def extract_html_forms(content):
    """
    Extract HTML form opening tags from content.

    Returns:
        list[str]: Form opening tags found in the content.
    """

    pattern = re.compile(
        r"<form\b[^>]*>",
        re.IGNORECASE
    )

    return pattern.findall(content)


def detect_password_inputs(content):
    """
    Detect password input fields in HTML content.

    Returns:
        bool: True if a password input is detected, otherwise False.
    """

    pattern = re.compile(
        r"<input\b[^>]*type\s*=\s*[\"']password[\"'][^>]*>",
        re.IGNORECASE
    )

    return bool(pattern.search(content))


def extract_password_inputs(content):
    """
    Extract password input elements from HTML content.

    Returns:
        list[str]: Password input tags found in the content.
    """

    pattern = re.compile(
        r"<input\b[^>]*type\s*=\s*[\"']password[\"'][^>]*>",
        re.IGNORECASE
    )

    return pattern.findall(content)


def extract_form_actions(content):
    """
    Extract action URLs from HTML form elements.

    Returns:
        list[str]: Action values found in form elements.
    """

    pattern = re.compile(
        r"<form\b[^>]*\baction\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
        re.IGNORECASE
    )

    return pattern.findall(content)


def extract_form_methods(content):
    """
    Extract method values from HTML form elements.

    Returns:
        list[str]: Form methods found in the content.
    """

    forms = extract_html_forms(content)

    methods = []

    for form in forms:

        match = re.search(
            r'\bmethod\s*=\s*["\']([^"\']+)["\']',
            form,
            re.IGNORECASE
        )

        if match:
            methods.append(
                match.group(1).upper()
            )

    return methods


# ---------------------------------------------------------------------------
# Hidden Input Analysis
# ---------------------------------------------------------------------------

HIDDEN_INPUT_PATTERN = re.compile(
    r"<input\b[^>]*type\s*=\s*[\"']hidden[\"'][^>]*>",
    re.IGNORECASE
)


def detect_hidden_inputs(content):
    """
    Detect hidden input fields in HTML content.

    Returns:
        bool: True if a hidden input is detected, otherwise False.
    """

    return bool(
        HIDDEN_INPUT_PATTERN.search(content)
    )


def extract_hidden_inputs(content):
    """
    Extract hidden input elements from HTML content.

    Returns:
        list[str]: Hidden input tags found in the content.
    """

    return HIDDEN_INPUT_PATTERN.findall(content)


# ---------------------------------------------------------------------------
# Script Tag Analysis
# ---------------------------------------------------------------------------

SCRIPT_TAG_PATTERN = re.compile(
    r"<script\b[^>]*>",
    re.IGNORECASE
)


def detect_script_tags(content):
    """
    Detect script elements in HTML content.

    Returns:
        bool: True if a script tag is detected, otherwise False.
    """

    return bool(
        SCRIPT_TAG_PATTERN.search(content)
    )


def extract_script_tags(content):
    """
    Extract script opening tags from HTML content.

    Returns:
        list[str]: Script opening tags found in the content.
    """

    return SCRIPT_TAG_PATTERN.findall(content)


# ---------------------------------------------------------------------------
# External JavaScript Source Analysis
# ---------------------------------------------------------------------------

SCRIPT_SRC_PATTERN = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
    re.IGNORECASE
)


def detect_external_javascript(content):
    """
    Detect script tags that load JavaScript from a source.

    Returns:
        bool: True if an external JavaScript source is detected,
        otherwise False.
    """

    return bool(
        SCRIPT_SRC_PATTERN.search(content)
    )


def extract_external_javascript_sources(content):
    """
    Extract JavaScript source URLs or paths from script tags.

    Returns:
        list[str]: External JavaScript sources found in the content.
    """

    sources = SCRIPT_SRC_PATTERN.findall(content)

    return list(
        dict.fromkeys(sources)
    )


# ---------------------------------------------------------------------------
# Form Destination Analysis
# ---------------------------------------------------------------------------

def analyze_form_destinations(actions):
    """
    Analyze form action destinations.

    This function observes transport schemes and destination types.
    It does not determine whether a destination is malicious.

    Returns:
        dict: Structured form-destination observations.
    """

    actions = actions or []

    http_destinations = []
    https_destinations = []
    ip_destinations = []
    relative_destinations = []
    unusual_scheme_destinations = []

    for action in actions:

        action = action.strip()

        if not action:
            continue

        parsed = urlparse(action)

        scheme = parsed.scheme.lower()

        if scheme == "http":
            http_destinations.append(action)

        elif scheme == "https":
            https_destinations.append(action)

        elif scheme:
            unusual_scheme_destinations.append(action)

        else:
            relative_destinations.append(action)

        hostname = parsed.hostname

        if hostname:

            try:
                ipaddress.ip_address(hostname)

                if action not in ip_destinations:
                    ip_destinations.append(action)

            except ValueError:
                pass

    return {
        "http_destinations": list(
            dict.fromkeys(http_destinations)
        ),
        "https_destinations": list(
            dict.fromkeys(https_destinations)
        ),
        "ip_destinations": list(
            dict.fromkeys(ip_destinations)
        ),
        "relative_destinations": list(
            dict.fromkeys(relative_destinations)
        ),
        "unusual_scheme_destinations": list(
            dict.fromkeys(unusual_scheme_destinations)
        ),
    }


# ---------------------------------------------------------------------------
# Iframe Analysis
# ---------------------------------------------------------------------------

IFRAME_PATTERN = re.compile(
    r"<iframe\b[^>]*>",
    re.IGNORECASE
)


IFRAME_SRC_PATTERN = re.compile(
    r"<iframe\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
    re.IGNORECASE
)


def detect_iframes(content):
    """
    Detect iframe elements in HTML content.

    Returns:
        bool: True if an iframe is detected, otherwise False.
    """

    return bool(
        IFRAME_PATTERN.search(content)
    )


def extract_iframes(content):
    """
    Extract iframe opening tags from HTML content.

    Returns:
        list[str]: Iframe opening tags found in the content.
    """

    return IFRAME_PATTERN.findall(content)


def extract_iframe_sources(content):
    """
    Extract iframe source URLs or paths.

    Returns:
        list[str]: Iframe source values found in the content.
    """

    sources = IFRAME_SRC_PATTERN.findall(content)

    return list(
        dict.fromkeys(sources)
    )


# ---------------------------------------------------------------------------
# External Image Resource Analysis
# ---------------------------------------------------------------------------

IMAGE_SRC_PATTERN = re.compile(
    r"<img\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
    re.IGNORECASE
)


def extract_image_sources(content):
    """
    Extract image source URLs or paths.

    Returns:
        list[str]: Image source values found in the content.
    """

    sources = IMAGE_SRC_PATTERN.findall(content)

    return list(
        dict.fromkeys(sources)
    )


# ---------------------------------------------------------------------------
# External Stylesheet Resource Analysis
# ---------------------------------------------------------------------------

LINK_HREF_PATTERN = re.compile(
    r"<link\b[^>]*\bhref\s*=\s*[\"']([^\"']+)[\"'][^>]*>",
    re.IGNORECASE
)


def extract_link_resources(content):
    """
    Extract href values from link elements.

    Returns:
        list[str]: Link resource values found in the content.
    """

    sources = LINK_HREF_PATTERN.findall(content)

    return list(
        dict.fromkeys(sources)
    )


# ---------------------------------------------------------------------------
# External Resource Classification
# ---------------------------------------------------------------------------

def classify_resource_url(resource):
    """
    Classify an HTML resource by its URL/path characteristics.

    Returns:
        str: Resource classification.
    """

    resource = resource.strip()

    if not resource:
        return "empty"

    parsed = urlparse(resource)

    if parsed.scheme in ("http", "https"):
        return "external"

    if parsed.scheme:
        return "unusual_scheme"

    return "relative"


def analyze_html_resources(
    iframe_sources=None,
    image_sources=None,
    link_resources=None,
):
    """
    Analyze iframe, image, and link resources.

    Returns:
        dict: Structured HTML resource observations.
    """

    iframe_sources = iframe_sources or []
    image_sources = image_sources or []
    link_resources = link_resources or []

    external_iframes = []
    external_images = []
    external_links = []

    unusual_iframes = []
    unusual_images = []
    unusual_links = []

    for source in iframe_sources:

        classification = classify_resource_url(source)

        if classification == "external":
            external_iframes.append(source)

        elif classification == "unusual_scheme":
            unusual_iframes.append(source)

    for source in image_sources:

        classification = classify_resource_url(source)

        if classification == "external":
            external_images.append(source)

        elif classification == "unusual_scheme":
            unusual_images.append(source)

    for source in link_resources:

        classification = classify_resource_url(source)

        if classification == "external":
            external_links.append(source)

        elif classification == "unusual_scheme":
            unusual_links.append(source)

    return {
        "external_iframes": list(
            dict.fromkeys(external_iframes)
        ),
        "external_images": list(
            dict.fromkeys(external_images)
        ),
        "external_links": list(
            dict.fromkeys(external_links)
        ),
        "unusual_iframes": list(
            dict.fromkeys(unusual_iframes)
        ),
        "unusual_images": list(
            dict.fromkeys(unusual_images)
        ),
        "unusual_links": list(
            dict.fromkeys(unusual_links)
        ),
    }


# ---------------------------------------------------------------------------
# Complete HTML Analysis
# ---------------------------------------------------------------------------

def analyze_html(content):
    """
    Analyze HTML content for forms, password inputs, hidden inputs,
    script tags, external JavaScript sources, form actions, methods,
    form destination characteristics, iframes, and external resources.

    Returns:
        dict: Structured HTML analysis result.
    """

    forms = extract_html_forms(content)

    password_inputs = extract_password_inputs(content)

    hidden_inputs = extract_hidden_inputs(content)

    script_tags = extract_script_tags(content)

    external_javascript_sources = (
        extract_external_javascript_sources(content)
    )

    actions = extract_form_actions(content)

    methods = extract_form_methods(content)

    form_destinations = analyze_form_destinations(
        actions
    )

    iframes = extract_iframes(content)

    iframe_sources = extract_iframe_sources(content)

    image_sources = extract_image_sources(content)

    link_resources = extract_link_resources(content)

    html_resources = analyze_html_resources(
        iframe_sources=iframe_sources,
        image_sources=image_sources,
        link_resources=link_resources,
    )

    return {
        "forms_detected": bool(forms),
        "forms": forms,

        "password_inputs_detected": bool(
            password_inputs
        ),
        "password_inputs": password_inputs,

        "hidden_inputs_detected": bool(
            hidden_inputs
        ),
        "hidden_inputs": hidden_inputs,

        "script_tags_detected": bool(
            script_tags
        ),
        "script_tags": script_tags,

        "external_javascript_detected": bool(
            external_javascript_sources
        ),
        "external_javascript_sources": (
            external_javascript_sources
        ),

        "form_actions": actions,
        "form_methods": methods,

        "form_destinations": form_destinations,

        "iframes_detected": bool(iframes),
        "iframes": iframes,
        "iframe_sources": iframe_sources,

        "image_sources": image_sources,
        "link_resources": link_resources,

        "html_resources": html_resources,
    }