import re


# ---------------------------------------------------------------------------
# Function detection
# ---------------------------------------------------------------------------

FUNCTION_DECLARATION_PATTERN = re.compile(
    r"\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\("
)

FUNCTION_EXPRESSION_PATTERN = re.compile(
    r"\bfunction\s*\(\s*[^)]*\s*\)"
)

ARROW_FUNCTION_PATTERN = re.compile(
    r"(?:\b(?:const|let|var)\s+)?"
    r"(?:[A-Za-z_$][A-Za-z0-9_$]*|\([^)]*\))"
    r"\s*=>"
)


def extract_js_functions(content):
    """
    Extract JavaScript function names and anonymous function counts.

    Returns:
        dict: Function analysis result.
    """

    named_functions = list(
        dict.fromkeys(
            FUNCTION_DECLARATION_PATTERN.findall(content)
        )
    )

    anonymous_functions = len(
        FUNCTION_EXPRESSION_PATTERN.findall(content)
    )

    arrow_functions = len(
        ARROW_FUNCTION_PATTERN.findall(content)
    )

    return {
        "named": named_functions,
        "anonymous_count": anonymous_functions,
        "arrow_count": arrow_functions,
        "total": (
            len(named_functions)
            + anonymous_functions
            + arrow_functions
        ),
    }


def detect_js_functions(content):
    """
    Detect whether JavaScript functions are present.

    Returns:
        bool: True if at least one function is detected.
    """

    result = extract_js_functions(content)

    return result["total"] > 0


# ---------------------------------------------------------------------------
# Variable detection
# ---------------------------------------------------------------------------

VARIABLE_PATTERN = re.compile(
    r"\b(const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)"
)


def extract_js_variables(content):
    """
    Extract JavaScript variable declarations.

    Returns:
        list[dict]: Variable declarations found in the content.
    """

    variables = []

    for declaration_type, name in VARIABLE_PATTERN.findall(content):
        variables.append(
            {
                "name": name,
                "declaration": declaration_type,
            }
        )

    return variables


# ---------------------------------------------------------------------------
# Console API detection
# ---------------------------------------------------------------------------

CONSOLE_PATTERN = re.compile(
    r"\bconsole\.([A-Za-z_$][A-Za-z0-9_$]*)\s*\("
)


def extract_console_apis(content):
    """
    Extract console API calls.

    Returns:
        list[str]: Console methods found in the content.
    """

    methods = CONSOLE_PATTERN.findall(content)

    return list(dict.fromkeys(methods))


# ---------------------------------------------------------------------------
# Browser API detection
# ---------------------------------------------------------------------------

BROWSER_API_PATTERNS = {
    "document": re.compile(r"\bdocument\."),
    "window": re.compile(r"\bwindow\."),
    "navigator": re.compile(r"\bnavigator\."),
}


def detect_browser_apis(content):
    """
    Detect common browser API usage.

    Returns:
        list[str]: Browser APIs detected.
    """

    detected = []

    for name, pattern in BROWSER_API_PATTERNS.items():
        if pattern.search(content):
            detected.append(name)

    return detected


# ---------------------------------------------------------------------------
# DOM / input analysis
# ---------------------------------------------------------------------------

DOM_API_PATTERNS = {
    "querySelector": re.compile(
        r"\bquerySelector\s*\("
    ),
    "querySelectorAll": re.compile(
        r"\bquerySelectorAll\s*\("
    ),
    "getElementById": re.compile(
        r"\bgetElementById\s*\("
    ),
    "getElementsByClassName": re.compile(
        r"\bgetElementsByClassName\s*\("
    ),
    "getElementsByTagName": re.compile(
        r"\bgetElementsByTagName\s*\("
    ),
    "addEventListener": re.compile(
        r"\baddEventListener\s*\("
    ),
}


def detect_dom_apis(content):
    """
    Detect common DOM manipulation and event APIs.

    Returns:
        list[str]: DOM APIs detected.
    """

    detected = []

    for name, pattern in DOM_API_PATTERNS.items():
        if pattern.search(content):
            detected.append(name)

    return detected


INPUT_PATTERN = re.compile(
    r"\.(?:value|valueAsText)\b"
)


def detect_input_value_access(content):
    """
    Detect access to input element values.

    Returns:
        bool: True if input value access is detected.
    """

    return bool(INPUT_PATTERN.search(content))


# ---------------------------------------------------------------------------
# Network API detection
# ---------------------------------------------------------------------------

NETWORK_API_PATTERNS = {
    "fetch": re.compile(
        r"\bfetch\s*\("
    ),
    "XMLHttpRequest": re.compile(
        r"\bXMLHttpRequest\b"
    ),
    "WebSocket": re.compile(
        r"\bWebSocket\s*\("
    ),
    "sendBeacon": re.compile(
        r"\bnavigator\.sendBeacon\s*\("
    ),
}


def detect_network_apis(content):
    """
    Detect common JavaScript network communication APIs.

    Returns:
        list[str]: Network APIs detected.
    """

    detected = []

    for name, pattern in NETWORK_API_PATTERNS.items():
        if pattern.search(content):
            detected.append(name)

    return detected


# ---------------------------------------------------------------------------
# Storage API detection
# ---------------------------------------------------------------------------

STORAGE_API_PATTERNS = {
    "localStorage": re.compile(
        r"\blocalStorage\b"
    ),
    "sessionStorage": re.compile(
        r"\bsessionStorage\b"
    ),
    "cookies": re.compile(
        r"\bdocument\.cookie\b"
    ),
}


def detect_storage_apis(content):
    """
    Detect browser storage mechanisms.

    Returns:
        list[str]: Storage mechanisms detected.
    """

    detected = []

    for name, pattern in STORAGE_API_PATTERNS.items():
        if pattern.search(content):
            detected.append(name)

    return detected


# ---------------------------------------------------------------------------
# Dynamic execution detection
# ---------------------------------------------------------------------------

DYNAMIC_EXECUTION_PATTERNS = {
    "eval": re.compile(
        r"\beval\s*\("
    ),
    "Function": re.compile(
        r"\bnew\s+Function\s*\("
    ),
    "setTimeout_string": re.compile(
        r"\bsetTimeout\s*\(\s*[\"'`]"
    ),
    "setInterval_string": re.compile(
        r"\bsetInterval\s*\(\s*[\"'`]"
    ),
}


def detect_dynamic_execution(content):
    """
    Detect JavaScript constructs capable of dynamic code execution.

    Returns:
        list[str]: Dynamic execution mechanisms detected.
    """

    detected = []

    for name, pattern in DYNAMIC_EXECUTION_PATTERNS.items():
        if pattern.search(content):
            detected.append(name)

    return detected


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

URL_PATTERN = re.compile(
    r"(?:https?|wss?|ws)://[^\s\"'<>]+",
    re.IGNORECASE
)


def extract_js_urls(content):
    """
    Extract HTTP, HTTPS, WS, and WSS URLs from JavaScript content.

    Returns:
        list[str]: Unique URLs found in the content.
    """

    urls = URL_PATTERN.findall(content)

    return list(dict.fromkeys(urls))


# ---------------------------------------------------------------------------
# Obfuscation indicators
# ---------------------------------------------------------------------------

LONG_STRING_PATTERN = re.compile(
    r"""["'`]([^"'`]{100,})["'`]"""
)

HEX_ESCAPE_PATTERN = re.compile(
    r"\\x[0-9a-fA-F]{2}"
)

UNICODE_ESCAPE_PATTERN = re.compile(
    r"\\u[0-9a-fA-F]{4}"
)


def detect_obfuscation_indicators(content):
    """
    Detect basic indicators that may be associated with obfuscated
    JavaScript.

    These observations do not prove that code is malicious or
    intentionally obfuscated.

    Returns:
        dict: Obfuscation indicators.
    """

    long_strings = LONG_STRING_PATTERN.findall(content)
    hex_escapes = HEX_ESCAPE_PATTERN.findall(content)
    unicode_escapes = UNICODE_ESCAPE_PATTERN.findall(content)

    return {
        "long_string_count": len(long_strings),
        "hex_escape_count": len(hex_escapes),
        "unicode_escape_count": len(unicode_escapes),
    }


# ---------------------------------------------------------------------------
# Complete JavaScript analysis
# ---------------------------------------------------------------------------

def analyze_javascript(content):
    """
    Run the complete static JavaScript analysis.

    This function observes JavaScript structure and behavior-related
    constructs. It does not execute the JavaScript.

    Returns:
        dict: Structured JavaScript analysis result.
    """

    functions = extract_js_functions(content)
    variables = extract_js_variables(content)
    console_apis = extract_console_apis(content)
    browser_apis = detect_browser_apis(content)
    dom_apis = detect_dom_apis(content)
    network_apis = detect_network_apis(content)
    storage_apis = detect_storage_apis(content)
    dynamic_execution = detect_dynamic_execution(content)
    urls = extract_js_urls(content)
    input_value_access = detect_input_value_access(content)
    obfuscation = detect_obfuscation_indicators(content)

    return {
        "functions": functions,
        "variables": variables,
        "console_apis": console_apis,
        "browser_apis": browser_apis,
        "dom_apis": dom_apis,
        "input_value_access": input_value_access,
        "network_apis": network_apis,
        "storage_apis": storage_apis,
        "dynamic_execution": dynamic_execution,
        "urls": urls,
        "obfuscation": obfuscation,
    }