import re


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
    named_functions = list(dict.fromkeys(
        FUNCTION_DECLARATION_PATTERN.findall(content)
    ))

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
    result = extract_js_functions(content)
    return result["total"] > 0


VARIABLE_PATTERN = re.compile(
    r"\b(const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)"
)


def extract_js_variables(content):
    variables = []

    for declaration_type, name in VARIABLE_PATTERN.findall(content):
        variables.append({
            "name": name,
            "declaration": declaration_type
        })

    return variables


CONSOLE_PATTERN = re.compile(
    r"\bconsole\.([A-Za-z_$][A-Za-z0-9_$]*)\s*\("
)


def extract_console_apis(content):
    methods = CONSOLE_PATTERN.findall(content)

    return list(dict.fromkeys(methods))


BROWSER_API_PATTERNS = {
    "document": re.compile(r"\bdocument\."),
    "window": re.compile(r"\bwindow\."),
    "navigator": re.compile(r"\bnavigator\."),
}


def detect_browser_apis(content):
    detected = []

    for name, pattern in BROWSER_API_PATTERNS.items():

        if pattern.search(content):
            detected.append(name)

    return detected


DOM_API_PATTERNS = {
    "querySelector": re.compile(r"\bquerySelector\s*\("),
    "querySelectorAll": re.compile(r"\bquerySelectorAll\s*\("),
    "getElementById": re.compile(r"\bgetElementById\s*\("),
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
    detected = []

    for name, pattern in DOM_API_PATTERNS.items():

        if pattern.search(content):
            detected.append(name)

    return detected


INPUT_PATTERN = re.compile(
    r"\.(?:value|valueAsText)\b"
)


def detect_input_value_access(content):
    return bool(INPUT_PATTERN.search(content))


EVENT_HANDLER_PATTERN = re.compile(
    r"\.addEventListener\s*\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE
)


INTERESTING_INPUT_EVENTS = {
    "input",
    "change",
    "submit",
    "keydown",
    "keyup",
    "keypress",
}


def extract_event_handlers(content):
    events = EVENT_HANDLER_PATTERN.findall(content)

    return list(
        dict.fromkeys(
            event.lower()
            for event in events
        )
    )


def detect_input_collection_events(content):
    events = extract_event_handlers(content)

    return [
        event
        for event in events
        if event in INTERESTING_INPUT_EVENTS
    ]


def detect_form_submission_events(content):
    return "submit" in detect_input_collection_events(content)


NETWORK_API_PATTERNS = {
    "fetch": re.compile(r"\bfetch\s*\("),
    "XMLHttpRequest": re.compile(r"\bXMLHttpRequest\b"),
    "WebSocket": re.compile(r"\bWebSocket\s*\("),
    "sendBeacon": re.compile(
        r"\bnavigator\.sendBeacon\s*\("
    ),
}


def detect_network_apis(content):
    detected = []

    for name, pattern in NETWORK_API_PATTERNS.items():

        if pattern.search(content):
            detected.append(name)

    return detected


STORAGE_API_PATTERNS = {
    "localStorage": re.compile(r"\blocalStorage\b"),
    "sessionStorage": re.compile(r"\bsessionStorage\b"),
    "cookies": re.compile(r"\bdocument\.cookie\b"),
}


def detect_storage_apis(content):
    detected = []

    for name, pattern in STORAGE_API_PATTERNS.items():

        if pattern.search(content):
            detected.append(name)

    return detected


DYNAMIC_EXECUTION_PATTERNS = {
    "eval": re.compile(r"\beval\s*\("),
    "Function": re.compile(r"\bnew\s+Function\s*\("),
    "setTimeout_string": re.compile(
        r"\bsetTimeout\s*\(\s*[\"'`]"
    ),
    "setInterval_string": re.compile(
        r"\bsetInterval\s*\(\s*[\"'`]"
    ),
}


def detect_dynamic_execution(content):
    detected = []

    for name, pattern in DYNAMIC_EXECUTION_PATTERNS.items():

        if pattern.search(content):
            detected.append(name)

    return detected


URL_PATTERN = re.compile(
    r"(?:https?|wss?|ws)://[^\s\"'<>]+",
    re.IGNORECASE
)


def extract_js_urls(content):
    urls = URL_PATTERN.findall(content)

    return list(dict.fromkeys(urls))


SENSITIVE_DATA_PATTERNS = {
    "password": re.compile(
        r"\bpassword\b",
        re.IGNORECASE
    ),
    "username": re.compile(
        r"\busername\b",
        re.IGNORECASE
    ),
    "email": re.compile(
        r"\bemail\b",
        re.IGNORECASE
    ),
    "credential": re.compile(
        r"\bcredentials?\b",
        re.IGNORECASE
    ),
    "token": re.compile(
        r"\btoken\b",
        re.IGNORECASE
    ),
    "auth": re.compile(
        r"\bauth(?:entication|orization)?\b",
        re.IGNORECASE
    ),
    "secret": re.compile(
        r"\bsecret\b",
        re.IGNORECASE
    ),
    "api_key": re.compile(
        r"\bapi[_-]?key\b",
        re.IGNORECASE
    ),
    "session": re.compile(
        r"\bsession(?:id|_id)?\b",
        re.IGNORECASE
    ),
}


def detect_sensitive_data_indicators(content):
    detected = []

    for name, pattern in SENSITIVE_DATA_PATTERNS.items():

        if pattern.search(content):
            detected.append(name)

    return detected


def detect_cookie_access(content):
    return bool(
        re.search(
            r"\bdocument\.cookie\b",
            content,
            re.IGNORECASE
        )
    )


# ------------------------------------------------------------------
# JavaScript Obfuscation Analysis
# ------------------------------------------------------------------

LONG_STRING_PATTERN = re.compile(
    r"""["'`]([^"'`]{100,})["'`]"""
)

HEX_ESCAPE_PATTERN = re.compile(
    r"\\x[0-9a-fA-F]{2}"
)

UNICODE_ESCAPE_PATTERN = re.compile(
    r"\\u[0-9a-fA-F]{4}"
)

BASE64_STRING_PATTERN = re.compile(
    r"""["'`]([A-Za-z0-9+/]{40,}={0,2})["'`]"""
)


def detect_obfuscation_indicators(content):
    """
    Detect stronger indicators commonly associated with
    JavaScript obfuscation.

    Long strings are observed separately because a long string
    can be completely legitimate.

    Returns:
        dict: Structured obfuscation observations.
    """

    long_strings = LONG_STRING_PATTERN.findall(content)

    hex_escapes = HEX_ESCAPE_PATTERN.findall(content)

    unicode_escapes = UNICODE_ESCAPE_PATTERN.findall(content)

    base64_strings = BASE64_STRING_PATTERN.findall(content)

    encoded_string_count = (
        len(hex_escapes)
        + len(unicode_escapes)
        + len(base64_strings)
    )

    score = 0

    if len(hex_escapes) >= 3:
        score += 1

    if len(unicode_escapes) >= 3:
        score += 1

    if len(base64_strings) >= 1:
        score += 1

    if len(hex_escapes) >= 10:
        score += 1

    if len(unicode_escapes) >= 10:
        score += 1

    if len(base64_strings) >= 3:
        score += 1

    if score >= 2:
        assessment = "HIGH"

    elif score == 1:
        assessment = "MEDIUM"

    else:
        assessment = "NONE"

    return {
        "long_string_count": len(long_strings),
        "hex_escape_count": len(hex_escapes),
        "unicode_escape_count": len(unicode_escapes),
        "base64_like_string_count": len(base64_strings),
        "encoded_string_count": encoded_string_count,
        "score": score,
        "assessment": assessment,
    }


def analyze_javascript(content):
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

    sensitive_data = detect_sensitive_data_indicators(
        content
    )

    cookie_access = detect_cookie_access(content)

    event_handlers = extract_event_handlers(content)

    input_collection_events = detect_input_collection_events(
        content
    )

    form_submission_events = detect_form_submission_events(
        content
    )

    obfuscation = detect_obfuscation_indicators(
        content
    )

    return {
        "functions": functions,
        "variables": variables,
        "console_apis": console_apis,
        "browser_apis": browser_apis,
        "dom_apis": dom_apis,
        "input_value_access": input_value_access,
        "event_handlers": event_handlers,
        "input_collection_events": input_collection_events,
        "form_submission_events": form_submission_events,
        "network_apis": network_apis,
        "storage_apis": storage_apis,
        "dynamic_execution": dynamic_execution,
        "urls": urls,
        "sensitive_data": sensitive_data,
        "cookie_access": cookie_access,
        "obfuscation": obfuscation,
    }