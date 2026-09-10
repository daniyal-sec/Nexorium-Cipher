import re


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
            methods.append(match.group(1).upper())

    return methods


def analyze_html(content):
    """
    Analyze HTML content for forms and password-related inputs.

    Returns:
        dict: Structured HTML analysis result.
    """

    forms = extract_html_forms(content)
    password_inputs = extract_password_inputs(content)
    actions = extract_form_actions(content)
    methods = extract_form_methods(content)

    return {
        "forms_detected": bool(forms),
        "forms": forms,
        "password_inputs_detected": bool(password_inputs),
        "password_inputs": password_inputs,
        "form_actions": actions,
        "form_methods": methods,
    }