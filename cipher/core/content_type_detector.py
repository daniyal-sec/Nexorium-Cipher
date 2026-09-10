import re
from pathlib import Path


def detect_content_type(content, file_path=None):
    """
    Detect the likely content type of text content.

    Detection uses file extension when useful and content structure
    when available.

    Returns:
        dict: Detected content type, confidence, and reason.
    """

    extension = ""

    if file_path:
        extension = Path(file_path).suffix.lower()

    stripped = content.lstrip()

    # ---------------------------------------------------------
    # HTML detection
    # ---------------------------------------------------------

    html_patterns = (
        r"<!doctype\s+html",
        r"<html\b",
        r"<head\b",
        r"<body\b",
        r"<form\b",
        r"<script\b",
    )

    for pattern in html_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return {
                "type": "html",
                "confidence": "HIGH",
                "reason": "HTML structure was detected in the content."
            }

    if extension in (".html", ".htm"):
        return {
            "type": "html",
            "confidence": "MEDIUM",
            "reason": "The file uses an HTML extension."
        }

    # ---------------------------------------------------------
    # JavaScript detection
    # ---------------------------------------------------------

    javascript_patterns = (
        r"\bconsole\.",
        r"\bfunction\s+\w+\s*\(",
        r"\bconst\s+\w+\s*=",
        r"\blet\s+\w+\s*=",
        r"\bvar\s+\w+\s*=",
        r"\bdocument\.",
        r"\bwindow\.",
        r"\bfetch\s*\(",
        r"\bXMLHttpRequest\b",
    )

    javascript_matches = 0

    for pattern in javascript_patterns:
        if re.search(pattern, content):
            javascript_matches += 1

    if javascript_matches >= 2:
        return {
            "type": "javascript",
            "confidence": "HIGH",
            "reason": (
                "Multiple JavaScript language or browser API "
                "patterns were detected in the content."
            )
        }

    if extension == ".js":
        return {
            "type": "javascript",
            "confidence": "HIGH",
            "reason": "The file uses a JavaScript extension."
        }

    # ---------------------------------------------------------
    # Python detection
    # ---------------------------------------------------------

    python_patterns = (
        r"^\s*import\s+\w+",
        r"^\s*from\s+\w+",
        r"^\s*def\s+\w+\s*\(",
        r"^\s*class\s+\w+",
        r"^\s*if\s+__name__\s*==",
        r"\bprint\s*\(",
    )

    python_matches = 0

    for pattern in python_patterns:
        if re.search(pattern, content, re.MULTILINE):
            python_matches += 1

    if python_matches >= 2:
        return {
            "type": "python",
            "confidence": "HIGH",
            "reason": (
                "Multiple Python language patterns were detected "
                "in the content."
            )
        }

    if extension == ".py":
        return {
            "type": "python",
            "confidence": "HIGH",
            "reason": "The file uses a Python extension."
        }

    # ---------------------------------------------------------
    # Plain text
    # ---------------------------------------------------------

    if extension in (".txt", ".text"):
        return {
            "type": "plain_text",
            "confidence": "HIGH",
            "reason": "The file uses a plain-text extension."
        }

    return {
        "type": "plain_text",
        "confidence": "MEDIUM",
        "reason": (
            "The content is text but no supported programming "
            "language or markup structure was identified."
        )
    }