def analyze_text_content(content):
    """
    Calculate basic statistics for text content.

    Returns:
        dict: Basic content statistics.
    """

    return {
        "characters": len(content),
        "lines": len(content.splitlines()),
        "words": len(content.split()),
        "empty": not content.strip()
    }