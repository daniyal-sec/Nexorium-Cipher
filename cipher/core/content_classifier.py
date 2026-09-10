from pathlib import Path


def classify_content(file_path, sample_size=8192):
    """
    Classify a file as text or binary using a small byte sample.

    Returns:
        dict: Basic content classification result.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError("The supplied file does not exist.")

    if path.is_dir():
        raise IsADirectoryError("The supplied path is a directory.")

    try:
        with path.open("rb") as file:
            data = file.read(sample_size)

    except PermissionError:
        raise PermissionError("Permission denied while reading the file.")

    if b"\x00" in data:
        return {
            "type": "binary",
            "content_type": "binary",
            "confidence": "HIGH",
            "reason": "Null bytes were detected in the sampled content."
        }

    try:
        data.decode("utf-8")

    except UnicodeDecodeError:
        return {
            "type": "binary",
            "content_type": "binary",
            "confidence": "MEDIUM",
            "reason": "The sampled content could not be decoded as UTF-8."
        }

    return {
        "type": "text",
        "content_type": "text",
        "confidence": "MEDIUM",
        "reason": "The sampled content can be decoded as UTF-8."
    }