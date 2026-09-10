from pathlib import Path


def read_text_file(file_path, encoding="utf-8"):
    """
    Read a file as text without executing it.

    Returns:
        str: File content.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError("The supplied file does not exist.")

    if path.is_dir():
        raise IsADirectoryError("The supplied path is a directory.")

    try:
        return path.read_text(
            encoding=encoding,
            errors="replace"
        )

    except PermissionError:
        raise PermissionError("Permission denied while reading the file.")