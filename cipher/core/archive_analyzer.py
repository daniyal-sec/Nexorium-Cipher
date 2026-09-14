"""
Cipher Phase 5 — Archive Analyzer

Provides static inspection of archive containers.

Current support:
    - ZIP

The analyzer does not execute files or extract archive contents.
It inspects archive metadata, entry names, and archive-level
security characteristics.
"""

from pathlib import Path
import zipfile

from cipher.core.evidence import build_finding


# Archive formats currently recognized by Cipher.
ARCHIVE_EXTENSIONS = {
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".rar",
    ".7z",
}


# Extensions that may deserve additional attention when found
# inside an archive.
SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".apk",
    ".elf",
    ".sh",
}


# Extensions representing executable content.
EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".elf",
}


# Extensions representing script content.
SCRIPT_EXTENSIONS = {
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".wsf",
    ".wsh",
    ".hta",
    ".bat",
    ".cmd",
    ".ps1",
    ".sh",
}


def _normalize_path(path):
    """
    Normalize an archive entry path for consistent inspection.
    """

    return path.replace("\\", "/")


def _is_directory(info):
    """
    Determine whether a ZIP entry represents a directory.
    """

    return info.is_dir() or info.filename.endswith("/")


def _is_nested_archive(filename):
    """
    Determine whether an archive entry appears to be another archive.
    """

    suffix = Path(filename).suffix.lower()

    return suffix in ARCHIVE_EXTENSIONS


def _has_path_traversal(filename):
    """
    Detect parent-directory traversal patterns such as ../.
    """

    normalized = _normalize_path(filename)

    parts = normalized.split("/")

    return ".." in parts


def _is_absolute_path(filename):
    """
    Detect Unix-style and Windows-style absolute archive paths.
    """

    normalized = _normalize_path(filename)

    if normalized.startswith("/"):
        return True

    # Windows drive path such as C:/Windows/system32/file.exe
    if len(normalized) >= 3:
        if normalized[0].isalpha() and normalized[1:3] == ":/":
            return True

    return False


def _get_extension(filename):
    """
    Return the lowercase file extension.
    """

    return Path(filename).suffix.lower()


def _inspect_zip(file_path):
    """
    Inspect a ZIP archive without extracting its contents.
    """

    entries = []

    file_count = 0
    directory_count = 0
    nested_archive_count = 0

    traversal_count = 0
    absolute_path_count = 0
    suspicious_extension_count = 0

    with zipfile.ZipFile(file_path, "r") as archive:
        for info in archive.infolist():

            filename = _normalize_path(info.filename)

            is_directory = _is_directory(info)

            nested_archive = (
                not is_directory
                and _is_nested_archive(filename)
            )

            path_traversal = _has_path_traversal(filename)

            absolute_path = _is_absolute_path(filename)

            extension = _get_extension(filename)

            suspicious_extension = (
                not is_directory
                and extension in SUSPICIOUS_EXTENSIONS
            )

            if is_directory:
                directory_count += 1
            else:
                file_count += 1

            if nested_archive:
                nested_archive_count += 1

            if path_traversal:
                traversal_count += 1

            if absolute_path:
                absolute_path_count += 1

            if suspicious_extension:
                suspicious_extension_count += 1

            entries.append(
                {
                    "name": filename,
                    "type": "directory" if is_directory else "file",
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "compression_ratio": (
                        round(
                            info.compress_size / info.file_size,
                            4,
                        )
                        if info.file_size > 0
                        else None
                    ),
                    "nested_archive": nested_archive,
                    "path_traversal": path_traversal,
                    "absolute_path": absolute_path,
                    "extension": extension,
                    "suspicious_extension": suspicious_extension,
                }
            )

    return {
        "archive_type": "ZIP",
        "file_count": file_count,
        "directory_count": directory_count,
        "nested_archive_count": nested_archive_count,
        "path_traversal_count": traversal_count,
        "absolute_path_count": absolute_path_count,
        "suspicious_extension_count": suspicious_extension_count,
        "entries": entries,
    }


def _build_archive_findings(archive_result):
    """
    Convert archive observations into structured Cipher findings.

    Findings describe observed archive characteristics.
    They do not independently classify the archive as malicious.
    """

    findings = []

    entries = archive_result.get("entries", [])

    executable_entries = [
        entry
        for entry in entries
        if entry.get("extension") in EXECUTABLE_EXTENSIONS
    ]

    script_entries = [
        entry
        for entry in entries
        if entry.get("extension") in SCRIPT_EXTENSIONS
    ]

    nested_entries = [
        entry
        for entry in entries
        if entry.get("nested_archive")
    ]

    traversal_entries = [
        entry
        for entry in entries
        if entry.get("path_traversal")
    ]

    absolute_entries = [
        entry
        for entry in entries
        if entry.get("absolute_path")
    ]

    # Executable content
    if executable_entries:
        names = [
            entry["name"]
            for entry in executable_entries
        ]

        findings.append(
            build_finding(
                "Archive Analysis",
                "Executable files found inside archive",
                ", ".join(names),
                (
                    "The archive contains executable file types. "
                    "Executable content may be legitimate software, "
                    "installers, or potentially unwanted or malicious "
                    "payloads and should be analyzed further."
                ),
                "MEDIUM",
                "HIGH",
                tags=[
                    "archive.executable",
                ],
            )
        )

    # Script content
    if script_entries:
        names = [
            entry["name"]
            for entry in script_entries
        ]

        findings.append(
            build_finding(
                "Archive Analysis",
                "Script files found inside archive",
                ", ".join(names),
                (
                    "The archive contains script files that may execute "
                    "commands or application logic when opened or run. "
                    "Their presence alone does not indicate malicious activity."
                ),
                "LOW",
                "HIGH",
                tags=[
                    "archive.script",
                ],
            )
        )

    # Nested archives
    if nested_entries:
        names = [
            entry["name"]
            for entry in nested_entries
        ]

        findings.append(
            build_finding(
                "Archive Analysis",
                "Nested archives detected",
                ", ".join(names),
                (
                    "The archive contains one or more additional archive "
                    "containers. Nested archives can conceal additional "
                    "content and may require recursive analysis."
                ),
                "LOW",
                "HIGH",
                tags=[
                    "archive.nested",
                ],
            )
        )

    # Path traversal
    if traversal_entries:
        names = [
            entry["name"]
            for entry in traversal_entries
        ]

        findings.append(
            build_finding(
                "Archive Security",
                "Archive path traversal detected",
                ", ".join(names),
                (
                    "One or more archive entries contain parent-directory "
                    "traversal components such as '..'. If extracted "
                    "unsafely, these paths may attempt to write files "
                    "outside the intended extraction directory."
                ),
                "HIGH",
                "HIGH",
                tags=[
                    "archive.path_traversal",
                ],
            )
        )

    # Absolute paths
    if absolute_entries:
        names = [
            entry["name"]
            for entry in absolute_entries
        ]

        findings.append(
            build_finding(
                "Archive Security",
                "Absolute archive paths detected",
                ", ".join(names),
                (
                    "One or more archive entries use absolute paths. "
                    "Unsafe extraction could attempt to write files to "
                    "locations outside the intended extraction directory."
                ),
                "HIGH",
                "HIGH",
                tags=[
                    "archive.absolute_path",
                ],
            )
        )

    return findings


def analyze_archive(file_path):
    """
    Analyze an archive file.

    Parameters
    ----------
    file_path : str or Path
        Path to the archive.

    Returns
    -------
    dict
        Structured archive analysis result containing:

        - archive_type
        - archive metadata
        - entries
        - findings

    Raises
    ------
    FileNotFoundError
        If the archive does not exist.

    ValueError
        If the archive format is currently unsupported.

    zipfile.BadZipFile
        If the file is identified as ZIP but is invalid/corrupt.
    """

    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Archive does not exist: {file_path}"
        )

    if not file_path.is_file():
        raise ValueError(
            f"Archive path is not a file: {file_path}"
        )

    suffix = file_path.suffix.lower()

    if suffix != ".zip":
        raise ValueError(
            f"Unsupported archive format: {suffix or 'unknown'}"
        )

    if not zipfile.is_zipfile(file_path):
        raise zipfile.BadZipFile(
            f"Invalid ZIP archive: {file_path}"
        )

    archive_result = _inspect_zip(file_path)

    archive_result["findings"] = _build_archive_findings(
        archive_result
    )

    return archive_result