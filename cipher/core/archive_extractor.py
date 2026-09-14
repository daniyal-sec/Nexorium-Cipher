"""
Cipher Phase 5 — Archive Extractor

Provides controlled extraction of supported archive files.

Current support:
    - ZIP

Security controls:
    - Rejects path traversal
    - Rejects absolute paths
    - Prevents extraction outside the destination directory
    - Enforces a maximum total extracted size
    - Enforces a maximum number of extracted entries

This module extracts files only. It does not execute them.
"""

from pathlib import Path
import tempfile
import zipfile


# Maximum number of archive entries that Cipher will extract.
DEFAULT_MAX_ENTRIES = 1000

# Maximum total uncompressed data Cipher will extract.
# 100 MB provides a reasonable starting point for the lab/tool.
DEFAULT_MAX_EXTRACTED_SIZE = 100 * 1024 * 1024


def _normalize_path(path):
    """
    Normalize archive paths for security checks.
    """

    return path.replace("\\", "/")


def _is_absolute_path(filename):
    """
    Detect Unix-style and Windows-style absolute paths.
    """

    normalized = _normalize_path(filename)

    if normalized.startswith("/"):
        return True

    # Windows drive path such as C:/Windows/file.exe
    if len(normalized) >= 3:
        if normalized[0].isalpha() and normalized[1:3] == ":/":
            return True

    return False


def _has_path_traversal(filename):
    """
    Detect parent-directory traversal components.
    """

    normalized = _normalize_path(filename)

    parts = normalized.split("/")

    return ".." in parts


def _validate_entry_path(filename):
    """
    Validate an archive entry path before extraction.

    Raises
    ------
    ValueError
        If the path is unsafe.
    """

    if _is_absolute_path(filename):
        raise ValueError(
            f"Unsafe archive entry: absolute path: {filename}"
        )

    if _has_path_traversal(filename):
        raise ValueError(
            f"Unsafe archive entry: path traversal: {filename}"
        )


def _safe_destination_path(destination, filename):
    """
    Build and validate the final extraction path.

    This provides a second containment check even after the
    archive path has passed the explicit traversal checks.
    """

    destination = Path(destination).resolve()

    normalized = _normalize_path(filename)

    target = (destination / normalized).resolve()

    try:
        target.relative_to(destination)
    except ValueError:
        raise ValueError(
            f"Archive entry escapes extraction directory: {filename}"
        )

    return target


def _check_limits(
    archive,
    max_entries,
    max_extracted_size,
):
    """
    Check archive limits before extraction.
    """

    entries = archive.infolist()

    if len(entries) > max_entries:
        raise ValueError(
            f"Archive contains {len(entries)} entries, "
            f"exceeding the maximum allowed {max_entries}."
        )

    total_size = sum(
        info.file_size
        for info in entries
        if not info.is_dir()
    )

    if total_size > max_extracted_size:
        raise ValueError(
            f"Archive contains {total_size} bytes of uncompressed data, "
            f"exceeding the maximum allowed {max_extracted_size} bytes."
        )


def extract_zip(
    file_path,
    destination=None,
    max_entries=DEFAULT_MAX_ENTRIES,
    max_extracted_size=DEFAULT_MAX_EXTRACTED_SIZE,
):
    """
    Safely extract a ZIP archive.

    Parameters
    ----------
    file_path : str or Path
        Path to the ZIP archive.

    destination : str or Path, optional
        Extraction directory.

        If omitted, a temporary directory is created.

    max_entries : int
        Maximum number of archive entries.

    max_extracted_size : int
        Maximum total uncompressed size in bytes.

    Returns
    -------
    dict
        Structured extraction result containing:

        - extraction_directory
        - extracted_files
        - extracted_directories
        - file_count
        - directory_count
        - total_extracted_size

    Raises
    ------
    FileNotFoundError
        If the archive does not exist.

    ValueError
        If the archive is unsupported or contains unsafe content.

    zipfile.BadZipFile
        If the ZIP archive is invalid.
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

    if file_path.suffix.lower() != ".zip":
        raise ValueError(
            "Only ZIP archives are currently supported."
        )

    if not zipfile.is_zipfile(file_path):
        raise zipfile.BadZipFile(
            f"Invalid ZIP archive: {file_path}"
        )

    temporary_directory = None

    if destination is None:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix="nexorium_cipher_"
        )

        destination = Path(
            temporary_directory.name
        )

    else:
        destination = Path(destination)
        destination.mkdir(
            parents=True,
            exist_ok=True,
        )

    destination = destination.resolve()

    extracted_files = []
    extracted_directories = []

    total_extracted_size = 0

    with zipfile.ZipFile(file_path, "r") as archive:

        _check_limits(
            archive,
            max_entries,
            max_extracted_size,
        )

        for info in archive.infolist():

            filename = _normalize_path(info.filename)

            _validate_entry_path(filename)

            target = _safe_destination_path(
                destination,
                filename,
            )

            if info.is_dir() or filename.endswith("/"):
                target.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                extracted_directories.append(
                    str(
                        target.relative_to(destination)
                    )
                )

                continue

            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with archive.open(info, "r") as source:
                with target.open("wb") as output:

                    while True:
                        chunk = source.read(1024 * 1024)

                        if not chunk:
                            break

                        total_extracted_size += len(chunk)

                        if (
                            total_extracted_size
                            > max_extracted_size
                        ):
                            raise ValueError(
                                "Archive extraction exceeded "
                                "the maximum allowed size."
                            )

                        output.write(chunk)

            extracted_files.append(
                str(
                    target.relative_to(destination)
                )
            )

    result = {
        "extraction_directory": str(destination),
        "extracted_files": extracted_files,
        "extracted_directories": extracted_directories,
        "file_count": len(extracted_files),
        "directory_count": len(extracted_directories),
        "total_extracted_size": total_extracted_size,
    }

    # Keep the temporary directory alive for the caller when one
    # was created automatically. The caller is responsible for
    # cleanup by calling the cleanup callback.
    if temporary_directory is not None:
        result["_temporary_directory"] = temporary_directory

    return result