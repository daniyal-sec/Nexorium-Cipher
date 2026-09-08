import os
from cipher.core.evidence import create_finding
from cipher.core.hashing import hash_file


file_formats = {
    "pdf": {
        "signatures": [b"%PDF"],
        "extensions": ["pdf"]
    },

    "png": {
        "signatures": [b"\x89PNG"],
        "extensions": ["png"]
    },

    "zip": {
        "signatures": [b"PK\x03\x04"],
        "extensions": ["zip"]
    },

    "exe": {
        "signatures": [b"MZ"],
        "extensions": ["exe"]
    },

    "jpeg": {
        "signatures": [b"\xFF\xD8\xFF"],
        "extensions": ["jpg", "jpeg"]
    },

    "gif": {
        "signatures": [b"GIF87a", b"GIF89a"],
        "extensions": ["gif"]
    }
}


def identify_file(file_path):

    if not os.path.exists(file_path):
        raise FileNotFoundError("The supplied file does not exist.")

    if os.path.isdir(file_path):
        raise IsADirectoryError("The supplied path is a directory.")

    file_name = os.path.basename(file_path)

    file_metadata = os.stat(file_path)

    file_size = file_metadata.st_size
    created_time = file_metadata.st_ctime
    modified_time = file_metadata.st_mtime
    accessed_time = file_metadata.st_atime

    hashes = hash_file(file_path)

    extension = os.path.splitext(file_path)[1]
    extension = extension.lower().replace(".", "")

    if not extension:
        extension = "none"

    with open(file_path, "rb") as file:
        data = file.read(16)

    detected_format = "unknown"
    valid_extensions = []
    match_found = False

    for format_name, details in file_formats.items():

        valid_signatures = details["signatures"]

        for signature in valid_signatures:

            if data.startswith(signature):
                detected_format = format_name
                valid_extensions = details["extensions"]
                match_found = True
                break

        if match_found:
            break

    if detected_format == "unknown":
        status = "UNKNOWN"

    else:
        if extension in valid_extensions:
            status = "MATCH"
        else:
            status = "MISMATCH"

    findings = create_finding(
    extension,
    detected_format,
    valid_extensions
)

    return {
        "file_name": file_name,
        "extension": extension,
        "file_size": file_size,
        "detected_format": detected_format,
        "valid_extensions": valid_extensions,
        "status": status,
        "findings": findings,
        "created_time": created_time,
        "modified_time": modified_time,
        "accessed_time": accessed_time,
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "sha256": hashes["sha256"]
    }