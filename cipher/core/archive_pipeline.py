"""
Cipher Phase 5 — Archive Analysis Pipeline

Coordinates safe extraction and analysis of files contained
inside supported archives.

This module does not execute extracted files.

The caller provides the file-analysis function so that this
module does not create a circular dependency with analyzer.py.
"""

from pathlib import Path

from cipher.core.archive_extractor import extract_zip


# Maximum recursive archive depth.

# Depth 0:
#     Analyze the original archive.
#
# Depth 1:
#     Analyze archives directly contained inside it.
#
# Depth 2:
#     Analyze archives contained inside those archives.
#
# This prevents uncontrolled recursive archive processing.
DEFAULT_MAX_DEPTH = 3


# Maximum number of files analyzed across one archive branch.
DEFAULT_MAX_FILES = 1000


def _is_archive_file(file_path):
    """
    Determine whether a file appears to be a supported archive.
    """

    return Path(file_path).suffix.lower() == ".zip"


def _build_relative_path(base_path, relative_path):
    """
    Build a normalized relative path for reporting.
    """

    if not relative_path:
        return str(base_path)

    return f"{base_path}/{relative_path}".replace(
        "\\",
        "/",
    )


def _analyze_extracted_files(
    extraction_result,
    analyze_file,
    archive_path,
    current_depth,
    max_depth,
    max_files,
    state,
):
    """
    Analyze files extracted from an archive.

    Nested archives are handled recursively through this same
    pipeline, subject to the configured maximum depth.
    """

    results = []

    extraction_directory = Path(
        extraction_result["extraction_directory"]
    )

    for relative_file in extraction_result["extracted_files"]:

        if state["files_analyzed"] >= max_files:
            break

        extracted_path = (
            extraction_directory / relative_file
        )

        relative_display_path = _build_relative_path(
            archive_path,
            relative_file,
        )

        state["files_analyzed"] += 1

        if _is_archive_file(extracted_path):

            if current_depth >= max_depth:

                results.append(
                    {
                        "path": relative_display_path,
                        "type": "archive",
                        "analysis_skipped": True,
                        "reason": (
                            "Maximum archive recursion depth reached."
                        ),
                    }
                )

                continue

            try:
                nested_result = analyze_archive_contents(
                    extracted_path,
                    analyze_file,
                    current_depth=current_depth + 1,
                    max_depth=max_depth,
                    max_files=max_files,
                    state=state,
                    display_path=relative_display_path,
                )

                results.append(
                    {
                        "path": relative_display_path,
                        "type": "archive",
                        "analysis": nested_result,
                    }
                )

            except Exception as exc:

                results.append(
                    {
                        "path": relative_display_path,
                        "type": "archive",
                        "analysis_error": str(exc),
                    }
                )

            continue

        try:

            file_result = analyze_file(
                extracted_path
            )

            results.append(
                {
                    "path": relative_display_path,
                    "type": "file",
                    "analysis": file_result,
                }
            )

        except Exception as exc:

            results.append(
                {
                    "path": relative_display_path,
                    "type": "file",
                    "analysis_error": str(exc),
                }
            )

    return results


def analyze_archive_contents(
    file_path,
    analyze_file,
    current_depth=0,
    max_depth=DEFAULT_MAX_DEPTH,
    max_files=DEFAULT_MAX_FILES,
    state=None,
    display_path=None,
):
    """
    Safely extract and analyze the contents of a ZIP archive.

    Parameters
    ----------
    file_path : str or Path
        Archive to analyze.

    analyze_file : callable
        Existing Cipher file-analysis function.

        The function must accept one file path and return
        Cipher's structured analysis result.

    current_depth : int
        Current archive recursion depth.

    max_depth : int
        Maximum allowed archive recursion depth.

    max_files : int
        Maximum number of files analyzed across the current
        archive branch.

    state : dict, optional
        Shared recursion state.

    display_path : str, optional
        Human-readable path used when reporting nested archives.

    Returns
    -------
    dict
        Structured archive-content analysis result.

    Security behavior
    -----------------
    Unsafe archive entries rejected by the extraction layer
    are captured and returned as a structured extraction error.

    The archive itself is still analyzed by archive_analyzer.py,
    which reports security findings such as path traversal
    and absolute paths.
    """

    file_path = Path(file_path)

    if state is None:
        state = {
            "files_analyzed": 0,
        }

    if current_depth > max_depth:
        return {
            "archive_path": (
                display_path
                or str(file_path)
            ),
            "analysis_skipped": True,
            "reason": "Maximum archive recursion depth reached.",
            "files_analyzed": state["files_analyzed"],
            "results": [],
        }

    # ---------------------------------------------------------------
    # Safe extraction
    # ---------------------------------------------------------------
    #
    # The extractor performs the actual security validation.
    #
    # If an unsafe entry such as:
    #
    #     ../outside.txt
    #
    # is detected, extract_zip() raises ValueError.
    #
    # Do not allow that exception to crash the entire Cipher CLI.
    # Instead, preserve it as structured archive-content state.
    #
    try:

        extraction_result = extract_zip(
            file_path
        )

    except ValueError as exc:

        return {
            "archive_path": (
                display_path
                or str(file_path)
            ),
            "depth": current_depth,
            "files_analyzed": 0,
            "total_files_analyzed": state["files_analyzed"],
            "analysis_limit": max_files,
            "max_depth": max_depth,
            "results": [],
            "extraction_blocked": True,
            "extraction_error": str(exc),
        }

    except Exception as exc:

        return {
            "archive_path": (
                display_path
                or str(file_path)
            ),
            "depth": current_depth,
            "files_analyzed": 0,
            "total_files_analyzed": state["files_analyzed"],
            "analysis_limit": max_files,
            "max_depth": max_depth,
            "results": [],
            "extraction_blocked": True,
            "extraction_error": (
                f"Archive extraction failed: {exc}"
            ),
        }

    # ---------------------------------------------------------------
    # Analyze extracted files
    # ---------------------------------------------------------------

    results = _analyze_extracted_files(
        extraction_result=extraction_result,
        analyze_file=analyze_file,
        archive_path=(
            display_path
            or file_path.name
        ),
        current_depth=current_depth,
        max_depth=max_depth,
        max_files=max_files,
        state=state,
    )

    return {
        "archive_path": (
            display_path
            or str(file_path)
        ),
        "depth": current_depth,
        "files_analyzed": len(results),
        "total_files_analyzed": state["files_analyzed"],
        "analysis_limit": max_files,
        "max_depth": max_depth,
        "results": results,
    }


def collect_archive_findings(
    archive_result,
    minimum_severity="MEDIUM",
):
    """
    Collect meaningful findings from all files and nested archives
    contained within an archive analysis result.

    Findings below the configured severity threshold remain available
    inside the detailed archive analysis but are not promoted into
    the parent file's main risk pipeline.

    Each promoted finding receives an additional 'archive_path' field
    identifying where the finding originated.

    Parameters
    ----------
    archive_result : dict
        Result returned by analyze_archive_contents().

    minimum_severity : str
        Minimum severity to promote.

        Supported levels:
            LOW
            MEDIUM
            HIGH
            CRITICAL

    Returns
    -------
    list[dict]
        Flattened list of promoted findings.
    """

    severity_rank = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    threshold = severity_rank.get(
        str(minimum_severity).strip().upper(),
        severity_rank["MEDIUM"],
    )

    findings = []

    def walk_results(results):

        for result in results:

            path = result.get(
                "path",
                "unknown",
            )

            analysis = result.get(
                "analysis"
            )

            if not analysis:
                continue

            # Nested archive
            if result.get("type") == "archive":

                nested_results = analysis.get(
                    "results",
                    [],
                )

                walk_results(
                    nested_results
                )

                continue

            # Normal contained file
            file_findings = analysis.get(
                "findings",
                [],
            )

            for finding in file_findings:

                severity = str(
                    finding.get(
                        "severity",
                        "",
                    )
                ).strip().upper()

                if severity_rank.get(
                    severity,
                    0,
                ) < threshold:
                    continue

                finding_copy = dict(
                    finding
                )

                finding_copy["archive_path"] = path

                findings.append(
                    finding_copy
                )

    walk_results(
        archive_result.get(
            "results",
            [],
        )
    )

    return findings