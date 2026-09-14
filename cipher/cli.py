import sys

from cipher.core.analyzer import analyze_file
from cipher.core.formatter import format_analysis


def run():

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    file_path = input("Enter file path: ").strip()

    if not file_path:
        print("ERROR: No file path supplied.")
        return

    try:
        result = analyze_file(file_path)

    except FileNotFoundError:
        print("ERROR: File not found.")
        return

    except IsADirectoryError:
        print("ERROR: The supplied path is a directory.")
        return

    except PermissionError:
        print("ERROR: Permission denied.")
        return

    print()
    print(format_analysis(result))