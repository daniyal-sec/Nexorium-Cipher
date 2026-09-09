from cipher.core.file_identifier import identify_file
from cipher.core.formatter import format_analysis


file_path = "test.jpg"

try:
    result = identify_file(file_path)

except FileNotFoundError:
    print("ERROR: File not found.")
    exit()

except IsADirectoryError:
    print("ERROR: The supplied path is a directory.")
    exit()

except PermissionError:
    print("ERROR: Permission denied.")
    exit()


print(format_analysis(result))