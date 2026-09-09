import sys
import os

from cipher.core.hashing import hash_file


if len(sys.argv) < 2:
    print("ERROR: No file path provided.")
    print("Usage: python test_hashing.py <file_path>")
    sys.exit(1)


file_path = sys.argv[1]

if os.path.isdir(file_path):
    print("ERROR: The supplied path is a directory.")
    print("Please provide a file.")
    sys.exit(1)

try:
    hashes = hash_file(file_path)
except FileNotFoundError:
    print("ERROR: File not found.")
    sys.exit(1)


print("File:", file_path)
print("MD5:", hashes["md5"])
print("SHA-1:", hashes["sha1"])
print("SHA-256:", hashes["sha256"])