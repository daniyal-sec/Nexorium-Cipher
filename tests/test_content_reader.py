import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cipher.core.content_reader import read_text_file


content = read_text_file("cipher_test.txt")

print("Content:")
print(content)