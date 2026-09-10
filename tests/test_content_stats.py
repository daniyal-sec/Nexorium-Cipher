from cipher.core.content_reader import read_text_file
from cipher.core.content_stats import analyze_text_content


content = read_text_file("cipher_test.txt")

result = analyze_text_content(content)

print("Characters :", result["characters"])
print("Lines      :", result["lines"])
print("Words      :", result["words"])
print("Empty      :", result["empty"])