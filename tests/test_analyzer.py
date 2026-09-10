from cipher.core.analyzer import analyze_file


result = analyze_file("cipher_test.txt")

print("FILE")
print("Name       :", result["file_name"])
print("Size       :", result["file_size"])
print("Format     :", result["detected_format"])
print("Status     :", result["status"])

content = result["content_analysis"]

print("\nCONTENT")
print("Type       :", content["type"])
print("Confidence :", content["classification_confidence"])
print("Reason     :", content["classification_reason"])

print("\nSTATISTICS")

for key, value in content["statistics"].items():
    print(f"{key}: {value}")

print("\nINDICATORS")

for category, values in content["indicators"].items():
    print(f"{category}: {values}")

print("\nALL FINDINGS")

for number, finding in enumerate(result["findings"], start=1):
    print(f"\nFinding {number}")
    print("Category   :", finding["category"])
    print("Finding    :", finding["finding"])
    print("Evidence   :", finding["evidence"])
    print("Severity   :", finding["severity"])
    print("Confidence :", finding["confidence"])