from cipher.core.content_analyzer import analyze_content


result = analyze_content("cipher_test.txt")

print("Content Type :", result["type"])
print("Confidence   :", result["classification_confidence"])
print("Reason       :", result["classification_reason"])

print("\nStatistics:")
for key, value in result["statistics"].items():
    print(f"  {key}: {value}")

print("\nIndicators:")
for category, values in result["indicators"].items():
    print(f"  {category}: {values}")

print("\nFindings:")
for number, finding in enumerate(result["findings"], start=1):
    print(f"\n  Finding {number}")
    print("    Category   :", finding["category"])
    print("    Finding    :", finding["finding"])
    print("    Evidence   :", finding["evidence"])
    print("    Severity   :", finding["severity"])
    print("    Confidence :", finding["confidence"])