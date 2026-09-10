from cipher.core.content_classifier import classify_content


result = classify_content("cipher_test.txt")

print("Content Type :", result["type"])
print("Confidence   :", result["confidence"])
print("Reason       :", result["reason"])