from cipher.core.indicator_analysis import analyze_indicators


findings = analyze_indicators(
    urls=[
        "https://example.com/login"
    ],
    ipv4_addresses=[
        "192.168.1.10"
    ],
    domains=[
        "example.com"
    ]
)


for number, finding in enumerate(findings, start=1):
    print(f"\nFinding {number}")
    print("Category   :", finding["category"])
    print("Finding    :", finding["finding"])
    print("Evidence   :", finding["evidence"])
    print("Severity   :", finding["severity"])
    print("Confidence :", finding["confidence"])
    print("Explanation:", finding["explanation"])