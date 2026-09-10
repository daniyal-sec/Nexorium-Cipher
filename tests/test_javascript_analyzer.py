from cipher.core.javascript_analyzer import (
    analyze_javascript,
    detect_browser_apis,
    detect_dom_apis,
    detect_dynamic_execution,
    detect_input_value_access,
    detect_network_apis,
    detect_obfuscation_indicators,
    detect_storage_apis,
    extract_console_apis,
    extract_js_functions,
    extract_js_variables,
)


javascript_sample = """
const message = "Hello from JavaScript";

function greet(name) {
    console.log(message);

    const input = document.querySelector("#password");
    const value = input.value;

    localStorage.setItem("name", name);

    fetch("https://example.com/api");

    return value;
}

greet("Daniyal");
"""


clean_javascript = """
const message = "Hello World";

function greet() {
    console.log(message);
}

greet();
"""


# ---------------------------------------------------------------------------
# TEST CASE 1
# ---------------------------------------------------------------------------

print("=" * 60)
print("TEST CASE 1: JAVASCRIPT FEATURE ANALYSIS")
print("-" * 60)

result = analyze_javascript(javascript_sample)

print("Functions:")
print("  Named       :", result["functions"]["named"])
print("  Anonymous   :", result["functions"]["anonymous_count"])
print("  Arrow       :", result["functions"]["arrow_count"])
print("  Total       :", result["functions"]["total"])

print()
print("Variables:")

if result["variables"]:
    for variable in result["variables"]:
        print(
            f"  {variable['declaration']} "
            f"{variable['name']}"
        )
else:
    print("  None")

print()
print("Console APIs :", result["console_apis"])
print("Browser APIs :", result["browser_apis"])
print("DOM APIs     :", result["dom_apis"])
print(
    "Input access :",
    result["input_value_access"]
)
print("Network APIs :", result["network_apis"])
print("Storage APIs :", result["storage_apis"])
print(
    "Dynamic exec :",
    result["dynamic_execution"]
)
print("URLs         :", result["urls"])

print()
print("Obfuscation:")
print(
    "  Long strings :",
    result["obfuscation"]["long_string_count"]
)
print(
    "  Hex escapes  :",
    result["obfuscation"]["hex_escape_count"]
)
print(
    "  Unicode      :",
    result["obfuscation"]["unicode_escape_count"]
)


# ---------------------------------------------------------------------------
# TEST CASE 2
# ---------------------------------------------------------------------------

print()
print("=" * 60)
print("TEST CASE 2: CLEAN JAVASCRIPT")
print("-" * 60)

result = analyze_javascript(clean_javascript)

print(
    "Functions     :",
    result["functions"]["named"]
)

print(
    "Console APIs  :",
    result["console_apis"]
)

print(
    "Browser APIs  :",
    result["browser_apis"]
)

print(
    "Network APIs  :",
    result["network_apis"]
)

print(
    "Storage APIs  :",
    result["storage_apis"]
)

print(
    "Dynamic exec  :",
    result["dynamic_execution"]
)

print(
    "URLs          :",
    result["urls"]
)

print("=" * 60)