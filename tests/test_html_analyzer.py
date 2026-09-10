from cipher.core.html_analyzer import (
    detect_html_forms,
    extract_html_forms,
    detect_password_inputs,
    extract_password_inputs,
    extract_form_actions,
    extract_form_methods,
    analyze_html
)


html_with_form = """
<html>
    <body>
        <form action="https://example.com/login" method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
        </form>
    </body>
</html>
"""


html_without_form = """
<html>
    <body>
        <h1>Hello World</h1>
    </body>
</html>
"""


# ---------------------------------------------------------------------------
# TEST CASE 1
# ---------------------------------------------------------------------------

print("=" * 60)
print("TEST CASE 1: HTML WITH LOGIN FORM")
print("-" * 60)

print(
    "Form detected           :",
    detect_html_forms(html_with_form)
)

print(
    "Password input detected :",
    detect_password_inputs(html_with_form)
)

print("Extracted forms         :")

forms = extract_html_forms(html_with_form)

if forms:
    for form in forms:
        print(f"  {form}")
else:
    print("  None")

print("Password inputs         :")

password_inputs = extract_password_inputs(html_with_form)

if password_inputs:
    for password_input in password_inputs:
        print(f"  {password_input}")
else:
    print("  None")

print("Form actions            :")

actions = extract_form_actions(html_with_form)

if actions:
    for action in actions:
        print(f"  {action}")
else:
    print("  None")

print("Form methods            :")

methods = extract_form_methods(html_with_form)

if methods:
    for method in methods:
        print(f"  {method}")
else:
    print("  None")


# ---------------------------------------------------------------------------
# TEST CASE 2
# ---------------------------------------------------------------------------

print()
print("=" * 60)
print("TEST CASE 2: HTML WITHOUT FORM")
print("-" * 60)

print(
    "Form detected           :",
    detect_html_forms(html_without_form)
)

print(
    "Password input detected :",
    detect_password_inputs(html_without_form)
)

print("Extracted forms         :")

forms = extract_html_forms(html_without_form)

if forms:
    for form in forms:
        print(f"  {form}")
else:
    print("  None")

print("Password inputs         :")

password_inputs = extract_password_inputs(html_without_form)

if password_inputs:
    for password_input in password_inputs:
        print(f"  {password_input}")
else:
    print("  None")

print("Form actions            :")

actions = extract_form_actions(html_without_form)

if actions:
    for action in actions:
        print(f"  {action}")
else:
    print("  None")

print("Form methods            :")

methods = extract_form_methods(html_without_form)

if methods:
    for method in methods:
        print(f"  {method}")
else:
    print("  None")

print("=" * 60)


print()
print("=" * 60)
print("TEST CASE 3: COMPLETE HTML ANALYSIS")
print("-" * 60)

result = analyze_html(html_with_form)

print("Forms detected          :", result["forms_detected"])
print("Password inputs         :", result["password_inputs_detected"])
print("Form actions            :", result["form_actions"])
print("Form methods            :", result["form_methods"])

print()
print("Complete result:")
print(result)

print("=" * 60)

