from cipher.core.evidence import build_finding


def analyze_html_findings(html_analysis):
    """
    Convert HTML analyzer observations into structured findings.

    This layer interprets HTML observations and assigns
    severity/confidence. It does not make an overall malware verdict.
    """

    if not html_analysis:
        return []

    findings = []

    # --------------------------------------------------------------
    # Password inputs
    # --------------------------------------------------------------

    password_inputs = html_analysis.get(
        "password_inputs",
        []
    )

    if password_inputs:
        findings.append(
            build_finding(
                "HTML Input Analysis",
                "Password input detected",
                "\n".join(password_inputs),
                (
                    "The HTML contains one or more password input "
                    "fields. Password fields are common in legitimate "
                    "login pages but are relevant when investigating "
                    "credential collection."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Hidden inputs
    # --------------------------------------------------------------

    hidden_inputs = html_analysis.get(
        "hidden_inputs",
        []
    )

    if hidden_inputs:
        findings.append(
            build_finding(
                "HTML Input Analysis",
                "Hidden input detected",
                "\n".join(hidden_inputs),
                (
                    "The HTML contains hidden input fields. Hidden "
                    "inputs are commonly used for tokens, state values, "
                    "identifiers, and other application data. Their "
                    "presence alone does not indicate malicious behavior."
                ),
                "LOW",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Script tags
    # --------------------------------------------------------------

    script_tags = html_analysis.get(
        "script_tags",
        []
    )

    if script_tags:
        findings.append(
            build_finding(
                "HTML Script Analysis",
                "Script tag detected",
                "\n".join(script_tags),
                (
                    "The HTML contains one or more script elements. "
                    "JavaScript is common in modern web applications, "
                    "but scripts are relevant when investigating "
                    "client-side behavior."
                ),
                "LOW",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # External JavaScript
    # --------------------------------------------------------------

    external_javascript_sources = html_analysis.get(
        "external_javascript_sources",
        []
    )

    if external_javascript_sources:
        findings.append(
            build_finding(
                "HTML Script Analysis",
                "External JavaScript source detected",
                "\n".join(external_javascript_sources),
                (
                    "The HTML loads JavaScript from an external "
                    "source or path. External scripts are common in "
                    "legitimate websites, but their destinations are "
                    "relevant when investigating third-party or "
                    "potentially untrusted code."
                ),
                "LOW",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Form action
    # --------------------------------------------------------------

    form_actions = html_analysis.get(
        "form_actions",
        []
    )

    if form_actions:
        findings.append(
            build_finding(
                "HTML Form Analysis",
                "Form submission destination detected",
                "\n".join(form_actions),
                (
                    "The HTML form submits data to the specified "
                    "destination. Form submission is normal web "
                    "application behavior, but the destination becomes "
                    "important when investigating possible credential "
                    "or data transmission."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Form method
    # --------------------------------------------------------------

    form_methods = html_analysis.get(
        "form_methods",
        []
    )

    if form_methods:
        findings.append(
            build_finding(
                "HTML Form Analysis",
                "Form submission method detected",
                ", ".join(form_methods),
                (
                    "The HTML specifies one or more form submission "
                    "methods. POST submissions are commonly used for "
                    "sending user-entered data to a server."
                ),
                "LOW",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Form destination analysis
    # --------------------------------------------------------------

    form_destinations = html_analysis.get(
        "form_destinations",
        {}
    )

    # HTTP destinations

    http_destinations = form_destinations.get(
        "http_destinations",
        []
    )

    if http_destinations:
        findings.append(
            build_finding(
                "HTML Form Destination Analysis",
                "Insecure HTTP form destination detected",
                "\n".join(http_destinations),
                (
                    "The HTML form submits data to an HTTP destination "
                    "without HTTPS transport. Data submitted through "
                    "HTTP may be exposed or modified while in transit. "
                    "This is a security-relevant observation, but it "
                    "does not by itself prove malicious behavior."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # IP address destinations

    ip_destinations = form_destinations.get(
        "ip_destinations",
        []
    )

    if ip_destinations:
        findings.append(
            build_finding(
                "HTML Form Destination Analysis",
                "IP address form destination detected",
                "\n".join(ip_destinations),
                (
                    "The HTML form submits data directly to an IP "
                    "address instead of a domain name. Direct IP "
                    "destinations can be legitimate, but they are "
                    "relevant during investigation because they may "
                    "identify infrastructure that is not represented "
                    "by a conventional domain."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # Unusual URL schemes

    unusual_scheme_destinations = form_destinations.get(
        "unusual_scheme_destinations",
        []
    )

    if unusual_scheme_destinations:
        findings.append(
            build_finding(
                "HTML Form Destination Analysis",
                "Unusual form destination scheme detected",
                "\n".join(unusual_scheme_destinations),
                (
                    "The HTML form specifies a destination using a "
                    "scheme other than HTTP or HTTPS. Non-standard "
                    "schemes can have specialized uses, but they are "
                    "worth investigating because they may alter normal "
                    "form submission behavior."
                ),
                "HIGH",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Iframe analysis
    # --------------------------------------------------------------

    iframes = html_analysis.get(
        "iframes",
        []
    )

    if iframes:
        findings.append(
            build_finding(
                "HTML Frame Analysis",
                "Iframe detected",
                "\n".join(iframes),
                (
                    "The HTML contains one or more iframe elements "
                    "that can embed another document or web resource. "
                    "Iframes are common in legitimate websites, but "
                    "their sources are relevant when investigating "
                    "embedded third-party or potentially untrusted "
                    "content."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # External iframe resources
    # --------------------------------------------------------------

    html_resources = html_analysis.get(
        "html_resources",
        {}
    )

    external_iframes = html_resources.get(
        "external_iframes",
        []
    )

    if external_iframes:
        findings.append(
            build_finding(
                "HTML Resource Analysis",
                "External iframe resource detected",
                "\n".join(external_iframes),
                (
                    "The HTML embeds one or more iframe resources "
                    "from an external HTTP or HTTPS destination. "
                    "External embedded content can be legitimate, "
                    "but its destination is relevant when investigating "
                    "untrusted or potentially deceptive content."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # External image resources
    # --------------------------------------------------------------

    external_images = html_resources.get(
        "external_images",
        []
    )

    if external_images:
        findings.append(
            build_finding(
                "HTML Resource Analysis",
                "External image resource detected",
                "\n".join(external_images),
                (
                    "The HTML loads one or more images from an "
                    "external HTTP or HTTPS destination. External "
                    "images are common in legitimate websites and "
                    "are recorded as resource observations for "
                    "further analysis."
                ),
                "LOW",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # External link resources
    # --------------------------------------------------------------

    external_links = html_resources.get(
        "external_links",
        []
    )

    if external_links:
        findings.append(
            build_finding(
                "HTML Resource Analysis",
                "External link resource detected",
                "\n".join(external_links),
                (
                    "The HTML references one or more external "
                    "resources through link elements. These commonly "
                    "include stylesheets and other page resources. "
                    "The destination is recorded for further analysis."
                ),
                "LOW",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Unusual iframe schemes
    # --------------------------------------------------------------

    unusual_iframes = html_resources.get(
        "unusual_iframes",
        []
    )

    if unusual_iframes:
        findings.append(
            build_finding(
                "HTML Resource Analysis",
                "Unusual iframe resource scheme detected",
                "\n".join(unusual_iframes),
                (
                    "The HTML iframe uses a scheme other than the "
                    "standard HTTP or HTTPS schemes. Unusual resource "
                    "schemes can change normal browser resource "
                    "handling and should be investigated."
                ),
                "HIGH",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Unusual image schemes
    # --------------------------------------------------------------

    unusual_images = html_resources.get(
        "unusual_images",
        []
    )

    if unusual_images:
        findings.append(
            build_finding(
                "HTML Resource Analysis",
                "Unusual image resource scheme detected",
                "\n".join(unusual_images),
                (
                    "The HTML image resource uses a scheme other "
                    "than HTTP or HTTPS. Unusual schemes may have "
                    "specialized purposes but are worth investigating "
                    "because they can alter normal resource handling."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    # --------------------------------------------------------------
    # Unusual link schemes
    # --------------------------------------------------------------

    unusual_links = html_resources.get(
        "unusual_links",
        []
    )

    if unusual_links:
        findings.append(
            build_finding(
                "HTML Resource Analysis",
                "Unusual link resource scheme detected",
                "\n".join(unusual_links),
                (
                    "The HTML link resource uses a scheme other "
                    "than HTTP or HTTPS. Unusual schemes may have "
                    "specialized purposes but are worth investigating "
                    "because they can alter normal resource handling."
                ),
                "MEDIUM",
                "HIGH"
            )
        )

    return findings