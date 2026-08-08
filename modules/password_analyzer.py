"""
Central Password Analysis Engine.

This module coordinates all password analysis modules
and produces a single security report.

Optional email breach checking is performed through
the HIBP Breached Account API when an email address
and API key are supplied.
"""

from modules.entropy import analyze_password_entropy
from modules.strength_checker import extract_zxcvbn_results
from modules.custom_rules import evaluate_custom_rules

from modules.breach_checker import (
    check_password_breach,
    check_email_breach,
)


def analyze_password(
    password: str,
    email: str | None = None,
    hibp_api_key: str | None = None,
) -> dict:
    """
    Run all password security analysis modules.

    Parameters
    ----------
    password:
        Password to analyze.

    email:
        Optional email address to check against
        the HIBP breached-account database.

    hibp_api_key:
        Optional HIBP API key.

        This key is used only during the request and
        is never stored in the returned report.

    Returns
    -------
    dict
        Unified security report.
    """

    # ========================================================
    # Password Analysis
    # ========================================================

    entropy = analyze_password_entropy(password)

    strength = extract_zxcvbn_results(password)

    rules = evaluate_custom_rules(password)

    # ========================================================
    # Password Breach Check
    # ========================================================

    breach = check_password_breach(password)

    # ========================================================
    # Email Breach Check
    # ========================================================

    email_breach = {
        "checked": False,
        "breached": False,
        "count": 0,
        "breaches": [],
        "error": None,
    }

    # Only perform the email lookup when an email
    # was actually supplied.
    if email and email.strip():

        email_breach = check_email_breach(
            email=email,
            api_key=hibp_api_key,
        )

    # ========================================================
    # Unified Report
    # ========================================================

    return {
        "password": password,
        "entropy": entropy,
        "strength": strength,
        "rules": rules,
        "breach": breach,
        "email_breach": email_breach,
    }


def display_report(report: dict) -> None:
    """
    Display the analysis report in the terminal.
    """

    print("PASSWORD SECURITY REPORT")
    print("=" * 60)

    # ========================================================
    # Entropy
    # ========================================================

    entropy = report["entropy"]

    print("\nEntropy")
    print(
        f"Entropy : {entropy['entropy']} bits"
    )
    print(
        f"Rating  : {entropy['rating']}"
    )

    # ========================================================
    # zxcvbn
    # ========================================================

    strength = report["strength"]

    print("\nzxcvbn")
    print(
        f"Score : {strength['score']}/4"
    )

    print(
        "Offline Crack Time : "
        f"{strength['crack_time']['offline_fast_hashing_1e10_per_second']}"
    )

    print(
        "Online Crack Time  : "
        f"{strength['crack_time']['online_throttling_100_per_hour']}"
    )

    warning = strength["feedback"]["warning"]

    if warning:

        print("\nWarning:")
        print(f"• {warning}")

    suggestions = strength["feedback"]["suggestions"]

    if suggestions:

        print("\nSuggestions:")

        for suggestion in suggestions:
            print(f"• {suggestion}")

    # ========================================================
    # Custom Rules
    # ========================================================

    rules = report["rules"]

    print("\n[Custom Rules]")

    if rules["passed"]:

        print(
            "✓ Password satisfies all policy rules."
        )

    else:

        print("Issues:")

        for issue in rules["issues"]:
            print(f"• {issue}")

    # ========================================================
    # Password Breach
    # ========================================================

    breach = report["breach"]

    print("\nPassword Breach Check")

    if breach["breached"]:

        print(
            "Password appeared "
            f"{breach['count']:,} times "
            "in known data breaches."
        )

    elif breach.get("error"):

        print(
            f"Password breach check error: "
            f"{breach['error']}"
        )

    else:

        print(
            "Password was NOT found "
            "in the HIBP database."
        )

    # ========================================================
    # Email Breach
    # ========================================================

    email_breach = report["email_breach"]

    print("\nEmail Breach Check")

    if not email_breach["checked"]:

        if email_breach["error"]:

            print(
                f"Email check not performed: "
                f"{email_breach['error']}"
            )

        else:

            print(
                "No email address was supplied."
            )

    elif email_breach["breached"]:

        print(
            "Email found in "
            f"{email_breach['count']} breach(es)."
        )

        for breach_entry in email_breach["breaches"]:
        	breach_name = (breach_entry.get("title") or breach_entry.get("name") or "Unknown Breach")
        	print(f"• {breach_name}")

    elif email_breach["error"]:

        print(
            f"Email breach check error: "
            f"{email_breach['error']}"
        )

    else:

        print(
            "Email was NOT found "
            "in the HIBP breach database."
        )

    # ========================================================
    # Overall Status
    # ========================================================

    print("\n" + "=" * 60)

    if breach["breached"]:

        print("Overall Status : HIGH RISK")

    elif (
        strength["score"] < 3
        or not rules["passed"]
    ):

        print(
            "Overall Status : NEEDS IMPROVEMENT"
        )

    else:

        print(
            "Overall Status : STRONG PASSWORD"
        )

    print("=" * 60)


def main() -> None:

    while True:

        password = input(
            "\nEnter password (or 'exit'): "
        )

        if password.lower() == "exit":
            break

        email = input(
            "Email (optional): "
        ).strip()

        api_key = input(
            "HIBP API key (optional): "
        ).strip()

        report = analyze_password(
            password=password,
            email=email or None,
            hibp_api_key=api_key or None,
        )

        display_report(report)


if __name__ == "__main__":
    main()
