"""
Have I Been Pwned Email Breach Checker

Checks whether an email address has appeared
in known public data breaches using the official
HIBP Breached Account API.

Requirements:
- Valid HIBP API key
- Internet connection
"""

from __future__ import annotations

import os
from typing import Dict

import requests
from dotenv import load_dotenv
from email_validator import (
    validate_email,
    EmailNotValidError,
)

load_dotenv()

HIBP_API_KEY = os.getenv("HIBP_API_KEY", "").strip()

HIBP_URL = (
    "https://haveibeenpwned.com/api/v3/"
    "breachedaccount/"
)

HEADERS = {
    "hibp-api-key": HIBP_API_KEY,
    "user-agent": "PasswordSecurityToolkit/1.0",
}


def check_email_breach(email: str) -> Dict:
    """
    Check whether an email address appears in
    Have I Been Pwned.

    Returns a standardized dictionary.
    """

    # -------------------------------
    # Validate email
    # -------------------------------

    try:
        validated = validate_email(email)

        email = validated.email

    except EmailNotValidError as exc:

        return {
            "enabled": bool(HIBP_API_KEY),
            "checked": False,
            "breached": False,
            "count": 0,
            "breaches": [],
            "message": str(exc),
        }

    # -------------------------------
    # API key configured?
    # -------------------------------

    if not HIBP_API_KEY:

        return {
            "enabled": False,
            "checked": False,
            "breached": False,
            "count": 0,
            "breaches": [],
            "message": (
                "HIBP API key is not configured."
            ),
        }

    # -------------------------------
    # Perform request
    # -------------------------------

    try:

        response = requests.get(
            HIBP_URL + email,
            headers=HEADERS,
            params={
                "truncateResponse": "false"
            },
            timeout=15,
        )

    except requests.RequestException as exc:

        return {
            "enabled": True,
            "checked": False,
            "breached": False,
            "count": 0,
            "breaches": [],
            "message": str(exc),
        }

    # -------------------------------
    # Success
    # -------------------------------

    if response.status_code == 200:

        data = response.json()

        return {
            "enabled": True,
            "checked": True,
            "breached": True,
            "count": len(data),
            "breaches": [
                breach["Name"]
                for breach in data
            ],
            "message": "Breaches found.",
        }

    # -------------------------------
    # Not breached
    # -------------------------------

    if response.status_code == 404:

        return {
            "enabled": True,
            "checked": True,
            "breached": False,
            "count": 0,
            "breaches": [],
            "message": (
                "Email not found in any known breaches."
            ),
        }

    # -------------------------------
    # Invalid API key
    # -------------------------------

    if response.status_code == 401:

        return {
            "enabled": True,
            "checked": False,
            "breached": False,
            "count": 0,
            "breaches": [],
            "message": "Invalid HIBP API key.",
        }

    # -------------------------------
    # Rate limit
    # -------------------------------

    if response.status_code == 429:

        return {
            "enabled": True,
            "checked": False,
            "breached": False,
            "count": 0,
            "breaches": [],
            "message": (
                "HIBP rate limit exceeded."
            ),
        }

    # -------------------------------
    # Other errors
    # -------------------------------

    return {
        "enabled": True,
        "checked": False,
        "breached": False,
        "count": 0,
        "breaches": [],
        "message": (
            f"HIBP returned HTTP "
            f"{response.status_code}."
        ),
    }


def main():

    email = input("Email: ")

    result = check_email_breach(email)

    from pprint import pprint

    pprint(result)


if __name__ == "__main__":
    main()
