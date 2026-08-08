"""
Have I Been Pwned (HIBP) Breach Checker.

Provides:

1. Password breach checking using the HIBP Pwned Passwords
   k-anonymity API.

2. Email breach checking using the HIBP Breached Account API.

Security requirements:
- Passwords are never logged.
- Password hashes are never logged.
- HIBP API keys are never logged.
- Password checks use k-anonymity.
- Email addresses are masked before logging.
- Network/API failures are returned in a structured format.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

import requests

from modules.logger import (
    logger,
    log_api_error,
    log_email_breach,
    log_email_check,
)


# ============================================================
# HIBP Configuration
# ============================================================

PASSWORD_API_URL = (
    "https://api.pwnedpasswords.com/range/"
)

EMAIL_API_URL = (
    "https://haveibeenpwned.com/api/v3/breachedaccount/"
)

DEFAULT_TIMEOUT = 10

HIBP_USER_AGENT = (
    "Password-Strength-Breach-Checker"
)


# ============================================================
# Email Validation / Masking
# ============================================================

def is_valid_email(email: str) -> bool:
    """
    Perform basic email validation.

    This is intentionally lightweight. HIBP remains the
    authoritative service for determining whether an account
    exists in its breach database.
    """

    if not email:
        return False

    email = email.strip()

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    return bool(re.match(pattern, email))


def mask_email(email: str) -> str:
    """
    Safely mask an email address for logging.

    Example:

        hassan@example.com
        ->
        h***n@example.com
    """

    if not email or "@" not in email:
        return "***"

    local, domain = email.split("@", 1)

    if not local:
        return f"***@{domain}"

    if len(local) == 1:
        masked_local = "*"
    elif len(local) == 2:
        masked_local = f"{local[0]}*"
    else:
        masked_local = (
            f"{local[0]}"
            f"{'*' * (len(local) - 2)}"
            f"{local[-1]}"
        )

    return f"{masked_local}@{domain}"


# ============================================================
# Password Hashing
# ============================================================

def hash_and_split(password: str) -> tuple[str, str]:
    """
    Hash a password using SHA-1 and split the hash into:

        prefix: first 5 characters
        suffix: remaining characters

    Only the prefix is sent to HIBP.

    The complete hash never leaves this application.
    """

    sha1_hash = hashlib.sha1(
        password.encode("utf-8")
    ).hexdigest().upper()

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    return prefix, suffix


# ============================================================
# Password Breach Checker
# ============================================================

def check_password_breach(
    password: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Check whether a password has appeared in known breaches.

    Uses the HIBP Pwned Passwords k-anonymity API.

    Only the first five characters of the SHA-1 hash are
    transmitted to HIBP.

    Returns
    -------
    dict
        {
            "breached": bool,
            "count": int,
            "error": str | None
        }
    """

    if not password:
        return {
            "breached": False,
            "count": 0,
            "error": "empty_password",
        }

    try:

        prefix, suffix = hash_and_split(password)

        response = requests.get(
            f"{PASSWORD_API_URL}{prefix}",
            timeout=timeout,
            headers={
                "User-Agent": HIBP_USER_AGENT,
            },
        )

        # ----------------------------------------------------
        # Authentication / permission errors
        # ----------------------------------------------------

        if response.status_code in (401, 403):

            log_api_error(
                logger,
                "HIBP Password API",
                Exception(
                    f"HTTP {response.status_code}"
                ),
            )

            return {
                "breached": False,
                "count": 0,
                "error": "api_authentication_error",
            }

        # ----------------------------------------------------
        # Rate limiting
        # ----------------------------------------------------

        if response.status_code == 429:

            log_api_error(
                logger,
                "HIBP Password API",
                Exception("HTTP 429 - rate limit exceeded"),
            )

            return {
                "breached": False,
                "count": 0,
                "error": "rate_limited",
            }

        # ----------------------------------------------------
        # HIBP server errors
        # ----------------------------------------------------

        if 500 <= response.status_code <= 599:

            log_api_error(
                logger,
                "HIBP Password API",
                Exception(
                    f"HTTP {response.status_code}"
                ),
            )

            return {
                "breached": False,
                "count": 0,
                "error": "api_server_error",
            }

        # ----------------------------------------------------
        # Other unexpected HTTP errors
        # ----------------------------------------------------

        response.raise_for_status()

        # ----------------------------------------------------
        # Parse k-anonymity response
        # ----------------------------------------------------

        for line in response.text.splitlines():

            if ":" not in line:
                continue

            returned_suffix, count = line.split(
                ":",
                1,
            )

            if returned_suffix.upper() == suffix:

                breach_count = int(
                    count.strip()
                )

                return {
                    "breached": True,
                    "count": breach_count,
                    "error": None,
                }

        return {
            "breached": False,
            "count": 0,
            "error": None,
        }

    except requests.Timeout as error:

        log_api_error(
            logger,
            "HIBP Password API",
            error,
        )

        return {
            "breached": False,
            "count": 0,
            "error": "timeout",
        }

    except requests.ConnectionError as error:

        log_api_error(
            logger,
            "HIBP Password API",
            error,
        )

        return {
            "breached": False,
            "count": 0,
            "error": "connection_error",
        }

    except requests.RequestException as error:

        log_api_error(
            logger,
            "HIBP Password API",
            error,
        )

        return {
            "breached": False,
            "count": 0,
            "error": "request_error",
        }

    except (ValueError, TypeError) as error:

        log_api_error(
            logger,
            "HIBP Password API",
            error,
        )

        return {
            "breached": False,
            "count": 0,
            "error": "invalid_response",
        }


# ============================================================
# Email Breach Checker
# ============================================================

def check_email_breach(
    email: str,
    api_key: str | None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Check whether an email address appears in known breaches.

    Uses the HIBP Breached Account API.

    Parameters
    ----------
    email:
        Email address to check.

    api_key:
        HIBP API key.

    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    dict
        {
            "checked": bool,
            "breached": bool,
            "count": int,
            "breaches": list,
            "error": str | None
        }
    """

    # --------------------------------------------------------
    # Normalize input
    # --------------------------------------------------------

    email = (email or "").strip()

    # --------------------------------------------------------
    # Email missing
    # --------------------------------------------------------

    if not email:

        return {
            "checked": False,
            "breached": False,
            "count": 0,
            "breaches": [],
            "error": "email_missing",
        }

    # --------------------------------------------------------
    # Validate email
    # --------------------------------------------------------

    if not is_valid_email(email):

        log_email_check(
            logger,
            email,
        )

        return {
            "checked": False,
            "breached": False,
            "count": 0,
            "breaches": [],
            "error": "invalid_email",
        }

    # --------------------------------------------------------
    # API key missing
    # --------------------------------------------------------

    if not api_key:

        log_email_check(
            logger,
            email,
        )

        return {
            "checked": False,
            "breached": False,
            "count": 0,
            "breaches": [],
            "error": "api_key_missing",
        }

    # --------------------------------------------------------
    # Prepare request
    # --------------------------------------------------------

    encoded_email = requests.utils.quote(
        email,
        safe="",
    )

    headers = {
        "hibp-api-key": api_key,
        "user-agent": HIBP_USER_AGENT,
    }

    log_email_check(
        logger,
        email,
    )

    try:

        response = requests.get(
            f"{EMAIL_API_URL}{encoded_email}",
            headers=headers,
            timeout=timeout,
        )

        # ----------------------------------------------------
        # Invalid API key
        # ----------------------------------------------------

        if response.status_code == 401:

            log_api_error(
                logger,
                "HIBP Email API",
                Exception("HTTP 401 - invalid API key"),
            )

            return {
                "checked": True,
                "breached": False,
                "count": 0,
                "breaches": [],
                "error": "invalid_api_key",
            }

        # ----------------------------------------------------
        # Forbidden
        # ----------------------------------------------------

        if response.status_code == 403:

            log_api_error(
                logger,
                "HIBP Email API",
                Exception("HTTP 403 - forbidden"),
            )

            return {
                "checked": True,
                "breached": False,
                "count": 0,
                "breaches": [],
                "error": "forbidden",
            }

        # ----------------------------------------------------
        # No breach found
        # ----------------------------------------------------

        if response.status_code == 404:

            return {
                "checked": True,
                "breached": False,
                "count": 0,
                "breaches": [],
                "error": None,
            }

        # ----------------------------------------------------
        # Rate limit
        # ----------------------------------------------------

        if response.status_code == 429:

            log_api_error(
                logger,
                "HIBP Email API",
                Exception(
                    "HTTP 429 - rate limit exceeded"
                ),
            )

            return {
                "checked": True,
                "breached": False,
                "count": 0,
                "breaches": [],
                "error": "rate_limited",
            }

        # ----------------------------------------------------
        # Server errors
        # ----------------------------------------------------

        if 500 <= response.status_code <= 599:

            log_api_error(
                logger,
                "HIBP Email API",
                Exception(
                    f"HTTP {response.status_code}"
                ),
            )

            return {
                "checked": True,
                "breached": False,
                "count": 0,
                "breaches": [],
                "error": "api_server_error",
            }

        # ----------------------------------------------------
        # Other HTTP errors
        # ----------------------------------------------------

        response.raise_for_status()

        # ----------------------------------------------------
        # Parse breach response
        # ----------------------------------------------------

        data = response.json()

        if not isinstance(data, list):

            return {
                "checked": True,
                "breached": False,
                "count": 0,
                "breaches": [],
                "error": "invalid_response",
            }

        breaches = []

        for breach in data:

            if not isinstance(breach, dict):
                continue

            breaches.append(
                {
                    "name": breach.get(
                        "Name"
                    ),
                    "title": breach.get(
                        "Title"
                    ),
                    "domain": breach.get(
                        "Domain"
                    ),
                    "date": breach.get(
                        "BreachDate"
                    ),
                    "description": breach.get(
                        "Description"
                    ),
                    "data_classes": breach.get(
                        "DataClasses",
                        [],
                    ),
                    "is_verified": breach.get(
                        "IsVerified"
                    ),
                }
            )

        breach_count = len(breaches)

        # ----------------------------------------------------
        # Log breach result
        # ----------------------------------------------------

        if breach_count > 0:

            log_email_breach(
                logger,
                email,
                breach_count,
            )

        return {
            "checked": True,
            "breached": breach_count > 0,
            "count": breach_count,
            "breaches": breaches,
            "error": None,
        }

    except requests.Timeout as error:

        log_api_error(
            logger,
            "HIBP Email API",
            error,
        )

        return {
            "checked": True,
            "breached": False,
            "count": 0,
            "breaches": [],
            "error": "timeout",
        }

    except requests.ConnectionError as error:

        log_api_error(
            logger,
            "HIBP Email API",
            error,
        )

        return {
            "checked": True,
            "breached": False,
            "count": 0,
            "breaches": [],
            "error": "connection_error",
        }

    except requests.RequestException as error:

        log_api_error(
            logger,
            "HIBP Email API",
            error,
        )

        return {
            "checked": True,
            "breached": False,
            "count": 0,
            "breaches": [],
            "error": "request_error",
        }

    except ValueError as error:

        log_api_error(
            logger,
            "HIBP Email API",
            error,
        )

        return {
            "checked": True,
            "breached": False,
            "count": 0,
            "breaches": [],
            "error": "invalid_response",
        }


# ============================================================
# Safe Standalone Test
# ============================================================

if __name__ == "__main__":

    print("HIBP Breach Checker")
    print("=" * 50)

    password = input(
        "Enter a password to check: "
    )

    result = check_password_breach(
        password
    )

    if result["error"]:

        print(
            f"Error: {result['error']}"
        )

    elif result["breached"]:

        print("Password breached: YES")
        print(
            f"Occurrences: {result['count']:,}"
        )

    else:

        print("Password breached: NO")
