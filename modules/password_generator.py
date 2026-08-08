"""
This module generates cryptographically secure passwords using Python's secrets module.

Features:
- Configurable length
- Uppercase letters
- Lowercase letters
- Digits
- Symbols
- Memorable passphrase (later)
"""

import secrets
import string

UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{}<>?"
AMBIGUOUS = "O0oIl1"

DEFAULT_LENGTH = 16
MIN_LENGTH = 12
MAX_LENGTH = 64


def build_character_pool(
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """
    Build the character pool based on user preferences.
    """

    pool = ""

    if uppercase:
        pool += UPPERCASE

    if lowercase:
        pool += LOWERCASE

    if digits:
        pool += DIGITS

    if symbols:
        pool += SYMBOLS

    if exclude_ambiguous:
        pool = "".join(c for c in pool if c not in AMBIGUOUS)

    if not pool:
        raise ValueError("At least one character set must be selected.")

    return pool


def generate_password(
    length: int = DEFAULT_LENGTH,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:

    if length < MIN_LENGTH or length > MAX_LENGTH:
        raise ValueError(
            f"Password length must be between {MIN_LENGTH} and {MAX_LENGTH}"
        )

    pool = build_character_pool(
        uppercase,
        lowercase,
        digits,
        symbols,
        exclude_ambiguous,
    )

    if exclude_ambiguous:

        uppercase_chars = "".join(c for c in UPPERCASE if c not in AMBIGUOUS)

        lowercase_chars = "".join(c for c in LOWERCASE if c not in AMBIGUOUS)

        digit_chars = "".join(c for c in DIGITS if c not in AMBIGUOUS)

        symbol_chars = SYMBOLS

    else:

        uppercase_chars = UPPERCASE
        lowercase_chars = LOWERCASE
        digit_chars = DIGITS
        symbol_chars = SYMBOLS

    password = []

    if uppercase:
        password.append(secrets.choice(uppercase_chars))

    if lowercase:
        password.append(secrets.choice(lowercase_chars))

    if digits:
        password.append(secrets.choice(digit_chars))

    if symbols:
        password.append(secrets.choice(symbol_chars))

    if length < len(password):
        raise ValueError(
            "Password length is too short for the selected character sets."
        )

    remaining = length - len(password)

    for _ in range(remaining):
        password.append(secrets.choice(pool))

    """
    Unlike the random module, secrets doesn't provide a shuffle function,
    so implement a Fisher–Yates shuffle using secrets.randbelow().
    """

    for i in range(len(password) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password[i], password[j] = password[j], password[i]

    return "".join(password)


def main():

    while True:

        try:
            password = generate_password()
            print(f"\nGenerated Password: {password}")

        except ValueError as e:
            print(f"Error: {e}")

        choice = input("\nGenerate another? (y/n): ").lower()

        if choice != "y":
            break


if __name__ == "__main__":
    main()
