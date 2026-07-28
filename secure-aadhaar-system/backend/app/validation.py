"""
validation.py
Aadhaar number format validation: 12 digits with a valid Verhoeff checksum
as the 12th digit — the check-digit scheme UIDAI uses. This validates that a
number is *well-formed*, not that it's a real, issued Aadhaar number.
"""

# Standard Verhoeff multiplication (D) and permutation (P) tables (RFC-free,
# widely published algorithm). Self-consistency between generation and
# validation below is covered by tests; either table alone is meaningless.
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def _checksum(digits: str) -> int:
    c = 0
    for i, digit in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(digit)]]
    return c


def is_valid_aadhaar_number(number: str) -> bool:
    """12 digits, and the last digit satisfies the Verhoeff checksum over the full number."""
    if not (len(number) == 12 and number.isdigit()):
        return False
    return _checksum(number) == 0


def generate_synthetic_aadhaar(base_11_digits: str) -> str:
    """
    Build a well-formed 12-digit synthetic Aadhaar number (11-digit base + a
    valid Verhoeff check digit) for tests and local development. Never use
    real Aadhaar numbers in development — see README Legal & Compliance.
    """
    if not (len(base_11_digits) == 11 and base_11_digits.isdigit()):
        raise ValueError("base_11_digits must be exactly 11 digits")

    c = 0
    for i, digit in enumerate(reversed(base_11_digits)):
        c = _D[c][_P[(i + 1) % 8][int(digit)]]
    check_digit = _INV[c]
    return base_11_digits + str(check_digit)
