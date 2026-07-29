"""Unit tests for Aadhaar number format validation (app.validation)."""
from app.validation import generate_synthetic_aadhaar, is_valid_aadhaar_number


def test_valid_synthetic_number_passes():
    number = generate_synthetic_aadhaar("12345678901")
    assert is_valid_aadhaar_number(number)


def test_wrong_length_rejected():
    assert is_valid_aadhaar_number("12345") is False
    assert is_valid_aadhaar_number("1234567890123") is False


def test_non_digit_rejected():
    assert is_valid_aadhaar_number("1234abcd9012") is False


def test_bad_checksum_rejected():
    number = generate_synthetic_aadhaar("12345678901")
    tampered = number[:-1] + str((int(number[-1]) + 1) % 10)
    assert is_valid_aadhaar_number(tampered) is False


def test_various_bases_round_trip():
    for base in ["00000000000", "99999999999", "12345678901", "55501234567", "00000000001"]:
        number = generate_synthetic_aadhaar(base)
        assert len(number) == 12
        assert is_valid_aadhaar_number(number)


def test_generate_rejects_wrong_length_base():
    import pytest

    with pytest.raises(ValueError):
        generate_synthetic_aadhaar("123")
