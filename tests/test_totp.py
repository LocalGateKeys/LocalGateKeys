from localvault.totp import generate_totp, parse_otpauth_uri


def test_totp_matches_rfc_6238_sha1_vector() -> None:
    # Base32("12345678901234567890")
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    code, remaining = generate_totp(secret, timestamp=59, digits=8, period=30, algorithm="SHA1")
    assert code == "94287082"
    assert remaining == 1


def test_parse_otpauth_uri() -> None:
    result = parse_otpauth_uri(
        "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30"
    )
    assert result["issuer"] == "Example"
    assert result["label"] == "Example:alice@example.com"
    assert result["digits"] == 6
