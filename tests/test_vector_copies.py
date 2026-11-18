"""Platform test-resource copies of the shared vectors must stay byte-identical to their sources.

Every task that copies a vector into a platform's test resources adds its (source, copy) pair here.
"""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

COPIES = [
    ("tests/vectors/markdown/cases.json", "android/lgk-core/src/test/resources/markdown_cases.json"),
    ("tests/vectors/wifi_qr/cases.json", "android/lgk-core/src/test/resources/wifi_qr_cases.json"),
    ("tests/vectors/jwt/cases.json", "android/lgk-core/src/test/resources/jwt_cases.json"),
    ("tests/vectors/composite_key/cases.json", "android/lgk-core/src/test/resources/composite_key/cases.json"),
    ("tests/vectors/composite_key/android_apppassword_v2.bin", "android/lgk-core/src/test/resources/composite_key/android_apppassword_v2.bin"),
    ("tests/vectors/composite_key/keyfiles/arbitrary.txt", "android/lgk-core/src/test/resources/composite_key/keyfiles/arbitrary.txt"),
    ("tests/vectors/composite_key/keyfiles/hex64.key", "android/lgk-core/src/test/resources/composite_key/keyfiles/hex64.key"),
    ("tests/vectors/composite_key/keyfiles/hex64_newline.key", "android/lgk-core/src/test/resources/composite_key/keyfiles/hex64_newline.key"),
    ("tests/vectors/composite_key/keyfiles/not_hex64.key", "android/lgk-core/src/test/resources/composite_key/keyfiles/not_hex64.key"),
    ("tests/vectors/composite_key/keyfiles/raw32.key", "android/lgk-core/src/test/resources/composite_key/keyfiles/raw32.key"),
    ("tests/vectors/composite_key/keyfiles/reject_xml_doctype.key", "android/lgk-core/src/test/resources/composite_key/keyfiles/reject_xml_doctype.key"),
    ("tests/vectors/composite_key/keyfiles/reject_xml_no_data.key", "android/lgk-core/src/test/resources/composite_key/keyfiles/reject_xml_no_data.key"),
    ("tests/vectors/composite_key/keyfiles/reject_xml_v1_short.key", "android/lgk-core/src/test/resources/composite_key/keyfiles/reject_xml_v1_short.key"),
    ("tests/vectors/composite_key/keyfiles/reject_xml_v2_bad_hash.keyx", "android/lgk-core/src/test/resources/composite_key/keyfiles/reject_xml_v2_bad_hash.keyx"),
    ("tests/vectors/composite_key/keyfiles/xml_v1.key", "android/lgk-core/src/test/resources/composite_key/keyfiles/xml_v1.key"),
    ("tests/vectors/composite_key/keyfiles/xml_v2.keyx", "android/lgk-core/src/test/resources/composite_key/keyfiles/xml_v2.keyx"),
]


@pytest.mark.parametrize(("source", "copy"), COPIES)
def test_copy_is_byte_identical(source, copy):
    assert (ROOT / copy).read_bytes() == (ROOT / source).read_bytes(), f"{copy} differs from {source}"
