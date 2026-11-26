import pytest

from app.models.enums import EntityType
from app.services.normalize import extract_entities, normalize


@pytest.mark.parametrize("raw", ["+91 98765 43210", "9876543210", "09876543210", "+91-98765-43210"])
def test_phone_variants_normalize_to_one_value(raw):
    assert normalize(EntityType.phone, raw) == "+919876543210"


def test_invalid_phone():
    assert normalize(EntityType.phone, "12345") is None


def test_extract_from_message():
    msg = "KYC expired. Call 9876543210 or pay to fraud.kyc@ybl. Visit http://bit.ly/kyc-upd now"
    found = extract_entities(msg)
    assert found[EntityType.phone] == ["+919876543210"]
    assert found[EntityType.upi] == ["fraud.kyc@ybl"]
    assert found[EntityType.url] == ["bit.ly/kyc-upd"]
