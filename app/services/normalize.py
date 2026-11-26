"""Find and normalise phone numbers, UPI IDs and URLs so the same scammer always maps to one DB row."""
import re
from urllib.parse import urlparse

from app.models.enums import EntityType

PHONE_RE = re.compile(r"(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}")
UPI_RE = re.compile(r"\b[\w.\-]{2,256}@[a-zA-Z]{2,64}\b")
URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+|\b[a-z0-9-]+\.(?:ly|in|com|xyz|top|link|io|co)/[^\s]*", re.I)


def normalize_phone(raw: str) -> str | None:
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    if len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    if len(digits) == 10 and digits[0] in "6789":
        return "+91" + digits
    return None


def normalize_upi(raw: str) -> str | None:
    raw = raw.strip().lower()
    return raw if UPI_RE.fullmatch(raw) and "." not in raw.split("@")[1] else None


def normalize_url(raw: str) -> str | None:
    raw = raw.strip().rstrip(".,)")
    if not raw.lower().startswith(("http://", "https://")):
        raw = "http://" + raw
    p = urlparse(raw)
    if not p.netloc or "." not in p.netloc:
        return None
    host = p.netloc.lower().removeprefix("www.")
    return f"{host}{p.path.rstrip('/')}"


NORMALIZERS = {EntityType.phone: normalize_phone, EntityType.upi: normalize_upi, EntityType.url: normalize_url}


def normalize(entity_type: EntityType, raw: str) -> str | None:
    return NORMALIZERS[entity_type](raw)


def extract_entities(text: str) -> dict[EntityType, list[str]]:
    found: dict[EntityType, set[str]] = {t: set() for t in EntityType}
    for m in URL_RE.findall(text):
        if (v := normalize_url(m)):
            found[EntityType.url].add(v)
    text_wo_urls = URL_RE.sub(" ", text)
    for m in UPI_RE.findall(text_wo_urls):
        if (v := normalize_upi(m)):
            found[EntityType.upi].add(v)
    for m in PHONE_RE.findall(text_wo_urls):
        if (v := normalize_phone(m)):
            found[EntityType.phone].add(v)
    return {t: sorted(v) for t, v in found.items() if v}
