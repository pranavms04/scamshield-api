"""Hand-written red-flag rules. Cheap, explainable, and they catch things a small model misses."""
import re

RULES: list[tuple[str, re.Pattern]] = [
    ("Creates urgency (account blocked / today / immediately)",
     re.compile(r"\b(blocked|suspend\w*|expire[sd]?|today|immediately|within \d+ ?(hours?|hrs|minutes?)|last chance)\b", re.I)),
    ("Asks for KYC / PAN / Aadhaar update", re.compile(r"\b(kyc|pan ?card|aadhaar|aadhar)\b", re.I)),
    ("Asks for OTP, PIN or password", re.compile(r"\b(otp|pin|cvv|password)\b", re.I)),
    ("Promises prize, lottery, cashback or refund", re.compile(r"\b(won|winner|lottery|prize|cashback|refund|reward|lucky)\b", re.I)),
    ("Easy-money job offer", re.compile(r"\b(work from home|part[- ]time|earn ₹?\s?\d+|daily income|like videos|youtube likes|task)\b", re.I)),
    ("Payment request disguised as receiving money",
     re.compile(r"\b(scan|enter (your )?upi pin|collect request|to receive)\b", re.I)),
    ("Shortened or suspicious link", re.compile(r"\b(bit\.ly|tinyurl|t\.co|cutt\.ly|rb\.gy|\.xyz|\.top|\.link)\b", re.I)),
    ("Impersonates bank, courier, police or government",
     re.compile(r"\b(sbi|hdfc|icici|rbi|income tax|customs|police|cbi|fedex|india post|electricity (bill|board))\b", re.I)),
    ("Instant loan with no documents", re.compile(r"\b(instant loan|loan approved|pre-?approved|no documents?)\b", re.I)),
]


def rule_flags(text: str) -> list[str]:
    return [label for label, pattern in RULES if pattern.search(text)]
