"""Plain-language explanation of WHY something looks like a scam.
OllamaExplainer calls a local LLM (free). RuleExplainer is the offline fallback.
If the LLM is down or returns junk, we degrade gracefully instead of failing the request."""
import json
import logging
from typing import Protocol

import httpx
from pydantic import ValidationError

from app.models.enums import ScamType
from app.schemas.check import Explanation

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a fraud-prevention assistant for Indian users.
Given a message and detection signals, respond ONLY with JSON:
{"scam_type": one of %s, "red_flags": [short strings], "advice": "2-3 sentences, simple English"}.
Never ask the user to click links or share OTP/PIN. If it looks safe, say so in advice.""" % [t.value for t in ScamType]

KEYWORD_TO_TYPE = [
    ("kyc", ScamType.kyc_update), ("aadhaar", ScamType.kyc_update), ("job", ScamType.fake_job),
    ("part time", ScamType.fake_job), ("lottery", ScamType.lottery_prize), ("won", ScamType.lottery_prize),
    ("upi pin", ScamType.upi_collect), ("loan", ScamType.loan_app), ("invest", ScamType.investment),
    ("courier", ScamType.delivery), ("parcel", ScamType.delivery), ("police", ScamType.impersonation),
]


class Explainer(Protocol):
    async def explain(self, text: str, flags: list[str], score: float) -> Explanation: ...


class RuleExplainer:
    async def explain(self, text: str, flags: list[str], score: float) -> Explanation:
        lower = text.lower()
        scam_type = next((t for kw, t in KEYWORD_TO_TYPE if kw in lower), ScamType.other)
        if score >= 0.4:
            advice = ("Do not click links, share OTP/PIN, or pay anyone. Contact the organisation through its "
                      "official app or number. Report it at cybercrime.gov.in or call 1930.")
        else:
            advice = "No strong scam signals found. Still, never share OTP or UPI PIN with anyone."
        return Explanation(scam_type=scam_type, red_flags=flags, advice=advice, source="rules")


class OllamaExplainer:
    def __init__(self, base_url: str, model: str, timeout: float, fallback: Explainer):
        self.base_url, self.model, self.timeout, self.fallback = base_url, model, timeout, fallback

    async def explain(self, text: str, flags: list[str], score: float) -> Explanation:
        user = f"Message: {text}\nDetected red flags: {flags}\nRisk score: {score:.2f}"
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}],
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.1},
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.post(f"{self.base_url}/api/chat", json=body)
                r.raise_for_status()
            data = json.loads(r.json()["message"]["content"])
            return Explanation(**data, source="llm")
        except (httpx.HTTPError, KeyError, json.JSONDecodeError, ValidationError, TypeError) as exc:
            log.warning("LLM explanation failed, using rules fallback: %s", exc)
            return await self.fallback.explain(text, flags, score)


def build_explainer(provider: str, base_url: str, model: str, timeout: float) -> Explainer:
    rules = RuleExplainer()
    return OllamaExplainer(base_url, model, timeout, rules) if provider == "ollama" else rules
