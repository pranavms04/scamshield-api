"""The /check pipeline: combine every signal into one explainable risk score."""
import hashlib
import json
import time

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CheckLog
from app.models.enums import EntityType, Verdict
from app.schemas.check import CheckRequest, CheckResponse, Signals
from app.services.classifier import ScamClassifier
from app.services.embeddings import Embedder
from app.services.llm import Explainer
from app.services.normalize import extract_entities, normalize
from app.services.reputation import get_reputation
from app.services.rules import rule_flags
from app.services.similarity import find_similar

# Weights for the content-based score. Tune these with labelled data (see Lesson 5).
W_CLASSIFIER, W_RULES, W_SIMILAR = 0.55, 0.25, 0.20


def input_hash(req: CheckRequest) -> str:
    payload = json.dumps(req.model_dump(exclude={"explain"}), sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def verdict_for(score: float) -> Verdict:
    return Verdict.high_risk if score >= 0.7 else Verdict.suspicious if score >= 0.4 else Verdict.likely_safe


class RiskEngine:
    def __init__(self, classifier: ScamClassifier, embedder: Embedder, explainer: Explainer):
        self.classifier, self.embedder, self.explainer = classifier, embedder, explainer

    async def check(self, db: AsyncSession, req: CheckRequest) -> CheckResponse:
        started = time.perf_counter()
        text = req.message or ""

        # 1. Entities: from the message + any passed explicitly
        entities = extract_entities(text) if text else {}
        for etype, raw in [(EntityType.phone, req.phone), (EntityType.upi, req.upi_id), (EntityType.url, req.url)]:
            if raw and (v := normalize(etype, raw)) and v not in entities.get(etype, []):
                entities.setdefault(etype, []).append(v)

        # 2. Reputation of each entity (crowd-sourced, moderator-verified reports)
        reputation = [await get_reputation(db, t, v) for t, vals in entities.items() for v in vals]
        rep_score = max((r.reputation_score for r in reputation), default=0.0)

        # 3. Content signals (only if there is message text)
        flags, clf_p, similar, content_score = [], None, [], 0.0
        if text:
            flags = rule_flags(text)
            clf_p = round(self.classifier.predict_proba(text), 3)
            similar = await find_similar(db, self.embedder.embed([text])[0])
            rule_score = min(1.0, len(flags) / 3)
            sim_score = similar[0].similarity if similar else 0.0
            content_score = W_CLASSIFIER * clf_p + W_RULES * rule_score + W_SIMILAR * sim_score

        # 4. A confirmed-scam number is high risk even if the message looks innocent
        score = round(max(rep_score, content_score), 3)
        verdict = verdict_for(score)

        explanation = None
        if req.explain and (text or score >= 0.4):
            explanation = await self.explainer.explain(text or str(entities), flags, score)

        return CheckResponse(
            risk_score=score, verdict=verdict, detected_entities=entities,
            signals=Signals(classifier_probability=clf_p, rule_flags=flags, reputation=reputation, similar_scams=similar),
            explanation=explanation, latency_ms=int((time.perf_counter() - started) * 1000),
        )


async def log_check(db: AsyncSession, req_hash: str, resp: CheckResponse,
                    api_key_id: int | None, user_id: int | None) -> None:
    db.add(CheckLog(
        api_key_id=api_key_id, user_id=user_id, input_hash=req_hash, risk_score=resp.risk_score,
        verdict=resp.verdict, scam_type=resp.explanation.scam_type if resp.explanation else None,
        latency_ms=resp.latency_ms, cached=resp.cached,
    ))
    await db.commit()
