import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

import app.models  # noqa: F401  (registers all tables on Base.metadata)
from app.api import analytics, auth, check, reports
from app.core.config import get_settings
from app.core.logging import setup_logging
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.services.cache import TTLCache
from app.services.classifier import ScamClassifier
from app.services.embeddings import build_embedder
from app.services.llm import build_explainer
from app.services.ratelimit import SlidingWindowLimiter
from app.services.risk import RiskEngine

log = logging.getLogger("scamshield")


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    setup_logging()
    if s.auto_create_tables:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    # Load heavy objects ONCE, not per request
    app.state.embedder = build_embedder(s.embedder, s.embedding_dim)
    app.state.risk_engine = RiskEngine(
        classifier=ScamClassifier.load_or_train(),
        embedder=app.state.embedder,
        explainer=build_explainer(s.llm_provider, s.ollama_url, s.ollama_model, s.llm_timeout_seconds),
    )
    app.state.limiter = SlidingWindowLimiter(s.rate_limit_per_minute)
    app.state.check_cache = TTLCache(s.check_cache_seconds)
    log.info("startup complete", extra={"extra_fields": {"env": s.environment, "llm": s.llm_provider}})
    yield
    await engine.dispose()


app = FastAPI(
    title="ScamShield API",
    version="1.0.0",
    description="Detect scam SMS, phone numbers, UPI IDs and links. Crowd-sourced reports + ML + LLM explanations.",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def request_logging(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex[:12])
    started = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    log.info("request", extra={"extra_fields": {
        "request_id": request_id, "method": request.method, "path": request.url.path,
        "status": response.status_code, "ms": round((time.perf_counter() - started) * 1000, 1)}})
    return response


for r in (auth.router, reports.router, check.router, analytics.router):
    app.include_router(r)


@app.get("/health", tags=["ops"])
async def health():
    async with SessionLocal() as db:
        await db.execute(text("SELECT 1"))
    return {"status": "ok", "database": "ok"}
