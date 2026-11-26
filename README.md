# ScamShield API

**Scam detection API for India.** Send a suspicious SMS/WhatsApp message, phone number, UPI ID or link, and get back a risk score, the likely scam type, the red flags, and a plain-language explanation.

Built with **FastAPI · PostgreSQL + pgvector · SQLAlchemy 2.0 (async) · Alembic · scikit-learn · Ollama (local LLM) · Docker · GitHub Actions**. Runs entirely on free, local tools.

## Why

UPI, KYC, fake-job and "parcel held at customs" scams target millions of Indian phone users. ScamShield combines four signals into one explainable score:

| Signal | How |
|---|---|
| Crowd reputation | Citizens report numbers/UPI IDs/links; moderators verify; reputation = saturating function of verified reports |
| ML classifier | TF-IDF (word + char n-grams) + Logistic Regression |
| Red-flag rules | Regex rules for urgency, OTP/PIN requests, KYC, shortened links, impersonation |
| Similar known scams | Sentence embeddings + pgvector cosine search (HNSW index) |

An LLM (Ollama, local) turns the signals into advice. If the LLM is down, the API falls back to a rule-based explanation instead of failing.

## Architecture

```
Client app ──X-API-Key──▶ FastAPI ──▶ RiskEngine ──┬─▶ Entity extraction + normalisation
Citizen/Moderator ─JWT──▶   │                       ├─▶ Reputation (SQL aggregates)
                            │                       ├─▶ Classifier (scikit-learn)
                            │                       ├─▶ Similar scams (pgvector)
                            │                       └─▶ Explanation (Ollama ▸ rules fallback)
                            ├─▶ Rate limiter · TTL cache · JSON logs · audit log (hashed input)
                            └─▶ PostgreSQL 16 + pgvector  (Alembic migrations)
```

## Endpoints

| Method | Path | Who |
|---|---|---|
| POST | `/v1/auth/register`, `/v1/auth/login` | anyone |
| POST/GET/DELETE | `/v1/api-keys` | logged-in user |
| POST | `/v1/check` | API key or user |
| GET | `/v1/entities/lookup` | API key or user |
| POST/GET | `/v1/reports`, `/v1/reports/mine` | citizen |
| GET/POST | `/v1/moderation/reports`, `.../{id}/decision` | moderator, admin |
| GET | `/v1/analytics/trending`, `/scam-types`, `/daily-checks` | moderator, admin |
| GET | `/health` | anyone |

Interactive docs: `http://localhost:8000/docs`

## Run it

**Quick (SQLite, no Docker):**
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m ml.train          # trains the classifier, prints CV metrics
python -m scripts.seed      # demo users + scam patterns
fastapi dev app/main.py
```

**Full stack (PostgreSQL + pgvector + Ollama):**
```bash
docker compose up -d --build
docker compose exec ollama ollama pull llama3.2:3b
docker compose exec api python -m scripts.seed
```

Demo logins: `moderator@scamshield.dev` / `admin@scamshield.dev`, password `ChangeMe123!`.

## Test

```bash
pytest -q        # 20 tests, ~5 s, no network needed
ruff check .
```

CI (GitHub Actions) runs lint and tests, applies the migrations up/down/up on real PostgreSQL + pgvector, and builds the Docker image.

## Design decisions

- **Hash, don't store:** API keys are stored as SHA-256 hashes; `/check` logs store a hash of the input, never the private message.
- **Normalise entities:** `+91 98765-43210` and `09876543210` map to one row, enforced by a unique constraint.
- **Row locks for moderation:** `SELECT … FOR UPDATE` stops two moderators deciding the same report.
- **Graceful degradation:** if the LLM is unavailable, the API still answers using the rule-based explanation.
- **Swappable components:** embedder and explainer sit behind interfaces, so tests run offline in seconds.

## Roadmap

Redis-backed rate limit and cache · Celery/ARQ worker for ingestion · Hindi/Malayalam support with multilingual embeddings · webhook alerts for B2B clients · a Flutter app as the client.
# scamshield-api
