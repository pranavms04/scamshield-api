"""Create demo data: an admin, a moderator and verified scam patterns from the seed dataset.
Run:  python -m scripts.seed"""
import asyncio

import pandas as pd
from sqlalchemy import select

import app.models  # noqa: F401
from app.core.config import get_settings
from app.core.security import hash_password
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models import ScamPattern, User
from app.models.enums import Role, ScamType
from app.services.embeddings import build_embedder
from app.services.llm import KEYWORD_TO_TYPE

DEMO_USERS = [("admin@scamshield.dev", Role.admin), ("moderator@scamshield.dev", Role.moderator)]


async def main() -> None:
    s = get_settings()
    embedder = build_embedder(s.embedder, s.embedding_dim)
    if s.auto_create_tables:  # SQLite dev mode; on Postgres run `alembic upgrade head` first
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    async with SessionLocal() as db:
        for email, role in DEMO_USERS:
            if not (await db.execute(select(User).where(User.email == email))).scalar_one_or_none():
                db.add(User(email=email, password_hash=hash_password("ChangeMe123!"), role=role))
        if not (await db.execute(select(ScamPattern).limit(1))).first():
            scams = pd.read_csv("ml/data/seed_messages.csv").query("label == 1").text.tolist()
            vectors = embedder.embed(scams)
            for text, vec in zip(scams, vectors, strict=True):
                stype = next((t for kw, t in KEYWORD_TO_TYPE if kw in text.lower()), ScamType.other)
                db.add(ScamPattern(text=text, scam_type=stype, embedding=vec))
        await db.commit()
    print("Seeded demo users (password ChangeMe123!) and scam patterns.")


if __name__ == "__main__":
    asyncio.run(main())
