from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ScamPattern
from app.schemas.check import SimilarScam
from app.services.embeddings import cosine


async def find_similar(db: AsyncSession, query_vec: list[float], k: int = 3, min_sim: float = 0.3) -> list[SimilarScam]:
    if db.bind.dialect.name == "postgresql":
        # pgvector: the database does the nearest-neighbour search using the HNSW index.
        distance = ScamPattern.embedding.cosine_distance(query_vec)
        rows = (await db.execute(
            select(ScamPattern, distance.label("dist")).order_by(distance).limit(k)
        )).all()
        hits = [(p, 1 - d) for p, d in rows]
    else:
        # SQLite fallback for tests: brute force in Python (fine for a few hundred rows).
        patterns = (await db.execute(select(ScamPattern))).scalars().all()
        hits = sorted(((p, cosine(query_vec, p.embedding)) for p in patterns), key=lambda x: -x[1])[:k]
    return [SimilarScam(text=p.text, scam_type=p.scam_type, similarity=round(s, 3)) for p, s in hits if s >= min_sim]
