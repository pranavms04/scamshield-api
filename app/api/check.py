from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import Client, get_client
from app.db.session import get_db
from app.schemas.check import CheckRequest, CheckResponse
from app.services.risk import input_hash, log_check

router = APIRouter(prefix="/v1", tags=["check"])


@router.post("/check", response_model=CheckResponse)
async def check(req: CheckRequest, request: Request, client: Client = Depends(get_client),
                db: AsyncSession = Depends(get_db)):
    """Score a message / phone / UPI ID / URL for scam risk. Auth: `X-API-Key` header or Bearer token."""
    state = request.app.state
    key = input_hash(req) + (":x" if req.explain else "")
    cached: CheckResponse | None = state.check_cache.get(key)
    if cached:
        resp = cached.model_copy(update={"cached": True, "latency_ms": 0})
    else:
        resp = await state.risk_engine.check(db, req)
        state.check_cache.set(key, resp)
    await log_check(db, input_hash(req), resp, client.api_key_id, client.user_id)
    return resp
