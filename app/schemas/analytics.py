from datetime import date

from pydantic import BaseModel

from app.models.enums import EntityType, ScamType


class TrendingEntity(BaseModel):
    type: EntityType
    value: str
    verified_reports: int
    rank: int


class ScamTypeShare(BaseModel):
    scam_type: ScamType
    reports: int
    share_pct: float


class DailyChecks(BaseModel):
    day: date
    checks: int
    high_risk: int
    high_risk_pct: float
    avg_latency_ms: float
