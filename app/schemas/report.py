from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import EntityType, ReportStatus, ScamType


class ReportCreate(BaseModel):
    entity_type: EntityType
    entity_value: str = Field(min_length=3, max_length=500, examples=["+91 98765 43210"])
    scam_type: ScamType
    description: str = Field(min_length=10, max_length=2000)
    message_text: str | None = Field(default=None, max_length=2000, description="The scam message, if any")


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    entity_id: int
    scam_type: ScamType
    description: str
    status: ReportStatus
    created_at: datetime


class ModerationDecision(BaseModel):
    status: ReportStatus = Field(description="verified or rejected")
    note: str | None = Field(default=None, max_length=500)


class EntityReputation(BaseModel):
    type: EntityType
    value: str
    known: bool
    verified_reports: int
    pending_reports: int
    reputation_score: float = Field(ge=0, le=1, description="0 = no evidence, 1 = confirmed scam")
    top_scam_type: ScamType | None
