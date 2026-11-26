from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from app.models.enums import EntityType, ReportStatus, ScamType
from app.schemas.common import SafeText, StrictModel, entity_value_for, must_have_letters

Description = Annotated[SafeText, Field(min_length=20, max_length=2000), AfterValidator(must_have_letters)]


class ReportCreate(StrictModel):
    entity_type: EntityType
    entity_value: Annotated[SafeText, Field(min_length=3, max_length=500, examples=["+91 98765 43210"],
                                            description="Phone number, UPI ID or link, matching entity_type")]
    scam_type: ScamType
    description: Annotated[Description, Field(
        examples=["Caller said my SBI KYC expired and asked me to share the OTP"],
        description="What happened, in your own words (20-2000 characters)")]
    message_text: Annotated[SafeText | None, Field(default=None, min_length=10, max_length=2000,
                                                   description="The scam message, if any")]

    @model_validator(mode="after")
    def normalise_entity(self):
        try:
            self.entity_value = entity_value_for(self.entity_type, self.entity_value)
        except ValueError as e:
            raise ValueError(f"entity_value {e}") from None
        return self


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    entity_id: int
    scam_type: ScamType
    description: str
    status: ReportStatus
    created_at: datetime


class ModerationDecision(StrictModel):
    status: Literal[ReportStatus.verified, ReportStatus.rejected] = Field(description="verified or rejected")
    note: Annotated[SafeText | None, Field(default=None, min_length=5, max_length=500,
                                           description="Required when rejecting, so the citizen knows why")]

    @model_validator(mode="after")
    def note_required_for_rejection(self):
        if self.status == ReportStatus.rejected and not self.note:
            raise ValueError("A note (at least 5 characters) is required when rejecting a report")
        return self


class EntityReputation(BaseModel):
    type: EntityType
    value: str
    known: bool
    verified_reports: int
    pending_reports: int
    reputation_score: float = Field(ge=0, le=1, description="0 = no evidence, 1 = confirmed scam")
    top_scam_type: ScamType | None
