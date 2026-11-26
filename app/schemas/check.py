from typing import Annotated

from pydantic import BaseModel, Field, StrictBool, field_validator, model_validator

from app.models.enums import EntityType, ScamType, Verdict
from app.schemas.common import OptionalMobile, OptionalUpi, OptionalUrl, SafeText, StrictModel
from app.schemas.report import EntityReputation


class CheckRequest(StrictModel):
    message: Annotated[SafeText | None, Field(default=None, min_length=2, max_length=2000, examples=[
        "Dear customer your SBI KYC is expired. Update now at http://bit.ly/sbi-kyc or account will be blocked today"
    ])]
    phone: Annotated[OptionalMobile, Field(examples=["+91 98765 43210"])]
    upi_id: Annotated[OptionalUpi, Field(examples=["refund.help@ybl"])]
    url: Annotated[OptionalUrl, Field(examples=["bit.ly/sbi-kyc"])]
    explain: StrictBool = Field(default=True, description="Ask the LLM for a plain-language explanation")

    @field_validator("message", "phone", "upi_id", "url", mode="before")
    @classmethod
    def blank_is_missing(cls, v):
        return None if isinstance(v, str) and not v.strip() else v

    @model_validator(mode="after")
    def at_least_one(self):
        if not any([self.message, self.phone, self.upi_id, self.url]):
            raise ValueError("Provide at least one of: message, phone, upi_id, url")
        return self


class SimilarScam(BaseModel):
    text: str
    scam_type: ScamType
    similarity: float


class Explanation(BaseModel):
    scam_type: ScamType
    red_flags: list[str]
    advice: str
    source: str = Field(description="'llm' or 'rules' (fallback when the LLM is unavailable)")


class Signals(BaseModel):
    classifier_probability: float | None
    rule_flags: list[str]
    reputation: list[EntityReputation]
    similar_scams: list[SimilarScam]


class CheckResponse(BaseModel):
    risk_score: float = Field(ge=0, le=1)
    verdict: Verdict
    detected_entities: dict[EntityType, list[str]]
    signals: Signals
    explanation: Explanation | None
    cached: bool = False
    latency_ms: int
