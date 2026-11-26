import enum


class Role(enum.StrEnum):
    citizen = "citizen"
    moderator = "moderator"
    admin = "admin"


class EntityType(enum.StrEnum):
    phone = "phone"
    upi = "upi"
    url = "url"


class ScamType(enum.StrEnum):
    kyc_update = "kyc_update"
    fake_job = "fake_job"
    lottery_prize = "lottery_prize"
    upi_collect = "upi_collect"
    loan_app = "loan_app"
    impersonation = "impersonation"
    investment = "investment"
    delivery = "delivery"
    other = "other"


class ReportStatus(enum.StrEnum):
    pending = "pending"
    verified = "verified"
    rejected = "rejected"


class Verdict(enum.StrEnum):
    likely_safe = "likely_safe"
    suspicious = "suspicious"
    high_risk = "high_risk"
