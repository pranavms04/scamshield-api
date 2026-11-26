# Import every model so Base.metadata (and Alembic) knows about all tables.
from app.models.api_key import ApiKey
from app.models.check import CheckLog
from app.models.entity import Entity
from app.models.report import Report
from app.models.scam_pattern import ScamPattern
from app.models.user import User

__all__ = ["ApiKey", "CheckLog", "Entity", "Report", "ScamPattern", "User"]
