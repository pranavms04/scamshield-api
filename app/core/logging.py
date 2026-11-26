import json
import logging
import sys


class JsonFormatter(logging.Formatter):
    """One JSON object per line — what log tools (Loki, CloudWatch, Datadog) expect."""

    def format(self, record: logging.LogRecord) -> str:
        data = {"level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        data.update(getattr(record, "extra_fields", {}))
        return json.dumps(data)


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
