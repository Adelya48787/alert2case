"""Parser interfeysi və registry: mənbə adına görə lazım olan parser seçilir (Strategy pattern)."""

from abc import ABC, abstractmethod
from datetime import datetime

from pydantic import ValidationError

from app.errors import PermanentError
from app.normalize.iocs import fingerprint
from app.schemas.alert import NormalizedAlert, Severity


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class BaseParser(ABC):
    source: str

    @abstractmethod
    def parse(self, payload: dict, received_at: datetime) -> NormalizedAlert: ...


PARSERS: dict[str, BaseParser] = {}


def register(cls):
    PARSERS[cls.source] = cls()
    return cls


def normalize(source: str, payload: dict, received_at: datetime) -> NormalizedAlert:
    parser = PARSERS.get(source)
    if parser is None:
        raise PermanentError(f"naməlum mənbə: {source}")
    try:
        alert = parser.parse(payload, received_at)
    except (KeyError, TypeError, ValueError, AttributeError, ValidationError) as e:
        raise PermanentError(f"{source} parse xətası: {type(e).__name__}: {e}") from e
    alert.fingerprint = fingerprint(alert.alert_type, alert.observables)
    return alert


__all__ = ["BaseParser", "PARSERS", "Severity", "normalize", "parse_ts", "register"]
