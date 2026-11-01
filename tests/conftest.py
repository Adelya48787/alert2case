import os

# app.config import olunan anda Settings() yaradılır: test dəyərləri ondan əvvəl qoyulur
os.environ["WEBHOOK_HMAC_SECRET"] = "test-secret"
os.environ["ADMIN_TOKEN"] = "test-admin"
# testlər heç vaxt real intel API-yə sorğu atmasın: .env-dəki açarlar burada boşaldılır
os.environ["VT_API_KEY"] = ""
os.environ["ABUSEIPDB_API_KEY"] = ""
os.environ["OTX_API_KEY"] = ""

import json  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

RAW = Path("dataset/raw")


@pytest.fixture
def now():
    return datetime.now(timezone.utc)


@pytest.fixture
def raw_doc():
    def _load(name: str) -> dict:
        return json.loads((RAW / f"{name}.json").read_text(encoding="utf-8"))

    return _load
