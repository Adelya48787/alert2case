"""Fayl backend-i, case başlığı və defang testləri."""

import json
from pathlib import Path

import pytest

from app.case import file_backend
from app.case.base import defang, title
from app.rules.engine import decide
from tests.unit.factories import make


@pytest.mark.parametrize(
    "value,expected",
    [
        ("http://evil.example/a", "hxxp://evil[.]example/a"),
        ("https://evil.example/a", "hxxps://evil[.]example/a"),
        ("8.8.8.8", "8[.]8[.]8[.]8"),
    ],
)
def test_defang(value, expected):
    assert defang(value) == expected


def test_title_contains_priority_type_hash_and_host():
    alert = make(verdict="malicious", score=89, host="DC-01")
    decision = decide(alert)

    result = title(alert, decision)

    assert result == (f"[{decision.priority}][malicious_hash] {'a' * 16}… on DC-01")


def test_url_title_is_defanged():
    alert = make(alert_type="suspicious_url")
    result = title(alert, decide(alert))

    assert "hxxp://x[.]example/a" in result
    assert "http://" not in result


@pytest.mark.asyncio
async def test_file_backend_create_and_comment(monkeypatch, tmp_path):
    case_dir = tmp_path / "cases"
    monkeypatch.setattr(file_backend, "CASE_DIR", case_dir)

    alert = make(verdict="malicious", score=89, host="DC-01")
    decision = decide(alert)
    backend = file_backend.FileBackend()

    ref = await backend.create(alert, decision)
    await backend.comment(ref, "Analitik yoxladı")

    path = Path(ref.url)
    doc = json.loads(path.read_text(encoding="utf-8"))

    assert ref.backend == "file"
    assert path.parent == case_dir
    assert doc["case_id"] == ref.case_id
    assert doc["title"] == title(alert, decision)
    assert doc["priority"] == decision.priority
    assert doc["verdict"] == "malicious"
    assert f"fp:{alert.fingerprint}" in doc["tags"]
    assert len(doc["tasks"]) == 3
    assert len(doc["observables"]) == len(alert.observables)
    assert doc["comments"][0]["text"] == "Analitik yoxladı"


@pytest.mark.asyncio
async def test_file_backend_shadow_description(monkeypatch, tmp_path):
    monkeypatch.setattr(file_backend, "CASE_DIR", tmp_path / "cases")
    alert = make()
    decision = decide(alert).model_copy(update={"action": "create_case", "shadow": True})

    ref = await file_backend.FileBackend().create(alert, decision)
    doc = json.loads(Path(ref.url).read_text(encoding="utf-8"))

    assert "Shadow mode" in doc["description"]
