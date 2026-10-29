import json
from pathlib import Path

from app.schemas.alert import NormalizedAlert

out = Path("schemas/normalized_alert.v1.json")
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps(NormalizedAlert.model_json_schema(), indent=2) + "\n", encoding="utf-8")
print("yazildi:", out)
