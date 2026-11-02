"""n8n credential-larını .env-dən yaradır: n8n/credentials.local.json (gitignore-dadır, commit OLUNMUR).
ID-lər workflow JSON-larındakı ilə eynidir, ona görə import-dan sonra node-lar credential-ı özü tapır.

  python tools/n8n_credentials.py
"""

import json
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()
OUT = Path("n8n/credentials.local.json")


def main() -> None:
    creds = [
        {
            "id": "a2cAdminToken01",
            "name": "alert2case admin token",
            "type": "httpHeaderAuth",
            "data": {"name": "X-Admin-Token", "value": os.environ["ADMIN_TOKEN"]},
        },
        {
            "id": "a2cWebhookTok01",
            "name": "n8n webhook token",
            "type": "httpHeaderAuth",
            "data": {"name": "X-N8N-Token", "value": os.environ["N8N_WEBHOOK_TOKEN"]},
        },
        {
            "id": "a2cMailpitSmtp1",
            "name": "Mailpit SMTP",
            "type": "smtp",
            "data": {
                "user": "",
                "password": "",
                "host": "mailpit",
                "port": 1025,
                "secure": False,
                "disableStartTls": True,
            },
        },
    ]
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(creds, indent=2), encoding="utf-8")
    print(f"{OUT} yazıldı ({len(creds)} credential). Import-dan sonra silin.")


if __name__ == "__main__":
    main()
