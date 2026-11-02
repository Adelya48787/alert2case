"""dataset/raw/*.json → n8n webhook. Worker yolunun alternativi: n8n /stage/* endpoint-lərini çağırır.

python tools/send_n8n.py                          # 36 alert, saniyədə 0.5
python tools/send_n8n.py --only HASH-01,URL-02
python tools/send_n8n.py --url http://localhost:5678/webhook-test/alert2case   # redaktorda test
"""

import json
import os
import time
from pathlib import Path

import httpx
import typer
from dotenv import load_dotenv

load_dotenv()
app = typer.Typer(add_completion=False)


@app.command()
def send(
    dataset: Path = Path("dataset/raw"),
    url: str = "http://localhost:5678/webhook/alert2case",
    rate: float = 0.5,
    only: str = "",
) -> None:
    token = os.environ.get("N8N_WEBHOOK_TOKEN", "")
    files = sorted(dataset.glob("*.json"))
    if only:
        wanted = set(only.split(","))
        files = [f for f in files if f.stem in wanted]
    ok = 0
    with httpx.Client(timeout=10) as client:
        for n, f in enumerate(files, 1):
            doc = json.loads(f.read_text(encoding="utf-8"))
            r = client.post(
                url, json={"source": doc["source"], "payload": doc["payload"]}, headers={"X-N8N-Token": token}
            )
            ok += r.status_code == 200
            typer.echo(f"{n:3d} {f.stem:10s} → {r.status_code} {r.text[:60]}")
            time.sleep(1 / rate)
    typer.echo(f"Göndərildi: {len(files)}, n8n qəbul etdi (200): {ok}")


if __name__ == "__main__":
    app()
