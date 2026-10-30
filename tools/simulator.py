"""dataset/raw/*.json → POST /ingest/{source}, HMAC-SHA256 imzası ilə.

python tools/simulator.py                       # 36 alert, saniyədə 1
python tools/simulator.py --rate 5 --only HASH-01,URL-02
python tools/simulator.py --burst 30            # 30-u bir anda (rate limit testi)
python tools/simulator.py --repeat 2            # hər alert 2 dəfə (dedup testi)
python tools/simulator.py --bad-signature       # 401 gözlənilir
"""

import hashlib
import hmac
import json
import os
import random
import time
from pathlib import Path

import httpx
import typer
from dotenv import load_dotenv

load_dotenv()
app = typer.Typer(add_completion=False)


def sign(body: bytes) -> str:
    secret = os.environ["WEBHOOK_HMAC_SECRET"].encode()
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


@app.command()
def send(
    dataset: Path = Path("dataset/raw"),
    url: str = "http://localhost:8000",
    rate: float = 1.0,
    burst: int = 0,
    only: str = "",
    repeat: int = 1,
    shuffle: bool = True,
    bad_signature: bool = False,
) -> None:
    files = sorted(dataset.glob("*.json"))
    if only:
        wanted = set(only.split(","))
        files = [f for f in files if f.stem in wanted]
    files = files * repeat
    if shuffle:
        random.shuffle(files)
    ok = 0
    with httpx.Client(timeout=10) as client:
        for n, f in enumerate(files, 1):
            doc = json.loads(f.read_text(encoding="utf-8"))
            body = json.dumps(doc["payload"], separators=(",", ":")).encode()
            sig = "sha256=" + "0" * 64 if bad_signature else sign(body)
            r = client.post(
                f"{url}/ingest/{doc['source']}",
                content=body,
                headers={"Content-Type": "application/json", "X-Signature": sig},
            )
            ok += r.status_code == 202
            typer.echo(f"{n:3d} {f.stem:10s} → {r.status_code} {r.text[:70]}")
            if burst and n % burst != 0:
                continue
            time.sleep(1 / rate)
    typer.echo(f"Göndərildi: {len(files)}, qəbul edildi (202): {ok}")


if __name__ == "__main__":
    app()
