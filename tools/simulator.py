"""dataset/raw/*.json → POST /ingest/{source}, HMAC-SHA256 imzası ilə.

python tools/simulator.py                       # 36 alert, saniyədə 1
python tools/simulator.py --rate 5 --only HASH-01,URL-02
python tools/simulator.py --burst 30            # 30-u bir anda (rate limit testi)
python tools/simulator.py --repeat 2            # hər alert 2 dəfə (dedup testi)
python tools/simulator.py --bad-signature       # 401 gözlənilir

Hər fayl: {"source": "wazuh|edr|proxy", "payload": {...}}
Çıxış kodu: hamısı gözlənilən statusla qəbul olunubsa 0, əks halda 1.
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
    secret = os.environ.get("WEBHOOK_HMAC_SECRET", "")
    if not secret:
        raise typer.BadParameter("WEBHOOK_HMAC_SECRET .env-də yoxdur")
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@app.command()
def send(
    dataset: Path = Path("dataset/raw"),
    url: str = "http://localhost:8000",
    rate: float = typer.Option(1.0, min=0.01),
    burst: int = typer.Option(0, min=0),
    only: str = "",
    repeat: int = typer.Option(1, min=1),
    shuffle: bool = True,
    bad_signature: bool = False,
) -> None:
    files = sorted(dataset.glob("*.json"))
    if only:
        wanted = {x.strip() for x in only.split(",") if x.strip()}
        files = [f for f in files if f.stem in wanted]
        missing = wanted - {f.stem for f in files}
        if missing:
            typer.echo(f"Tapılmadı: {', '.join(sorted(missing))}", err=True)
    if not files:
        typer.echo(f"{dataset}/ içində göndəriləcək alert yoxdur", err=True)
        raise typer.Exit(1)
    files = files * repeat
    if shuffle:
        random.shuffle(files)
    expected = 401 if bad_signature else 202
    ok = 0
    with httpx.Client(timeout=10) as client:
        for n, f in enumerate(files, 1):
            doc = json.loads(f.read_text(encoding="utf-8"))
            body = json.dumps(doc["payload"], separators=(",", ":")).encode()
            sig = "sha256=" + "0" * 64 if bad_signature else sign(body)
            try:
                r = client.post(
                    f"{url}/ingest/{doc['source']}",
                    content=body,
                    headers={"Content-Type": "application/json", "X-Signature": sig},
                )
            except httpx.TransportError as e:
                typer.echo(f"API əlçatmazdır ({url}): {type(e).__name__}", err=True)
                raise typer.Exit(1) from None
            ok += r.status_code == expected
            typer.echo(f"{n:3d} {f.stem:10s} → {r.status_code} {r.text[:70]}")
            if n == len(files) or (burst and n % burst != 0):
                continue
            time.sleep(1 / rate)
    typer.echo(f"Göndərildi: {len(files)}, gözlənilən cavab ({expected}): {ok}")
    if ok != len(files):
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
