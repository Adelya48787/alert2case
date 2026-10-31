#!/usr/bin/env bash
# alert2case · Phase 2 çıxış yoxlaması
# Hər üzv öz kompüterində, repo qovluğunda, main branch-da işlədir:
#   tools/phase2_exit.sh
# Nə edir: mühiti, servisləri və bütün axını yoxlayır. 36 alert-i göndərir (dedup sayəsində
# 15 dəqiqə ərzində təkrar işlətmək yeni sətir yaratmır), bir xarab mesajla DLQ-nu sınayır
# və sınaq mesajını DLQ-dan silir. Kodu və fayllarınızı dəyişmir. Açarlar ekrana çıxmır.

PASS=0; FAILN=0; WARNN=0; SUMMARY=""
ok()   { printf '  \033[32mOK  \033[0m %s\n' "$1"; PASS=$((PASS+1)); SUMMARY="$SUMMARY $2:OK"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${3:-}" ] && printf '       \033[2m→ %s\033[0m\n' "$3"; FAILN=$((FAILN+1)); SUMMARY="$SUMMARY $2:FAIL"; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$1"; [ -n "${3:-}" ] && printf '       \033[2m→ %s\033[0m\n' "$3"; WARNN=$((WARNN+1)); SUMMARY="$SUMMARY $2:WARN"; }
section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
[ -z "$ROOT" ] && { echo "Bu qovluq git repo deyil. Əvvəlcə: cd ~/projects/alert2case"; exit 1; }
cd "$ROOT" || exit 1
PY=.venv/bin/python
REPO_SLUG="Adelya48787/alert2case"
DC="docker compose"
psql_q() { $DC exec -T postgres psql -U soc -d alert2case -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
rcli()   { $DC exec -T redis redis-cli "$@" 2>/dev/null; }

WHO=$(git config user.name 2>/dev/null)
printf '\033[1malert2case · Phase 2 çıxış yoxlaması\033[0m\n'
printf 'Üzv: %s · Tarix: %s\n' "${WHO:-?}" "$(date '+%Y-%m-%d %H:%M')"

# =================================================================== 1. Repo və Python
section "1 · Repo və Python"
if git remote get-url origin 2>/dev/null | grep -q "$REPO_SLUG"; then ok "origin = $REPO_SLUG" repo
else bad "origin ortaq repo deyil" repo; fi

BR=$(git branch --show-current)
git fetch -q origin main 2>/dev/null
BEHIND=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo "?")
if [ "$BR" = "main" ] && [ "$BEHIND" = "0" ]; then ok "main branch-dasınız, GitHub ilə eynidir" main
elif [ "$BR" != "main" ]; then bad "Hazırda '$BR' branch-dasınız" main "git switch main && git pull"
else bad "main GitHub-dan $BEHIND commit geridədir" main "git pull"; fi

if git ls-files --error-unmatch .env >/dev/null 2>&1; then bad ".env repoda izlənir!" envtracked "Dərhal Team Lead-ə yazın"
else ok ".env repoya düşmür" envtracked; fi

if [ -x "$PY" ] && [ "$($PY -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)" = "3.12" ]; then ok ".venv Python 3.12" venv
else bad ".venv yoxdur və ya Python 3.12 deyil" venv "uv venv .venv --python 3.12"; fi

if $PY -c 'import fastapi, redis, asyncpg, alembic, tldextract, httpx, typer, pytest, hypothesis' >/dev/null 2>&1; then ok "Paketlər tamdır (requirements + dev)" pkgs
else bad "Bəzi paketlər çatışmır" pkgs "source .venv/bin/activate && uv pip install -r requirements.txt -r requirements-dev.txt"; fi

# =================================================================== 2. .env
section "2 · .env"
if [ -f .env ]; then
  DUP=$(grep -oE '^[A-Z_]+=' .env | sort | uniq -d | tr -d '=' | tr '\n' ' ')
  if [ -z "$DUP" ]; then ok "Təkrar açar yoxdur" envdup
  else bad "Təkrar açarlar: $DUP" envdup "Hər açar .env-də bir dəfə olmalıdır, artıq sətri silin"; fi
  EMPTY=""
  for K in WEBHOOK_HMAC_SECRET DATABASE_URL REDIS_URL ADMIN_TOKEN POSTGRES_PASSWORD; do
    V=$(grep -E "^$K=" .env | tail -1 | cut -d= -f2-)
    [ -z "$V" ] && EMPTY="$EMPTY $K"
  done
  if [ -z "$EMPTY" ]; then ok "Phase 2 açarları doludur (dəyərlər göstərilmir)" envkeys
  else bad "Boş və ya yoxdur:$EMPTY" envkeys ".env.example-a baxın, dəyərləri .env-ə yazın"; fi
  if grep -q $'\r' .env; then bad ".env-də Windows sətir sonu (\\r) var" envcrlf "sed -i 's/\\r\$//' .env"
  else ok ".env-də \\r yoxdur" envcrlf; fi
else bad ".env faylı yoxdur" envdup "cp .env.example .env və dəyərləri doldurun"; fi

# =================================================================== 3. Servislər
section "3 · Servislər (Docker)"
if ! docker info >/dev/null 2>&1; then
  bad "Docker işləmir" docker "Docker Desktop-u açın"
else
  for S in postgres redis; do
    ST=$($DC ps --format '{{.Service}} {{.Health}}' 2>/dev/null | awk -v s="$S" '$1==s{print $2}')
    [ "$ST" = "healthy" ] && ok "$S: healthy" "svc_$S" || bad "$S: ${ST:-işləmir}" "svc_$S" "make up"
  done
  for S in api worker; do
    ST=$($DC ps --format '{{.Service}} {{.State}}' 2>/dev/null | awk -v s="$S" '$1==s{print $2}')
    [ "$ST" = "running" ] && ok "$S: işləyir" "svc_$S" || bad "$S: ${ST:-işləmir}" "svc_$S" "docker compose up -d --build api worker"
  done
  HC=$(curl -s -o /dev/null -w '%{http_code}' localhost:8000/health)
  [ "$HC" = "200" ] && ok "API /health → 200" health || bad "API /health → $HC" health "docker compose logs api --tail 20"
fi

# =================================================================== 4. Baza
section "4 · Baza və miqrasiya"
HEAD_REV=$(grep -h '^revision' migrations/versions/*.py 2>/dev/null | sed -E "s/.*['\"]([^'\"]+)['\"].*/\\1/" | while read -r r; do grep -qE "^down_revision.*['\"]$r['\"]" migrations/versions/*.py || echo "$r"; done | head -1)
DB_REV=$(psql_q "select version_num from alembic_version")
if [ -n "$HEAD_REV" ] && [ "$DB_REV" = "$HEAD_REV" ]; then ok "Miqrasiya tətbiq olunub ($DB_REV)" migrate
else bad "Bazada miqrasiya: '${DB_REV:-yoxdur}', kodda: '${HEAD_REV:-?}'" migrate "make migrate"; fi
TABLES=$(psql_q "select count(*) from information_schema.tables where table_name in ('alerts','audit_log')")
[ "$TABLES" = "2" ] && ok "alerts və audit_log cədvəlləri var" tables || bad "Cədvəllər tapılmadı" tables "make migrate"

# =================================================================== 5. Dataset
section "5 · Dataset"
N_RAW=$(ls dataset/raw/*.json 2>/dev/null | wc -l | tr -d ' ')
N_SNAP=$(ls dataset/snapshots/*.json 2>/dev/null | wc -l | tr -d ' ')
N_EXP=$(($(wc -l < dataset/expected.csv 2>/dev/null || echo 1) - 1))
[ "$N_RAW" = "36" ] && ok "dataset/raw: 36 alert" raw || bad "dataset/raw: $N_RAW alert (36 olmalıdır)" raw "git pull"
[ "$N_SNAP" = "84" ] && ok "dataset/snapshots: 84 fayl" snaps || bad "dataset/snapshots: $N_SNAP fayl (84 olmalıdır)" snaps "git pull"
[ "$N_EXP" = "36" ] && ok "dataset/expected.csv: 36 etiket" truth || bad "dataset/expected.csv: $N_EXP etiket" truth "git pull"
NORM=$($PY -m tools.normalize_dataset 2>&1 | tail -1)
echo "$NORM" | grep -q "^36 alert normalizə olundu" && ok "normalize_dataset: 36/36" normalize || bad "normalize_dataset: $NORM" normalize

# =================================================================== 6. Tam axın
section "6 · Tam axın: simulyator → API → Redis → worker → baza"
SIM=$($PY tools/simulator.py --rate 10 2>&1 | tail -1)
if echo "$SIM" | grep -q "Göndərildi: 36, gözlənilən cavab (202): 36"; then ok "Simulyator: 36/36 → 202" simulate
else bad "Simulyator: ${SIM:-cavab yoxdur}" simulate "docker compose logs api --tail 20"; fi
FRESH=0
for _ in $(seq 1 20); do
  FRESH=$(psql_q "select count(distinct source_ref) from alerts where last_seen > now() - interval '3 minutes'")
  [ "$FRESH" = "36" ] && break; sleep 1
done
[ "$FRESH" = "36" ] && ok "Worker 36 alert-in hamısını bazaya yazıb" pipeline || bad "Bazaya son 3 dəqiqədə çatan alert: ${FRESH:-0}/36" pipeline "docker compose logs worker --tail 30"
PEND=$(rcli XPENDING alerts.in pipeline | head -1 | tr -d '[:space:]')
if [ -z "$PEND" ]; then bad "Redis-ə qoşulmaq olmadı" pending "make up"
elif [ "$PEND" = "0" ]; then ok "Redis-də ACK gözləyən mesaj yoxdur" pending
else warn "ACK gözləyən mesaj: $PEND" pending "docker compose logs worker --tail 30"; fi

# =================================================================== 7. Audit log
section "7 · Audit log"
AUD=$(psql_q "select count(*) from audit_log where stage='ingest' and event='received'")
[ "${AUD:-0}" -ge 36 ] 2>/dev/null && ok "audit_log-da ingest sətirləri: $AUD" audit || bad "audit_log-da ingest sətri: ${AUD:-0}" audit
CHAIN=$($PY - <<'PYEOF' 2>&1
import asyncio, os
from dotenv import load_dotenv
load_dotenv(".env")
import asyncpg
from app.audit.log import GENESIS, row_hash
async def main():
    c = await asyncpg.connect(os.environ["DATABASE_URL"])
    import json
    await c.set_type_codec("jsonb", schema="pg_catalog", encoder=json.dumps, decoder=json.loads)
    prev, n = GENESIS, 0
    for r in await c.fetch("SELECT * FROM audit_log ORDER BY id"):
        if r["prev_hash"] != prev or r["row_hash"] != row_hash(prev, r["ts"], r["correlation_id"], r["stage"], r["event"], r["actor"], r["payload"]):
            print(f"BROKEN id={r['id']}"); return
        prev, n = r["row_hash"], n + 1
    print(f"OK {n}")
    await c.close()
try:
    asyncio.run(main())
except Exception as e:
    print(f"{type(e).__name__}: {e}"[:120])
PYEOF
)
case "$CHAIN" in OK*) ok "Hash zənciri qırılmayıb (${CHAIN#OK } sətir)" chain ;; *) bad "Hash zənciri: $(echo "$CHAIN" | tail -1)" chain ;; esac

# =================================================================== 8. DLQ
section "8 · DLQ: xarab mesaj itmir"
BEFORE=$(rcli XREVRANGE alerts.dlq + - COUNT 1 | head -1)
SENT=$($PY - <<'PYEOF' 2>&1
import hashlib, hmac, os
import httpx
from dotenv import load_dotenv
load_dotenv(".env")
body = b"not-json"
sig = "sha256=" + hmac.new(os.environ["WEBHOOK_HMAC_SECRET"].encode(), body, hashlib.sha256).hexdigest()
try:
    r = httpx.post("http://localhost:8000/ingest/edr", content=body, headers={"X-Signature": sig, "Content-Type": "application/json"}, timeout=10)
    print(r.status_code)
except Exception as e:
    print(type(e).__name__)
PYEOF
)
NEWID=""; STAGE=""
for _ in $(seq 1 15); do
  NEWID=$(rcli XREVRANGE alerts.dlq + - COUNT 1 | head -1)
  if [ -n "$NEWID" ] && [ "$NEWID" != "$BEFORE" ]; then
    STAGE=$(rcli XREVRANGE alerts.dlq + - COUNT 1 | awk 'p{print;exit} /^stage$/{p=1}'); break
  fi
  sleep 1
done
if [ "$SENT" = "202" ] && [ "$STAGE" = "normalize" ]; then ok "not-json → 202 → DLQ (stage normalize)" dlq
else bad "DLQ yoxlaması: API=$SENT, DLQ stage='${STAGE:-yoxdur}'" dlq "docker compose logs worker --tail 30"; fi
TOKEN=$(grep -E '^ADMIN_TOKEN=' .env 2>/dev/null | tail -1 | cut -d= -f2-)
DLQHTTP=$(curl -s -o /dev/null -w '%{http_code}' localhost:8000/dlq -H "X-Admin-Token: $TOKEN")
[ "$DLQHTTP" = "200" ] && ok "GET /dlq (admin) → 200" dlqapi || bad "GET /dlq → $DLQHTTP" dlqapi "ADMIN_TOKEN-i yoxlayın (təkrar sətir?)"
[ -n "$NEWID" ] && [ "$NEWID" != "$BEFORE" ] && rcli XDEL alerts.dlq "$NEWID" >/dev/null   # sınaq mesajını sil

TB=$($DC logs worker --since 10m 2>/dev/null | grep -c Traceback)
if ! $DC ps --services --status running 2>/dev/null | grep -qx worker; then bad "Worker işləmir, log yoxlanmadı" traceback "docker compose up -d worker"
elif [ "$TB" = "0" ]; then ok "Worker log-unda son 10 dəqiqədə traceback yoxdur" traceback
else warn "Worker log-unda $TB traceback" traceback "docker compose logs worker --since 10m"; fi

# =================================================================== 9. Testlər və lint
section "9 · Testlər və kod keyfiyyəti"
TEST=$($PY -m pytest tests/unit -p no:cacheprovider --cov --cov-fail-under=85 2>&1 | tail -3)
if echo "$TEST" | grep -qE '^[0-9]+ passed' && ! echo "$TEST" | grep -q failed && echo "$TEST" | grep -q "coverage of 85% reached"; then
  ok "pytest: $(echo "$TEST" | grep -oE '^[0-9]+ passed'), coverage ≥ 85%" tests
else bad "pytest: $(echo "$TEST" | tail -1)" tests "pytest tests/unit -q ilə baxın"; fi
if [ -x .venv/bin/pre-commit ]; then
  T=$(mktemp -d); git archive HEAD | tar -x -C "$T"
  LINT=$(cd "$T" && git init -q && git add -A >/dev/null 2>&1 && "$ROOT/.venv/bin/pre-commit" run --all-files 2>&1; echo "rc=$?")
  rm -rf "$T"
  echo "$LINT" | grep -q 'rc=0$' && ok "CI lint (pre-commit --all-files) keçir" lint || bad "CI lint keçmir" lint "pre-commit run --all-files"
fi

# =================================================================== Nəticə
printf '\n\033[1mNƏTİCƏ:\033[0m %d OK · %d FAIL · %d WARN\n' "$PASS" "$FAILN" "$WARNN"
if [ $FAILN -eq 0 ]; then printf '\033[32mPhase 2 bu kompüterdə tam işləyir.\033[0m\n'
else printf '\033[31mFAIL olan sətirlərin altındakı → göstərişə əməl edin.\033[0m\n'; fi
printf '\nQrupa göndərmək üçün:\nP2EXIT %s |%s\n' "${WHO:-?}" "$SUMMARY"
[ $FAILN -eq 0 ]
