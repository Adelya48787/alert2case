#!/usr/bin/env bash
# alert2case · Phase 3 çıxış yoxlaması
# Hər üzv öz kompüterində, repo qovluğunda, main branch-da işlədir:
#   tools/phase3_exit.sh
# Nə edir: runbook-un ✓3 siyahısındakı 7 maddəni yoxlayır. Real intel API-yə az sorğu atır:
# VirusTotal-a 1 (rate limiter-dən icazə alaraq), AbuseIPDB-yə 1, OTX-ə 1–2. Simulyatorla 1 alert
# (HASH-01) göndərir. Kodu, .env-i və fayllarınızı dəyişmir. Açarlar ekrana çıxmır.

PASS=0; FAILN=0; WARNN=0; SUMMARY=""
ok()   { printf '  \033[32mOK  \033[0m %s\n' "$1"; PASS=$((PASS+1)); SUMMARY="$SUMMARY $2:OK"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${3:-}" ] && printf '       \033[2m→ %s\033[0m\n' "$3"; FAILN=$((FAILN+1)); SUMMARY="$SUMMARY $2:FAIL"; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$1"; [ -n "${3:-}" ] && printf '       \033[2m→ %s\033[0m\n' "$3"; WARNN=$((WARNN+1)); SUMMARY="$SUMMARY $2:WARN"; }
section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
[ -z "$ROOT" ] && { echo "Bu qovluq git repo deyil. Əvvəlcə: cd ~/projects/alert2case"; exit 1; }
cd "$ROOT" || exit 1
PY=.venv/bin/python
DC="docker compose"
psql_q() { $DC exec -T postgres psql -U soc -d alert2case -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
rcli()   { $DC exec -T redis redis-cli "$@" 2>/dev/null; }

WHO=$(git config user.name 2>/dev/null)
printf '\033[1malert2case · Phase 3 çıxış yoxlaması\033[0m\n'
printf 'Üzv: %s · Tarix: %s\n' "${WHO:-?}" "$(date '+%Y-%m-%d %H:%M')"

# =================================================================== 1. Repo və Python
section "1 · Repo və Python"
BR=$(git branch --show-current)
git fetch -q origin main 2>/dev/null
BEHIND=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo "?")
if [ "$BR" = "main" ] && [ "$BEHIND" = "0" ]; then ok "main branch-dasınız, GitHub ilə eynidir" main
elif [ "$BR" != "main" ]; then bad "Hazırda '$BR' branch-dasınız" main "git switch main && git pull"
else bad "main GitHub-dan $BEHIND commit geridədir" main "git pull"; fi

if $PY -c 'import tenacity, yaml, fakeredis, lupa' >/dev/null 2>&1; then
  ok "Phase 3 paketləri .venv-dədir (tenacity, pyyaml, fakeredis[lua])" pkgs
else bad "Phase 3 paketləri çatışmır" pkgs "uv pip install -r requirements.txt -r requirements-dev.txt"; fi

# =================================================================== 2. .env
section "2 · .env: intel açarları"
if [ -f .env ]; then
  EMPTY=""
  for K in VT_API_KEY ABUSEIPDB_API_KEY OTX_API_KEY; do
    V=$(grep -E "^$K=" .env | tail -1 | cut -d= -f2-)
    [ -z "$V" ] && EMPTY="$EMPTY $K"
  done
  if [ -z "$EMPTY" ]; then ok "3 intel açarı doludur (dəyərlər göstərilmir)" keys
  else bad "Boş və ya yoxdur:$EMPTY" keys "Runbook 1.5: açarı al və .env-ə yaz"; fi
  DUP=$(grep -oE '^[A-Z_]+=' .env | sort | uniq -d | tr -d '=' | tr '\n' ' ')
  [ -z "$DUP" ] && ok "Təkrar açar yoxdur" envdup || bad "Təkrar açarlar: $DUP" envdup "Hər açar .env-də bir dəfə olmalıdır"
else bad ".env faylı yoxdur" keys "cp .env.example .env və dəyərləri doldurun"; fi

# =================================================================== 3. Servislər
section "3 · Servislər"
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
  if $DC exec -T worker python -c 'import tenacity, yaml' >/dev/null 2>&1; then ok "Worker image-ində tenacity və pyyaml var" image
  else bad "Worker image-i köhnədir (tenacity yoxdur)" image "docker compose up -d --build api worker"; fi
  VTURL=$($DC exec -T worker printenv VT_BASE_URL 2>/dev/null | tr -d '[:space:]')
  case "$VTURL" in
    *toxiproxy*|*127.0.0.1*) bad "Worker test rejimindədir (VT_BASE_URL=$VTURL)" mode "docker compose up -d --force-recreate worker" ;;
    *) ok "Worker normal rejimdədir (real intel ünvanları)" mode ;;
  esac
fi

# =================================================================== 4. Provider-lər və cache (3.1, 3.3, 3.4)
section "4 · Provider-lər real açarla (3.1) və cache (3.3)"
INTEL=$($DC exec -T worker python - <<'PYEOF' 2>/dev/null
import asyncio
import time

from app.enrich import ratelimit
from app.enrich.providers import OTX, AbuseIPDB, VirusTotal
from app.enrich.service import lookup_one

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


async def one(name, coro):
    try:
        r = await coro
        return f"{name}={r.status}:{r.verdict}"
    except Exception as e:  # noqa: BLE001
        return f"{name}=exc:{type(e).__name__}"


async def main():
    out = []
    if await ratelimit.acquire("virustotal", 4, 500, 1, max_wait=60):
        out.append(await one("vt", VirusTotal().lookup("hash_sha256", EICAR)))
    else:
        out.append("vt=rate_limited:none")
    out.append(await one("ab", AbuseIPDB().lookup("ip", "8.8.8.8")))
    out.append(await one("otx", OTX().lookup("ip", "8.8.8.8")))
    p = OTX()
    await lookup_one(p, "ip", "1.1.1.1")
    t0 = time.perf_counter()
    r = await lookup_one(p, "ip", "1.1.1.1")
    out.append(f"cache={r.cached}:{(time.perf_counter() - t0) * 1000:.1f}")
    print(" ".join(out))


asyncio.run(main())
PYEOF
)
VT=$(echo "$INTEL" | grep -oE 'vt=[^ ]+' | cut -d= -f2)
AB=$(echo "$INTEL" | grep -oE 'ab=[^ ]+' | cut -d= -f2)
OTXR=$(echo "$INTEL" | grep -oE 'otx=[^ ]+' | cut -d= -f2)
CACHE=$(echo "$INTEL" | grep -oE 'cache=[^ ]+' | cut -d= -f2)
[ "$VT" = "ok:malicious" ] && ok "VirusTotal: EICAR → ok, malicious" vt || bad "VirusTotal: ${VT:-cavab yoxdur}" vt "VT_API_KEY-i yoxlayın; auth_error = açar səhvdir"
case "$AB" in ok:*) ok "AbuseIPDB: 8.8.8.8 → ${AB/:/, }" ab ;; *) bad "AbuseIPDB: ${AB:-cavab yoxdur}" ab "ABUSEIPDB_API_KEY-i yoxlayın" ;; esac
case "$OTXR" in ok:*) ok "OTX: 8.8.8.8 → ${OTXR/:/, }" otx ;; *) bad "OTX: ${OTXR:-cavab yoxdur}" otx "OTX_API_KEY-i yoxlayın" ;; esac
CMS=${CACHE#*:}
if [ "${CACHE%%:*}" = "True" ] && awk -v m="$CMS" 'BEGIN{exit !(m+0 < 5)}'; then ok "Cache: ikinci sorğu $CMS ms (< 5 ms)" cache
else bad "Cache: ${CACHE:-yoxlanmadı}" cache "docker compose logs worker --tail 20"; fi
QUOTA=$(rcli GET "quota:virustotal:$(date -u +%F)" | tr -d '[:space:]"')
[ -n "$QUOTA" ] && ok "VT gündəlik sayğacı işləyir: $QUOTA / 500" quota || warn "VT sayğacı tapılmadı" quota

# =================================================================== 5. Pipeline (3.6)
section "5 · Pipeline enrich edir (3.6)"
SIM=$($PY tools/simulator.py --only HASH-01 --rate 1 2>&1 | tail -1)
if echo "$SIM" | grep -q "Göndərildi: 1, gözlənilən cavab (202): 1"; then ok "Simulyator: HASH-01 → 202" simulate
else bad "Simulyator: ${SIM:-cavab yoxdur}" simulate "docker compose logs api --tail 20"; fi
ROW=""
for _ in $(seq 1 45); do
  ROW=$($DC exec -T postgres psql -U soc -d alert2case -tAc \
    "select doc->'enrichment'->>'status' || ':' || (doc->'enrichment'->>'verdict') from alerts
     where source_ref='HASH-01' and status='enriched' and last_seen > now() - interval '3 minutes'
       and doc->'enrichment'->>'status' in ('ok','partial')
     order by last_seen desc limit 1" 2>/dev/null | tr -d '[:space:]')
  [ -n "$ROW" ] && break; sleep 2
done
case "$ROW" in
  ok:malicious) ok "HASH-01 enrich olunub: ok, malicious (expected.csv: malicious)" enrich ;;
  ok:*|partial:*) warn "HASH-01 enrich olunub, amma ${ROW/:/, }" enrich "partial normaldır: 15 dəqiqəlik yenidən enrichment tamamlayacaq" ;;
  *) bad "HASH-01 3 dəqiqə ərzində enrich olunmadı" enrich "docker compose logs worker --tail 30" ;;
esac
PENDING=$(psql_q "select count(*) from alerts where status='enriched' and doc->'enrichment'->>'status'='pending'")
[ "$PENDING" = "0" ] && ok "'pending' qalan enriched alert yoxdur" pending || bad "pending: $PENDING" pending
REEN=$(psql_q "select count(*) from audit_log where event='re_enriched'")
if [ "${REEN:-0}" -gt 0 ] 2>/dev/null; then ok "Yenidən enrichment işləyir: $REEN re_enriched sətri" reenrich
else warn "re_enriched sətri hələ yoxdur" reenrich "Worker 15 dəqiqədən az işləyirsə normaldır; sonra skripti təkrar işlədin"; fi
XP=$(rcli XPENDING alerts.in pipeline | head -1 | tr -d '[:space:]')
[ "$XP" = "0" ] && ok "Redis-də ACK gözləyən mesaj yoxdur" xpending || warn "ACK gözləyən mesaj: ${XP:-?}" xpending "Bir az gözləyib təkrar işlədin"

# =================================================================== 6. Rate limit (3.4)
section "6 · Rate limit (3.4)"
N429=$($DC logs worker --since 24h 2>/dev/null | grep -c "HTTP 429")
[ "$N429" = "0" ] && ok "Son 24 saatda worker log-unda HTTP 429 yoxdur" r429 || warn "Son 24 saatda $N429 dəfə HTTP 429" r429 "Başqa proses eyni açarla sorğu atır?"

# =================================================================== 7. Testlər və konfiqurasiya (3.2, 3.5, 3.7)
section "7 · Testlər və konfiqurasiya"
MISSING=""
for F in tests/unit/test_breaker.py tests/unit/test_cache.py tests/unit/test_ratelimit.py \
         tests/unit/test_aggregate.py tests/unit/test_service.py rules/weights.yaml \
         docker-compose.test.yml wiremock/mappings/intel.json docs/resilience.md; do
  [ -f "$F" ] || MISSING="$MISSING $F"
done
[ -z "$MISSING" ] && ok "Phase 3 faylları yerindədir (testlər, weights.yaml, test mühiti, resilience.md)" files || bad "Yoxdur:$MISSING" files "git pull"
WV=$($PY -c 'import yaml;print(yaml.safe_load(open("rules/weights.yaml"))["version"])' 2>/dev/null)
[ -n "$WV" ] && ok "weights.yaml oxunur (version $WV)" weights || bad "weights.yaml oxunmur" weights
TEST=$($PY -m pytest tests/unit -p no:cacheprovider --cov --cov-fail-under=85 2>&1 | tail -3)
if echo "$TEST" | grep -qE '^[0-9]+ passed' && ! echo "$TEST" | grep -q failed && echo "$TEST" | grep -q "coverage of 85% reached"; then
  ok "pytest: $(echo "$TEST" | grep -oE '^[0-9]+ passed'), coverage ≥ 85%" tests
else bad "pytest: $(echo "$TEST" | tail -1)" tests "pytest tests/unit ilə baxın"; fi
TB=$($DC logs worker --since 10m 2>/dev/null | grep -c Traceback)
[ "$TB" = "0" ] && ok "Worker log-unda son 10 dəqiqədə traceback yoxdur" traceback || warn "Worker log-unda $TB traceback" traceback "docker compose logs worker --since 10m"

# =================================================================== Nəticə
printf '\n\033[1mNƏTİCƏ:\033[0m %d OK · %d FAIL · %d WARN\n' "$PASS" "$FAILN" "$WARNN"
if [ $FAILN -eq 0 ]; then printf '\033[32mPhase 3 bu kompüterdə tam işləyir.\033[0m\n'
else printf '\033[31mFAIL olan sətirlərin altındakı → göstərişə əməl edin.\033[0m\n'; fi
printf '\nQrupa göndərmək üçün:\nP3EXIT %s |%s\n' "${WHO:-?}" "$SUMMARY"
[ $FAILN -eq 0 ]
