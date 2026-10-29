#!/usr/bin/env bash
# alert2case · Phase 1 çıxış yoxlaması
# Hər üzv öz kompüterində, repo qovluğunda, main branch-da işlədir:
#   tools/phase1_exit.sh            # tam yoxlama (intel API-lərə 3 sorğu, GitHub CI sorğusu)
#   tools/phase1_exit.sh --offline  # internet sorğuları olmadan
# Skript heç bir faylı dəyişmir. Açarlar və parollar ekrana çıxmır.

OFFLINE=0
[ "${1:-}" = "--offline" ] && OFFLINE=1
REPO_SLUG="Adelya48787/alert2case"

PASS=0; FAILN=0; WARNN=0; SUMMARY=""
ok()   { printf '  \033[32mOK  \033[0m %s\n' "$1"; PASS=$((PASS+1)); SUMMARY="$SUMMARY $2:OK"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${3:-}" ] && printf '       \033[2m→ %s\033[0m\n' "$3"; FAILN=$((FAILN+1)); SUMMARY="$SUMMARY $2:FAIL"; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$1"; [ -n "${3:-}" ] && printf '       \033[2m→ %s\033[0m\n' "$3"; WARNN=$((WARNN+1)); SUMMARY="$SUMMARY $2:WARN"; }
section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
has() { [ -f "$1" ] && [ -s "$1" ]; }

ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
[ -z "$ROOT" ] && { echo "Bu qovluq git repo deyil. Əvvəlcə: cd ~/projects/alert2case"; exit 1; }
cd "$ROOT" || exit 1
PY=.venv/bin/python

WHO=$(git config user.name 2>/dev/null)
printf '\033[1malert2case · Phase 1 çıxış yoxlaması\033[0m\n'
printf 'Üzv: %s · Tarix: %s\n' "${WHO:-?}" "$(date '+%Y-%m-%d %H:%M')"

# =================================================================== 1. Mühit (hamı)
section "1.1 · Repo, Git, Python"
if git remote get-url origin 2>/dev/null | grep -q "$REPO_SLUG"; then ok "origin = $REPO_SLUG" repo
else bad "origin ortaq repo deyil" repo "git clone git@github.com:$REPO_SLUG.git"; fi

BR=$(git branch --show-current)
git fetch -q origin main 2>/dev/null
BEHIND=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo "?")
if [ "$BR" = "main" ] && [ "$BEHIND" = "0" ]; then ok "main branch-dasınız, GitHub ilə eynidir" main
elif [ "$BR" != "main" ]; then bad "Hazırda '$BR' branch-dasınız" main "git switch main && git pull, sonra skripti yenidən işlədin"
else bad "main GitHub-dan $BEHIND commit geridədir" main "git pull"; fi

if [ -z "$(git status --porcelain --untracked-files=no)" ]; then ok "İzlənən fayllarda commit olunmamış dəyişiklik yoxdur" clean
else warn "Commit olunmamış dəyişikliklər var" clean "git status ilə baxın"; fi

if [ -x .git/hooks/pre-commit ] && grep -q "pre-commit" .git/hooks/pre-commit; then ok "pre-commit hook qurulub" hook
else bad "pre-commit hook yoxdur" hook "source .venv/bin/activate && pre-commit install"; fi

if git ls-files --error-unmatch .env >/dev/null 2>&1; then bad ".env repoda izlənir!" envtracked "Dərhal Team Lead-ə yazın"
else ok ".env repoya düşmür" envtracked; fi

if [ -x "$PY" ] && [ "$($PY -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)" = "3.12" ]; then ok ".venv Python 3.12" venv
else bad ".venv yoxdur və ya Python 3.12 deyil" venv "uv venv --python 3.12 && uv pip install -r requirements-dev.txt"; fi

if $PY -c 'import pytest, dotenv, pandas, matplotlib, tabulate' >/dev/null 2>&1 && [ -x .venv/bin/ruff ] && [ -x .venv/bin/pre-commit ]; then
  ok "requirements-dev paketləri tamdır (pandas, matplotlib daxil)" pkgs
else bad "Bəzi paketlər çatışmır" pkgs "source .venv/bin/activate && uv pip install -r requirements-dev.txt"; fi

# =================================================================== 2. .env və açarlar
section "1.1c / 1.5 · .env və API açarları"
if [ -f .env ]; then
  MISSING=$(comm -23 <(grep -o '^[A-Z_]*=' .env.example | sort) <(grep -o '^[A-Z_]*=' .env | sort) | tr -d '=' | tr '\n' ' ')
  if [ -z "$MISSING" ]; then ok ".env-də bütün dəyişənlər var" envkeys
  else bad ".env-də çatışmır: $MISSING" envkeys "Dəyərləri .env.example-dan əlavə edin"; fi
  EMPTY=""
  for k in POSTGRES_PASSWORD N8N_ENCRYPTION_KEY WEBHOOK_HMAC_SECRET THEHIVE_SECRET; do grep -qE "^$k=.+" .env || EMPTY="$EMPTY $k"; done
  if [ -z "$EMPTY" ]; then ok "Daxili secret-lər doldurulub" secrets
  else bad "Boş secret-lər:$EMPTY" secrets "openssl rand -hex 32"; fi

  set -a; . ./.env 2>/dev/null; set +a
  if [ "${#VT_API_KEY}" -eq 64 ] && [ "${#ABUSEIPDB_API_KEY}" -eq 80 ] && [ "${#OTX_API_KEY}" -eq 64 ]; then
    ok "3 intel açarı yazılıb (64 · 80 · 64)" keys
    if [ $OFFLINE -eq 1 ]; then warn "API sorğuları keçildi (--offline)" apis
    else
      VT=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -H "x-apikey: $VT_API_KEY" https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8)
      AB=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=8.8.8.8" -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: application/json")
      OX=$(curl -s -m 20 -o /dev/null -w '%{http_code}' -H "X-OTX-API-KEY: $OTX_API_KEY" https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general)
      if [ "$VT$AB$OX" = "200200200" ]; then ok "VirusTotal, AbuseIPDB, OTX: 200" apis
      else bad "API: VT $VT · AbuseIPDB $AB · OTX $OX" apis "401/403 = açar səhvdir, 429 = limit"; fi
    fi
  else bad "Intel açarları boşdur və ya uzunluğu səhvdir" keys "code .env"; fi
else bad ".env yoxdur" envkeys "cp .env.example .env"; fi

# =================================================================== 3. Secret qoruması (real sınaq)
section "1.1c · Saxta açarlı commit bloklanırmı?"
if [ -x .venv/bin/pre-commit ]; then
  T=$(mktemp -d)
  cp .gitleaks.toml .pre-commit-config.yaml "$T"/
  # Nəzarət: təmiz fayl keçməlidir (hook həqiqətən işləyir)
  CTRL=$(cd "$T" && git init -q && git config user.email t@t && git config user.name t \
    && echo "hello=world" > ok.txt && git add -A && "$ROOT/.venv/bin/pre-commit" run gitleaks 2>&1; echo "rc=$?")
  # Sınaq: saxta VT açarı bloklanmalıdır
  LEAK=$(cd "$T" && printf 'VT_API_KEY=%s\n' "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" > leak.env \
    && git add -A && "$ROOT/.venv/bin/pre-commit" run gitleaks 2>&1; echo "rc=$?")
  rm -rf "$T"
  if ! echo "$CTRL" | grep -q 'rc=0$'; then
    bad "gitleaks hook işə düşmədi (təmiz faylda da xəta verdi)" leakblock "İnternet lazımdır: pre-commit run gitleaks --all-files"
  elif echo "$LEAK" | grep -q 'rc=1$' && echo "$LEAK" | grep -qi 'leaks found'; then
    ok "gitleaks saxta VT açarını blokladı" leakblock
  else bad "Saxta açar bloklanmadı!" leakblock ".gitleaks.toml və pre-commit konfiqurasiyasını yoxlayın"; fi
else bad "pre-commit yoxdur, sınaq mümkün olmadı" leakblock "uv pip install -r requirements-dev.txt"; fi

if [ $OFFLINE -eq 0 ]; then
  CI=$(curl -s -m 15 "https://api.github.com/repos/$REPO_SLUG/commits/main/check-runs" | $PY -c '
import json,sys
try:
    d=json.load(sys.stdin); r=d.get("check_runs",[])
    c=[x.get("conclusion") for x in r]
    print("none" if not r else ("ok" if all(v=="success" for v in c) else "bad:"+",".join(f"{x[\"name\"]}={x.get(\"conclusion\")}" for x in r)))
except Exception: print("err")' 2>/dev/null)
  case "$CI" in
    ok)   ok "GitHub CI main-də yaşıldır" ci ;;
    none) warn "main üçün CI nəticəsi tapılmadı" ci "GitHub → Actions" ;;
    err|"") warn "GitHub API-yə çatmaq olmadı (limit və ya şəbəkə)" ci "Bir az sonra yenidən işlədin" ;;
    *)    bad "CI qırmızıdır: ${CI#bad:}" ci "GitHub → Actions" ;;
  esac
fi

# =================================================================== 4. Servislər
section "1.2a / 1.2b · Servislər"
if ! docker info >/dev/null 2>&1; then bad "Docker işləmir" docker "Docker Desktop-u açın"
else
  if docker compose config --quiet >/dev/null 2>&1; then ok "docker-compose.yml .env ilə oxunur" compose
  else bad "docker compose config xəta verir" compose ".env-də dəyişən çatışmır"; fi
  for s in postgres redis; do
    st=$(docker inspect -f '{{.State.Health.Status}}' "alert2case-$s-1" 2>/dev/null)
    if [ "$st" = "healthy" ]; then ok "$s: healthy" "$s"; else bad "$s: ${st:-qalxmayıb}" "$s" "make up"; fi
  done
  N8N=$(curl -s -m 5 -o /dev/null -w '%{http_code}' http://localhost:5678)
  if [ "$N8N" = "200" ]; then
    SETUP=$(curl -s -m 5 http://localhost:5678/rest/settings | grep -o '"showSetupOnFirstLoad":[a-z]*' | head -1)
    case "$SETUP" in *false) ok "n8n: 200, owner hesabı var" n8n ;; *true) bad "n8n owner hesabı yoxdur" n8n "http://localhost:5678" ;; *) warn "n8n: 200, owner yoxlanmadı" n8n ;; esac
  else bad "n8n: $N8N" n8n "make up"; fi
  MP=$(curl -s -m 5 -o /dev/null -w '%{http_code}' http://localhost:8025)
  if [ "$MP" = "200" ] && $PY -c 'import smtplib; smtplib.SMTP("localhost",1025,timeout=5).quit()' >/dev/null 2>&1; then ok "Mailpit: UI 200, SMTP 1025 açıqdır" mailpit
  else bad "Mailpit: UI $MP və ya SMTP 1025 bağlıdır" mailpit "make up"; fi

  if docker inspect alert2case-thehive-1 >/dev/null 2>&1 && [ "$(docker inspect -f '{{.State.Running}}' alert2case-thehive-1 2>/dev/null)" = "true" ]; then
    TH=$(curl -s -m 10 -o /dev/null -w '%{http_code}' http://localhost:9000/api/status)
    if [ "$TH" = "200" ]; then
      if [ -n "${THEHIVE_API_KEY:-}" ]; then
        TU=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $THEHIVE_API_KEY" http://localhost:9000/api/v1/user/current)
        if [ "$TU" = "200" ]; then ok "TheHive işləyir, service account açarı keçərlidir" thehive
        else bad "TheHive işləyir, amma THEHIVE_API_KEY qəbul olunmur ($TU)" thehive "Service account açarını .env-ə yazın"; fi
      else warn "TheHive işləyir, THEHIVE_API_KEY .env-də boşdur" thehive "Service account açarını .env-ə yazın"; fi
    else bad "TheHive container var, amma API cavab vermir ($TH)" thehive "docker compose logs thehive"; fi
  else warn "TheHive bu kompüterdə işləmir (bir maşında kifayətdir)" thehive "Lazımdırsa: make up-full"; fi
fi

# =================================================================== 5. Taskların nəticələri (main-də)
section "Taskların nəticələri repo-da"
F11=""; for f in pyproject.toml .editorconfig .gitattributes README.md requirements-dev.txt; do has "$f" || F11="$F11 $f"; done
[ -z "$F11" ] && ok "1.1b repo skeleti tamdır" t11b || bad "1.1b çatışmır:$F11" t11b

F11C=""; for f in .gitleaks.toml .pre-commit-config.yaml .github/workflows/ci.yml .env.example; do has "$f" || F11C="$F11C $f"; done
[ -z "$F11C" ] && ok "1.1c secret qoruması faylları var" t11c || bad "1.1c çatışmır:$F11C" t11c

if has docker-compose.yml && grep -q 'profiles: \["thehive"\]' docker-compose.yml && grep -q '^up-full:' Makefile; then ok "1.2a/1.2b compose: əsas servislər + TheHive profili" t12
else bad "1.2a/1.2b compose və ya Makefile natamamdır" t12; fi

CARDS=$(ls docs/baseline/alerts/*.md 2>/dev/null | wc -l | tr -d ' ')
[ "$CARDS" = "12" ] && has tools/timer.py && ok "1.3a 12 kart və timer" t13a_prep || bad "1.3a kartlar ($CARDS) və ya timer çatışmır" t13a_prep

if has docs/baseline/baseline_raw.csv && has docs/baseline/answers.csv; then
  R=$($PY - <<'EOF' 2>&1
import csv, pathlib
cards = sorted(p.stem for p in pathlib.Path("docs/baseline/alerts").glob("*.md"))
rows = list(csv.DictReader(open("docs/baseline/baseline_raw.csv", encoding="utf-8")))
ans = {r["alert_id"] for r in csv.DictReader(open("docs/baseline/answers.csv", encoding="utf-8"))}
errs = []
analysts = sorted({r["analyst"] for r in rows})
if len(analysts) < 2: errs.append(f"analitik sayı {len(analysts)}")
for a in analysts:
    mine = [r for r in rows if r["analyst"] == a]
    ids = sorted({r["alert_id"] for r in mine})
    if ids != cards: errs.append(f"{a}: alert ID-ləri kartlarla uyğun deyil")
    for i in ids:
        steps = [r["step"] for r in mine if r["alert_id"] == i]
        if sorted(steps) != [f"S{n}" for n in range(1, 9)]: errs.append(f"{a}/{i}: addımlar {steps}")
        s8 = [r for r in mine if r["alert_id"] == i and r["step"] == "S8"]
        if s8 and not (s8[0]["verdict"] and s8[0]["priority"]): errs.append(f"{a}/{i}: S8-də verdict/priority yoxdur")
    fast = [r for r in mine if r["step"] in ("S3", "S4", "S7") and float(r["duration_s"]) < 5 and "outlier" not in r["note"]]
    if fast: errs.append(f"{a}: {len(fast)} addım (S3/S4/S7) 5 saniyədən qısadır")
if sorted(ans) != cards: errs.append("answers.csv ID-ləri kartlarla uyğun deyil")
print("OK " + f"{len(rows)} sətir, {len(analysts)} analitik" if not errs else "ERR " + "; ".join(errs[:4]))
EOF
)
  case "$R" in OK*) ok "1.3a ölçmə məlumatı keçərlidir (${R#OK })" t13a ;; *) bad "1.3a ölçmə məlumatında problem: ${R#ERR }" t13a ;; esac
else bad "1.3a baseline_raw.csv və ya answers.csv main-də yoxdur" t13a "1.3a PR-ı merge olunmalıdır"; fi

if has tools/baseline_report.py && has docs/baseline/report_output.md && { has docs/baseline/README.md || has docs/baseline.md; } \
   && ! grep -q '__%' docs/baseline/README.md docs/baseline.md 2>/dev/null; then ok "1.3b analiz skripti, nəticə və README" t13b
else bad "1.3b tamamlanmayıb (skript, report_output.md və ya README-də boş yerlər)" t13b "PR #13"; fi

FP=""; for f in shuffle n8n python; do has "docs/poc/$f.md" || FP="$FP $f"; done
if [ -z "$FP" ] && has docs/adr/0001-platform-selection.md && grep -q 'Accepted' docs/adr/0001-platform-selection.md; then ok "1.4 üç PoC qeydi və ADR-0001 (Accepted)" t14
else bad "1.4 çatışmır:${FP} ADR-0001" t14; fi

FX=$(ls tests/fixtures/*/*.json 2>/dev/null | wc -l | tr -d ' ')
if has docs/intel-sources.md && [ "$FX" -ge 9 ]; then ok "1.5 intel-sources.md və $FX fixture" t15
else bad "1.5 intel-sources.md və ya fixture-lar ($FX) çatışmır" t15; fi

has docs/adr/0002-fn-risk-and-fallback.md && ok "1.6 ADR-0002" t16 || bad "1.6 ADR-0002 yoxdur" t16

if has docs/week1-report.md; then ok "1.7 docs/week1-report.md" t17
else bad "1.7 docs/week1-report.md yoxdur" t17 "Həftə-1 hesabatı merge olunmalıdır"; fi

# =================================================================== 6. Kod keyfiyyəti
section "Kod keyfiyyəti"
if [ -x .venv/bin/pre-commit ]; then
  # CI-dakı lint addımının eynisi (pre-commit --all-files), repo-nun surətində: sizin fayllarınız dəyişmir
  T=$(mktemp -d)
  git archive HEAD | tar -x -C "$T"
  LINT=$(cd "$T" && git init -q && git add -A >/dev/null 2>&1 && "$ROOT/.venv/bin/pre-commit" run --all-files 2>&1; echo "rc=$?")
  rm -rf "$T"
  if echo "$LINT" | grep -q 'rc=0$'; then ok "CI lint (pre-commit --all-files) keçir" lint
  else
    FAILED=$(echo "$LINT" | grep -E 'Failed$' | sed 's/\.\.\..*//' | tr '\n' ',' | sed 's/,$//')
    bad "CI lint keçmir: ${FAILED:-naməlum}" lint "pre-commit run --all-files ilə baxın"
  fi
fi
NX=$(git ls-files -s -- '*.md' '*.csv' '*.json' | awk '$1=="100755"{print $4}' | tr '\n' ' ')
[ -z "$NX" ] && ok "Sənəd faylları icra modunda deyil" modes || warn "İcra modunda sənəd faylları: $NX" modes "chmod -x ... və commit"

# =================================================================== Nəticə
printf '\n\033[1mNƏTİCƏ:\033[0m %d OK · %d FAIL · %d WARN\n' "$PASS" "$FAILN" "$WARNN"
if [ $FAILN -eq 0 ]; then printf '\033[32mPhase 1 bu kompüterdə tam işləyir.\033[0m\n'
else printf '\033[31mFAIL olan sətirlərin altındakı → göstərişə əməl edin.\033[0m\n'; fi
printf '\nQrupa göndərmək üçün:\nP1EXIT %s |%s\n' "${WHO:-?}" "$SUMMARY"
[ $FAILN -eq 0 ]
