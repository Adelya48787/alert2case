#!/usr/bin/env bash
# alert2case · Phase 1 "Hamı" yoxlaması
# Hər üzv öz kompüterində repo qovluğunda işlədir:
#   tools/phase1_check.sh            # tam yoxlama (intel API-lərə 3 sorğu göndərir)
#   tools/phase1_check.sh --offline  # intel API sorğuları olmadan
# Açarların və parolların özü heç vaxt ekrana çıxmır.

OFFLINE=0
[ "${1:-}" = "--offline" ] && OFFLINE=1

PASS=0; FAILN=0; WARNN=0; SUMMARY=""
ok()   { printf '  \033[32mOK  \033[0m %s\n' "$1"; PASS=$((PASS+1)); SUMMARY="$SUMMARY $2:OK"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${3:-}" ] && printf '       \033[2m→ %s\033[0m\n' "$3"; FAILN=$((FAILN+1)); SUMMARY="$SUMMARY $2:FAIL"; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$1"; [ -n "${3:-}" ] && printf '       \033[2m→ %s\033[0m\n' "$3"; WARNN=$((WARNN+1)); SUMMARY="$SUMMARY $2:WARN"; }
section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$ROOT" ]; then
  echo "Bu qovluq git repo deyil. Əvvəlcə: cd ~/projects/alert2case"; exit 1
fi
cd "$ROOT" || exit 1

WHO=$(git config user.name 2>/dev/null)
printf '\033[1malert2case · Phase 1 yoxlaması\033[0m\n'
printf 'Üzv: %s · Tarix: %s\n' "${WHO:-?}" "$(date '+%Y-%m-%d %H:%M')"

# ------------------------------------------------------------------ Git və repo
section "1.1 · Repo və Git"
if git remote get-url origin 2>/dev/null | grep -q "Adelya48787/alert2case"; then
  ok "Ortaq repo-dasınız (origin = Adelya48787/alert2case)" repo
else
  bad "origin ortaq repo deyil: $(git remote get-url origin 2>/dev/null)" repo "Ortaq repo-nu klon edin: git clone git@github.com:Adelya48787/alert2case.git"
fi

BR=$(git branch --show-current)
git fetch -q origin main 2>/dev/null
BEHIND=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo "?")
if [ "$BR" = "main" ] && [ "$BEHIND" = "0" ]; then
  ok "main branch-dasınız və GitHub ilə eynidir" main
elif [ "$BR" != "main" ]; then
  warn "Hazırda '$BR' branch-dasınız" main "Yoxlama üçün: git switch main && git pull"
else
  bad "main GitHub-dan $BEHIND commit geridədir" main "git pull"
fi

if [ -x .git/hooks/pre-commit ] && grep -q "pre-commit" .git/hooks/pre-commit 2>/dev/null; then
  ok "pre-commit hook qurulub (gitleaks hər commit-də işləyir)" hook
else
  bad "pre-commit hook yoxdur" hook "source .venv/bin/activate && pre-commit install"
fi

if git ls-files --error-unmatch .env >/dev/null 2>&1; then
  bad ".env repoda izlənir! Açarlar GitHub-a gedə bilər" envtracked "Dərhal Adiləyə yazın"
else
  ok ".env repoya düşmür (.gitignore işləyir)" envtracked
fi

# ------------------------------------------------------------------ Python mühiti
section "1.1 · Python mühiti"
if [ -x .venv/bin/python ]; then
  PYV=$(.venv/bin/python -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)
  if [ "$PYV" = "3.12" ]; then ok ".venv var, Python $PYV" venv
  else bad ".venv Python $PYV ilə yaradılıb, 3.12 lazımdır" venv "rm -rf .venv && uv venv --python 3.12"; fi
  if .venv/bin/python -c 'import pytest, dotenv' >/dev/null 2>&1 && [ -x .venv/bin/ruff ] && [ -x .venv/bin/pre-commit ]; then
    ok "requirements-dev paketləri quraşdırılıb" pkgs
  else
    bad "Bəzi paketlər yoxdur" pkgs "source .venv/bin/activate && uv pip install -r requirements-dev.txt"
  fi
else
  bad ".venv yoxdur" venv "uv venv --python 3.12 && source .venv/bin/activate && uv pip install -r requirements-dev.txt"
fi

# ------------------------------------------------------------------ .env
section "1.1c / 1.2a · .env"
if [ -f .env ]; then
  MISSING=$(comm -23 <(grep -o '^[A-Z_]*=' .env.example | sort) <(grep -o '^[A-Z_]*=' .env | sort) | tr -d '=' | tr '\n' ' ')
  if [ -z "$MISSING" ]; then ok ".env-də .env.example-dakı bütün dəyişənlər var" envkeys
  else bad ".env-də çatışmır: $MISSING" envkeys "Dəyərləri .env.example-dan və ya qrupdakı mesajdan götürün"; fi
  EMPTY=""
  for k in POSTGRES_PASSWORD N8N_ENCRYPTION_KEY WEBHOOK_HMAC_SECRET THEHIVE_SECRET; do
    grep -qE "^$k=.+" .env || EMPTY="$EMPTY $k"
  done
  if [ -z "$EMPTY" ]; then ok "Daxili secret-lər doldurulub" secrets
  else bad "Boş daxili secret-lər:$EMPTY" secrets "1.1c · 'Öz .env faylını yarat' addımındakı openssl əmri"; fi
else
  bad ".env faylı yoxdur" envkeys "cp .env.example .env, sonra 1.1c · 'Öz .env faylını yarat'"
fi

# ------------------------------------------------------------------ Intel API açarları
section "1.5 · Intel API açarları"
if [ -f .env ]; then
  set -a; . ./.env 2>/dev/null; set +a
  LEN_OK=1; MSG=""
  [ "${#VT_API_KEY}" -eq 64 ] || { LEN_OK=0; MSG="$MSG VT(${#VT_API_KEY})"; }
  [ "${#ABUSEIPDB_API_KEY}" -eq 80 ] || { LEN_OK=0; MSG="$MSG AbuseIPDB(${#ABUSEIPDB_API_KEY})"; }
  [ "${#OTX_API_KEY}" -eq 64 ] || { LEN_OK=0; MSG="$MSG OTX(${#OTX_API_KEY})"; }
  if [ $LEN_OK -eq 1 ]; then ok "Üç açar yazılıb, uzunluqları düzgündür (64 · 80 · 64)" keys
  else bad "Açar boşdur və ya uzunluğu səhvdir:$MSG" keys "code .env, sonra açarı saytdan yenidən kopyalayın"; fi

  if [ $OFFLINE -eq 1 ]; then
    warn "API sorğuları keçildi (--offline)" apis
  elif [ $LEN_OK -eq 1 ]; then
    VT=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -H "x-apikey: $VT_API_KEY" https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8)
    AB=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=8.8.8.8" -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: application/json")
    OX=$(curl -s -m 20 -o /dev/null -w '%{http_code}' -H "X-OTX-API-KEY: $OTX_API_KEY" https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general)
    if [ "$VT$AB$OX" = "200200200" ]; then ok "VirusTotal, AbuseIPDB, OTX: hamısı 200" apis
    else bad "API cavabları: VirusTotal $VT · AbuseIPDB $AB · OTX $OX" apis "401/403 = açar səhvdir, 429 = limit, bir dəqiqə gözləyin"; fi
  fi
fi

# ------------------------------------------------------------------ Docker servisləri
section "1.2a · Servislər"
if ! docker info >/dev/null 2>&1; then
  bad "Docker işləmir" docker "Docker Desktop-u açın"
else
  if docker compose config --quiet >/dev/null 2>&1; then ok "docker-compose.yml .env ilə oxunur (config OK)" compose
  else bad "docker compose config xəta verir" compose "docker compose config ilə xətanı görün, çox vaxt .env-də dəyişən çatışmır"; fi
  for s in postgres redis; do
    st=$(docker inspect -f '{{.State.Health.Status}}' "alert2case-$s-1" 2>/dev/null)
    if [ "$st" = "healthy" ]; then ok "$s: healthy" "$s"
    else bad "$s: ${st:-qalxmayıb}" "$s" "make up, sonra 1 dəqiqə gözləyin"; fi
  done
  N8N=$(curl -s -m 5 -o /dev/null -w '%{http_code}' http://localhost:5678)
  MP=$(curl -s -m 5 -o /dev/null -w '%{http_code}' http://localhost:8025)
  if [ "$N8N" = "200" ]; then ok "n8n: 200" n8n; else bad "n8n: $N8N" n8n "make up"; fi
  if [ "$MP" = "200" ]; then ok "mailpit: 200" mailpit; else bad "mailpit: $MP" mailpit "make up"; fi
  if [ "$N8N" = "200" ]; then
    SETUP=$(curl -s -m 5 http://localhost:5678/rest/settings | grep -o '"showSetupOnFirstLoad":[a-z]*' | head -1)
    case "$SETUP" in
      *false) ok "n8n owner hesabı yaradılıb" n8nowner ;;
      *true)  bad "n8n owner hesabı yoxdur" n8nowner "Brauzerdə http://localhost:5678 açın və hesab yaradın" ;;
      *)      warn "n8n owner hesabını avtomatik yoxlamaq olmadı" n8nowner "http://localhost:5678 açılanda giriş səhifəsi görünürsə, hesab var" ;;
    esac
  fi
fi

# ------------------------------------------------------------------ Baseline
section "1.3a · Baseline materialları"
CARDS=$(ls docs/baseline/alerts/*.md 2>/dev/null | wc -l | tr -d ' ')
if [ "$CARDS" = "12" ]; then ok "12 alert kartı var" cards; else bad "Kart sayı: $CARDS (12 olmalıdır)" cards "git switch main && git pull"; fi
if [ -f tools/timer.py ]; then ok "tools/timer.py var" timer; else bad "tools/timer.py yoxdur" timer "git pull"; fi
if [ -f docs/baseline/answers.csv ]; then
  warn "Kompüterinizdə docs/baseline/answers.csv var" answers "Analitiksinizsə, faylı açmayın və Adiləyə yazın"
fi

# ------------------------------------------------------------------ Nəticə
printf '\n\033[1mNƏTİCƏ:\033[0m %d OK · %d FAIL · %d WARN\n' "$PASS" "$FAILN" "$WARNN"
if [ $FAILN -eq 0 ]; then printf '\033[32mPhase 1-in bütün "Hamı" bəndləri sizdə hazırdır.\033[0m\n'
else printf '\033[31mFAIL olan sətirlərin altındakı → göstərişə əməl edin və skripti yenidən işlədin.\033[0m\n'; fi
printf '\nQrupa göndərmək üçün bu sətri kopyalayın:\n'
printf 'P1CHECK %s |%s\n' "${WHO:-?}" "$SUMMARY"
[ $FAILN -eq 0 ]
