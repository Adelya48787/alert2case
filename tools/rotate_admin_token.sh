#!/usr/bin/env bash
# alert2case · 6.6b secret rotasiya məşqi: ADMIN_TOKEN yenisi ilə əvəz olunur və sistemin işlədiyi yoxlanılır.
#
#   tools/rotate_admin_token.sh
#
# 1. .env-in ehtiyat nüsxəsi (.env.rotate.bak, gitignore-dadır, yalnız sənə oxunaqlı)
# 2. yeni token (openssl rand -hex 24) .env-ə yazılır
# 3. api və worker yeni token ilə yenidən yaradılır
# 4. yoxlama: köhnə token → 403, yeni token → 200, /health → 200, worker işləyir
# 5. uğursuz olsa: .env ehtiyatdan qaytarılır. Uğurlu olsa: ehtiyat silinir
# Token-lər heç vaxt ekrana çıxmır. n8n credential-ı ayrıca yenilənir (sonda göstərilir).
set -u
set +x # trace açıq olsa token-lər loga düşərdi
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "Repo qovluğunda deyilsiniz"; exit 1; }
cd "$ROOT" || exit 1
API=http://localhost:8000
BAK=.env.rotate.bak
ok() { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=1; }
FAIL=0
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

command -v openssl >/dev/null || { echo "openssl yoxdur: sudo apt install openssl"; exit 1; }
[ -f .env ] || { echo ".env yoxdur"; exit 1; }
OLD=$(grep -E '^ADMIN_TOKEN=' .env | tail -1 | cut -d= -f2-)
[ -n "$OLD" ] || { echo ".env-də ADMIN_TOKEN boşdur"; exit 1; }
[ "$(code "$API/health")" = "200" ] || { echo "API cavab vermir: make up"; exit 1; }
[ "$(code -H "X-Admin-Token: $OLD" "$API/dlq")" = "200" ] || { echo "Köhnə token artıq işləmir: API .env ilə uyğun deyil, əvvəlcə: docker compose up -d --force-recreate api worker"; exit 1; }

recreate() {
  docker compose up -d --force-recreate --no-deps api worker >/dev/null 2>&1
  for _ in $(seq 1 30); do [ "$(code "$API/health")" = "200" ] && return 0; sleep 2; done
  return 1
}

printf '\n\033[1m▸ 1/4 Ehtiyat nüsxə\033[0m\n'
cp .env "$BAK" && chmod 600 "$BAK" && ok "$BAK (yalnız sənə oxunaqlı, gitignore-dadır)"

printf '\n\033[1m▸ 2/4 Yeni token .env-ə yazılır\033[0m\n'
NEW=$(openssl rand -hex 24)
NEW="$NEW" python3 - <<'EOF'
import os, pathlib
p = pathlib.Path(".env")
lines = p.read_text(encoding="utf-8").splitlines()
lines = [f"ADMIN_TOKEN={os.environ['NEW']}" if l.startswith("ADMIN_TOKEN=") else l for l in lines]
p.write_text("\n".join(lines) + "\n", encoding="utf-8")
EOF
[ "$(grep -E '^ADMIN_TOKEN=' .env | cut -d= -f2-)" = "$NEW" ] && ok "ADMIN_TOKEN dəyişdi (48 simvol, dəyər göstərilmir)" || { bad ".env yazılmadı"; cp "$BAK" .env; exit 1; }

printf '\n\033[1m▸ 3/4 api və worker yeni token ilə yenidən yaradılır\033[0m\n'
T0=$(date +%s)
if recreate; then ok "api hazırdır ($(($(date +%s) - T0)) s)"; else bad "api qalxmadı"; fi

printf '\n\033[1m▸ 4/4 Yoxlama\033[0m\n'
C_OLD=$(code -H "X-Admin-Token: $OLD" "$API/dlq")
C_NEW=$(code -H "X-Admin-Token: $NEW" "$API/dlq")
C_HEALTH=$(code "$API/health")
W=$(docker compose ps --format '{{.State}}' worker 2>/dev/null)
[ "$C_OLD" = "403" ] && ok "köhnə token rədd edilir (403)" || bad "köhnə token: $C_OLD (gözlənilən 403)"
[ "$C_NEW" = "200" ] && ok "yeni token qəbul edilir (200)" || bad "yeni token: $C_NEW (gözlənilən 200)"
[ "$C_HEALTH" = "200" ] && ok "/health 200" || bad "/health: $C_HEALTH"
[ "$W" = "running" ] && ok "worker işləyir" || bad "worker: ${W:-yoxdur}"

if [ $FAIL -ne 0 ]; then
  printf '\n\033[31mUğursuz: .env ehtiyatdan qaytarılır\033[0m\n'
  cp "$BAK" .env && recreate && echo "Köhnə vəziyyət bərpa olundu"
  rm -f "$BAK"
  echo "ROTATE FAIL"
  exit 1
fi
rm -f "$BAK"
unset OLD NEW
cat <<'EOF'

Ehtiyat nüsxə silindi. Əl ilə qalan addım: n8n də admin token işlədir (/stage çağırışları).
  python tools/n8n_credentials.py      # n8n/credentials.local.json yeni token ilə yaranır
  sonra n8n-də "alert2case admin token" credential-ını yenilə (4.6b, addım 3) və faylı sil
EOF
echo "ROTATE OK · ADMIN_TOKEN · köhnə 403 · yeni 200"
