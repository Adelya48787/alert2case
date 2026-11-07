#!/usr/bin/env bash
# alert2case · demo: VirusTotal-ı müvəqqəti "kəsmək" və geri qaytarmaq (6.8, chaos addımı).
#
#   tools/demo_chaos.sh off     # worker VT-yə çata bilmir (127.0.0.1:9), VT cache təmizlənir
#   tools/demo_chaos.sh on      # worker .env-dəki normal dəyərlərə qaytarılır
#
# .env-ə toxunmur: VT ünvanı müvəqqəti compose override faylı ilə dəyişir. Açarlar ekrana çıxmır.
set -u
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "Repo qovluğunda deyilsiniz"; exit 1; }
cd "$ROOT" || exit 1
OV=$(mktemp --suffix=.yml)
trap 'rm -f "$OV"' EXIT

case "${1:-}" in
  off)
    printf 'services:\n  worker:\n    environment:\n      VT_BASE_URL: "http://127.0.0.1:9"\n' >"$OV"
    docker compose -f docker-compose.yml -f "$OV" up -d --force-recreate --no-deps worker >/dev/null 2>&1 || exit 1
    # VT cache-i silinir: yoxsa əvvəlki cavab cache-dən gəlir və kəsilmə görünmür
    n=$(docker compose exec -T redis sh -c "redis-cli --scan --pattern 'intel:v1:virustotal:*' | xargs -r redis-cli DEL" | tr -d '[:space:]')
    echo "VT kəsildi: worker VT-yə çata bilmir. Silinən VT cache açarı: ${n:-0}"
    ;;
  on)
    docker compose up -d --force-recreate --no-deps worker >/dev/null 2>&1 || exit 1
    echo "VT bərpa olundu: worker .env-dəki dəyərlərlə işləyir"
    ;;
  *)
    echo "İstifadə: tools/demo_chaos.sh off|on"
    exit 1
    ;;
esac
