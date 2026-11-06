#!/usr/bin/env bash
# alert2case · 6.2 avtomatik ölçmə: bir ssenarini başdan sona aparır.
#   tools/measure_auto.sh cold     # boş cache, 10 s-də bir alert       (~10-12 dəq)
#   tools/measure_auto.sh warm     # cache dolu (cold-dan dərhal sonra)  (~7 dəq)
#   tools/measure_auto.sh burst    # boş cache, saniyədə 2 alert         (~12-15 dəq, VT limiti)
#   tools/measure_auto.sh chaos    # test steki: intel 3 s (±1 s) gecikmə ilə (~3 dəq)
#   tools/measure_auto.sh summary  # docs/measure/summary.md
# Dev rejimində işlədin (make down-prod). Lokal test məlumatını silir (make reset-data), repo fayllarına
# yalnız docs/measure/auto_*.csv, mttr_*.md və summary.md yazır. Açarlar ekrana çıxmır.
set -u
SC=${1:-}
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "Repo qovluğunda deyilsiniz: cd ~/projects/alert2case"; exit 1; }
cd "$ROOT" || exit 1
PY=.venv/bin/python
DCT="docker compose -f docker-compose.yml -f docker-compose.test.yml"
step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }

case "$SC" in
  cold|warm|burst|chaos) ;;
  summary) exec $PY -m tools.compute_mttr summary ;;
  *) echo "İstifadə: tools/measure_auto.sh cold|warm|burst|chaos|summary"; exit 1 ;;
esac

docker info >/dev/null 2>&1 || { echo "Docker işləmir"; exit 1; }
IMG=$(docker inspect "$(docker compose ps -q worker 2>/dev/null)" --format '{{.Config.Image}}' 2>/dev/null)
case "$IMG" in alert2case:*) echo "Worker prod image ilədir ($IMG). Əvvəlcə: make down-prod"; exit 1 ;; esac

cleanup_chaos() {
  curl -s -XDELETE localhost:8474/proxies/intel >/dev/null 2>&1
  $DCT rm -sf wiremock toxiproxy >/dev/null 2>&1
  docker compose up -d --force-recreate worker >/dev/null 2>&1
  echo "Chaos təmizləndi: worker real intel ünvanlarına qaytarıldı"
}

if [ "$SC" = "chaos" ]; then
  step "Test steki (WireMock + Toxiproxy) qaldırılır, worker test ünvanlarına keçir"
  trap cleanup_chaos EXIT
  $DCT up -d wiremock toxiproxy worker || exit 1
  for _ in $(seq 1 20); do curl -s localhost:8474/version >/dev/null 2>&1 && break; sleep 1; done
  curl -s -XDELETE localhost:8474/proxies/intel >/dev/null 2>&1
  curl -s -XPOST localhost:8474/proxies -d '{"name":"intel","listen":"0.0.0.0:8666","upstream":"wiremock:8080"}' >/dev/null || exit 1
  # 3 s gecikmə: timeout-dan (8 s) qısa, yəni sorğular uğurlu, amma yavaşdır
  curl -s -XPOST localhost:8474/proxies/intel/toxics \
    -d '{"name":"slow","type":"latency","attributes":{"latency":3000,"jitter":1000}}' >/dev/null || exit 1
  echo "Toxiproxy: intel → wiremock, 3000 ms ± 1000 ms gecikmə"
fi

if [ "$SC" = "warm" ]; then
  step "Alert, case, audit, korrelyasiya və bildiriş açarları silinir, intel cache qalır"
  make -s reset-keep-cache || exit 1
else
  step "Test məlumatı sıfırlanır (intel cache də silinir)"
  make -s reset-data || exit 1
fi
sleep 8

case "$SC" in
  cold|warm) RATE=0.1 ;;
  burst) RATE=2 ;;
  chaos) RATE=0.5 ;;
esac
step "36 alert göndərilir (saniyədə $RATE)"
$PY tools/simulator.py --rate "$RATE" --no-shuffle | tail -1

step "Emalın bitməsi gözlənilir və MTTR hesablanır"
$PY -m tools.compute_mttr --label "$SC"
RC=$?
[ $RC -eq 0 ] && printf '\n\033[32m%s ssenarisi bitdi.\033[0m Nəticə: docs/measure/mttr_%s.md\n' "$SC" "$SC" \
  || printf '\n\033[31m%s: hərəkətə çatmayan alert var (çıxış kodu %s)\033[0m\n' "$SC" "$RC"
exit $RC
