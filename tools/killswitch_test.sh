#!/usr/bin/env bash
# alert2case · kill switch testi (ADR-0002, ADR-0003): AUTO_CLOSE_ENABLED=false auto-close-u 1 dəqiqədə dayandırırmı?
#
#   tools/killswitch_test.sh            # ~12-15 dəq (VT limiti), dev stekdə (make up)
#
# 1. ON:  worker müvəqqəti AUTO_CLOSE_ENABLED=true, SHADOW_MODE=false ilə; 36 alert → bir neçəsi closed_auto olmalıdır
# 2. FLIP: AUTO_CLOSE_ENABLED=false; worker yeni dəyərlə işə düşənə qədər keçən vaxt ölçülür (hədd 60 s)
# 3. OFF: eyni 36 alert (intel cache dolu, qərarlar eyni) → closed_auto 0, "kill switch bağlıdır" səbəbi ilə case
# Sonda worker .env-dəki dəyərlərə qaytarılır (trap). .env-ə toxunmur. Lokal test məlumatını silir (make reset-data).
# Nəticə: docs/measure/killswitch.md. Açarlar ekrana çıxmır.
set -u
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "Repo qovluğunda deyilsiniz: cd ~/projects/alert2case"; exit 1; }
cd "$ROOT" || exit 1
PY=.venv/bin/python
OUT=docs/measure/killswitch.md
LIMIT_S=60
OV=$(mktemp --suffix=.yml)
step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }
ok() { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=1; }
FAIL=0
FLIP_S="—"
q() { docker compose exec -T postgres psql -U soc -d alert2case -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }
mode() { docker compose exec -T worker python -c 'from app.config import settings as s; print(s.auto_close_enabled, s.shadow_mode)' 2>/dev/null | tail -1; }

worker_with() { # $1 = AUTO_CLOSE_ENABLED, $2 = SHADOW_MODE
  printf 'services:\n  worker:\n    environment:\n      AUTO_CLOSE_ENABLED: "%s"\n      SHADOW_MODE: "%s"\n' "$1" "$2" >"$OV"
  docker compose -f docker-compose.yml -f "$OV" up -d --force-recreate --no-deps worker >/dev/null 2>&1
}

restore() {
  docker compose up -d --force-recreate --no-deps worker >/dev/null 2>&1
  rm -f "$OV"
  echo "Worker .env-dəki dəyərlərə qaytarıldı: $(mode)"
}

wait_done() { # bütün alert-lər act mərhələsinə çatana qədər (maks. 20 dəq)
  local n=0 done_=0
  for _ in $(seq 1 240); do
    n=$(q "select count(*) from alerts")
    done_=$(q "select count(distinct correlation_id) from audit_log where stage='act'")
    [ "${n:-0}" -ge 36 ] && [ "${done_:-0}" -ge "$n" ] && return 0
    sleep 5
  done
  echo "  20 dəqiqədə bitmədi: $done_/$n alert"
  return 1
}

docker info >/dev/null 2>&1 || { echo "Docker işləmir"; exit 1; }
IMG=$(docker inspect "$(docker compose ps -q worker 2>/dev/null)" --format '{{.Config.Image}}' 2>/dev/null)
case "$IMG" in alert2case:*) echo "Worker prod image ilədir ($IMG). Əvvəlcə: make down-prod"; exit 1 ;; esac
trap restore EXIT

# ---------------------------------------------------------------- 1. ON
step "1/3 ON: auto-close müvəqqəti açılır (yalnız bu test üçün, .env dəyişmir)"
make -s reset-data >/dev/null || exit 1
worker_with true false
sleep 8
M=$(mode)
[ "$M" = "True False" ] && ok "worker: AUTO_CLOSE_ENABLED=True, SHADOW_MODE=False" || { bad "worker rejimi gözlənilən deyil: $M"; exit 1; }
$PY tools/simulator.py --rate 0.1 --no-shuffle | tail -1
wait_done || exit 1
ON_CLOSED=$(q "select count(*) from alerts where status='closed_auto'")
ON_LIST=$(docker compose exec -T postgres psql -U soc -d alert2case -tAc \
  "select string_agg(source_ref, ',' order by source_ref) from alerts where status='closed_auto'" 2>/dev/null | tr -d '[:space:]')
if [ "${ON_CLOSED:-0}" -gt 0 ]; then
  ok "auto-close işləyir: $ON_CLOSED alert closed_auto ($ON_LIST)"
else
  bad "ON rejimində heç bir alert bağlanmadı: kill switch-i yoxlamaq olmur (intel bu dəfə heç nəyi 'clean' saymadı). Testi təkrarlayın"
  exit 1
fi

# ---------------------------------------------------------------- 2. FLIP
step "2/3 Kill switch: AUTO_CLOSE_ENABLED=false"
T0=$(date +%s%3N)
worker_with false false
FLIP_MS=""
for _ in $(seq 1 90); do
  if [ "$(mode)" = "False False" ]; then FLIP_MS=$(($(date +%s%3N) - T0)); break; fi
  sleep 0.5
done
if [ -z "$FLIP_MS" ]; then
  bad "worker yeni dəyərlə işə düşmədi"
  exit 1
fi
FLIP_S=$((FLIP_MS / 1000)).$(((FLIP_MS % 1000) / 100))
if [ "$FLIP_MS" -le $((LIMIT_S * 1000)) ]; then ok "worker ${FLIP_S} s-də AUTO_CLOSE_ENABLED=False ilə işləyir (hədd ${LIMIT_S} s)"; else bad "${FLIP_S} s > ${LIMIT_S} s"; fi

# ---------------------------------------------------------------- 3. OFF
step "3/3 OFF: eyni 36 alert yenidən (intel cache dolu: qərarlar ON ilə eyni olmalıdır)"
make -s reset-keep-cache >/dev/null || exit 1
$PY tools/simulator.py --rate 1 --no-shuffle | tail -1
wait_done || exit 1
OFF_CLOSED=$(q "select count(*) from alerts where status='closed_auto'")
OFF_KS=$(q "select count(*) from decisions where shadow and reasons::text like '%kill switch%'")
# ON-da bağlanan alert-lər OFF-da nə oldu?
OFF_ROWS=$(docker compose exec -T postgres psql -U soc -d alert2case -tA -F' | ' -c \
  "select a.source_ref, a.status, d.rule_id, case when d.reasons::text like '%kill switch%' then 'kill switch' else '' end
     from alerts a join decisions d using (alert_id)
    where a.source_ref = any(string_to_array('$ON_LIST', ','))
    order by a.source_ref" 2>/dev/null)
[ "${OFF_CLOSED:-1}" -eq 0 ] && ok "heç bir alert bağlanmadı (closed_auto 0)" || bad "kill switch bağlı olsa da $OFF_CLOSED alert bağlandı"
[ "${OFF_KS:-0}" -gt 0 ] && ok "$OFF_KS qərar 'kill switch bağlıdır' səbəbi ilə insana göndərildi" \
  || bad "'kill switch' səbəbli qərar yoxdur: sistem bu dəfə heç nəyi bağlamaq istəmədi, test qəti deyil"

# ---------------------------------------------------------------- hesabat
{
  echo "# Kill switch testi"
  echo
  echo "Tarix: $(date '+%Y-%m-%d %H:%M') · Skript: \`tools/killswitch_test.sh\` · Nəticə: $([ $FAIL -eq 0 ] && echo '**OK**' || echo '**FAIL**')"
  echo
  echo "| Addım | Nəticə |"
  echo "|---|---|"
  echo "| ON (AUTO_CLOSE_ENABLED=true, SHADOW_MODE=false), 36 alert | closed_auto: $ON_CLOSED ($ON_LIST) |"
  echo "| Kill switch: AUTO_CLOSE_ENABLED=false, worker yeni dəyərlə işləyir | ${FLIP_S} s (hədd ${LIMIT_S} s) |"
  echo "| OFF, eyni 36 alert (intel cache dolu) | closed_auto: $OFF_CLOSED; 'kill switch bağlıdır' səbəbli case: $OFF_KS |"
  echo
  echo "ON-da bağlanan alert-lər OFF-da:"
  echo
  echo "| Alert | Status | Qayda | Səbəb |"
  echo "|---|---|---|---|"
  echo "$OFF_ROWS" | sed '/^$/d; s/^/| /; s/$/ |/'
  echo
  echo "Kill switch worker-in mühit dəyişənidir: dəyişiklik worker yenidən yaradılanda qüvvəyə minir."
  echo "Növbədə gözləyən alert-lər yeni worker tərəfindən emal olunur və artıq bağlanmır."
} >"$OUT"
printf '\nNəticə: %s\n' "$OUT"
echo "KILLSWITCH $([ $FAIL -eq 0 ] && echo OK || echo FAIL) · keçid ${FLIP_S} s · ON closed_auto $ON_CLOSED · OFF closed_auto $OFF_CLOSED"
exit $FAIL
