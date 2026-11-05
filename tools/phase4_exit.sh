#!/usr/bin/env bash
# alert2case · Phase 4 çıxış yoxlaması
# Hər üzv öz kompüterində, repo qovluğunda, main branch-da işlədir:
#   tools/phase4_exit.sh
# Nə edir: runbook-un ✓4 siyahısını yoxlayır. Simulyatorla 2 alert göndərir (biri zərərli, biri
# təmiz gözlənilən), onların alert-dən case-ə və bildirişə qədər yolunu bazadan, Redis-dən, audit-dən
# və case faylından oxuyur. Real intel API-yə 2-6 sorğu gedir. P1 alert üçün komandaya real
# bildiriş (Slack/Telegram/email) gedə bilər. Kodu və .env-i dəyişmir. Açarlar ekrana çıxmır.

PASS=0; FAILN=0; WARNN=0; SUMMARY=""
ok()   { printf '  \033[32mOK  \033[0m %s\n' "$1"; PASS=$((PASS+1)); SUMMARY="$SUMMARY $2:OK"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${3:-}" ] && printf '       \033[2m→ %s\033[0m\n' "$3"; FAILN=$((FAILN+1)); SUMMARY="$SUMMARY $2:FAIL"; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$1"; [ -n "${3:-}" ] && printf '       \033[2m→ %s\033[0m\n' "$3"; WARNN=$((WARNN+1)); SUMMARY="$SUMMARY $2:WARN"; }
info() { printf '       \033[2m%s\033[0m\n' "$1"; }
section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
[ -z "$ROOT" ] && { echo "Bu qovluq git repo deyil. Əvvəlcə: cd ~/projects/alert2case"; exit 1; }
cd "$ROOT" || exit 1
PY=.venv/bin/python
DC="docker compose"
psql_q() { $DC exec -T postgres psql -U soc -d alert2case -tAc "$1" </dev/null 2>/dev/null | tr -d '[:space:]'; }
psql_raw() { $DC exec -T postgres psql -U soc -d alert2case -tA -F '|' -c "$1" </dev/null 2>/dev/null; }
rcli()   { $DC exec -T redis redis-cli "$@" </dev/null 2>/dev/null; }
envval() { grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2-; }   # dəyər yalnız dəyişənə yazılır, çap olunmur

WHO=$(git config user.name 2>/dev/null)
printf '\033[1malert2case · Phase 4 çıxış yoxlaması\033[0m\n'
printf 'Üzv: %s · Tarix: %s\n' "${WHO:-?}" "$(date '+%Y-%m-%d %H:%M')"

# =================================================================== 1. Repo və Python
section "1 · Repo və Python"
BR=$(git branch --show-current)
git fetch -q origin main 2>/dev/null
BEHIND=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo "?")
if [ "$BR" = "main" ] && [ "$BEHIND" = "0" ]; then ok "main branch-dasınız, GitHub ilə eynidir" main
elif [ "$BR" != "main" ]; then bad "Hazırda '$BR' branch-dasınız" main "git switch main && git pull"
else bad "main GitHub-dan $BEHIND commit geridədir" main "git pull"; fi

if $PY -c 'import prometheus_client, aiosmtplib, respx' >/dev/null 2>&1; then
  ok "Phase 4 paketləri .venv-dədir (prometheus-client, aiosmtplib, respx)" pkgs
else bad "Phase 4 paketləri çatışmır" pkgs "uv pip install -r requirements.txt -r requirements-dev.txt"; fi

# =================================================================== 2. .env
section "2 · .env: Phase 4 dəyişənləri"
if [ -f .env ]; then
  EMPTY=""
  for K in ADMIN_TOKEN PROMETHEUS_VERSION GRAFANA_VERSION GRAFANA_ADMIN_PASSWORD; do
    [ -z "$(envval $K)" ] && EMPTY="$EMPTY $K"
  done
  if [ -z "$EMPTY" ]; then ok "ADMIN_TOKEN, PROMETHEUS_VERSION, GRAFANA_VERSION, GRAFANA_ADMIN_PASSWORD doludur (dəyərlər göstərilmir)" env4
  else bad "Boş və ya yoxdur:$EMPTY" env4 "Qrup mesajındakı 3 echo sətri; ADMIN_TOKEN runbook 2.5-dədir"; fi
  CH=""
  [ -n "$(envval SLACK_WEBHOOK_URL)" ] && CH="$CH Slack"
  [ -n "$(envval TELEGRAM_BOT_TOKEN)" ] && [ -n "$(envval TELEGRAM_CHAT_ID)" ] && CH="$CH Telegram"
  if [ -n "$CH" ]; then ok "Chat kanalı qurulub:$CH (+ email Mailpit-ə)" channels
  else warn "Slack və Telegram boşdur: bildiriş yalnız email ilə (Mailpit) gedəcək" channels "Runbook 4.5a: webhook və bot tokenini .env-ə yazın"; fi
  DUP=$(grep -oE '^[A-Z_]+=' .env | sort | uniq -d | tr -d '=' | tr '\n' ' ')
  [ -z "$DUP" ] && ok "Təkrar açar yoxdur" envdup || bad "Təkrar açarlar: $DUP" envdup "Hər açar .env-də bir dəfə olmalıdır"
else bad ".env faylı yoxdur" env4 "cp .env.example .env və dəyərləri doldurun"; fi

# =================================================================== 3. Servislər
section "3 · Servislər və təhlükəsizlik rejimi (4.3)"
SVC_OK=1
if ! docker info >/dev/null 2>&1; then
  bad "Docker işləmir" docker "Docker Desktop-u açın"; SVC_OK=0
elif ! $DC config -q >/dev/null 2>&1; then
  bad "docker compose konfiqurasiyası oxunmur" compose "$($DC config -q 2>&1 | head -1)"; SVC_OK=0
else
  for S in postgres redis; do
    ST=$($DC ps --format '{{.Service}} {{.Health}}' 2>/dev/null | awk -v s="$S" '$1==s{print $2}')
    [ "$ST" = "healthy" ] && ok "$S: healthy" "svc_$S" || { bad "$S: ${ST:-işləmir}" "svc_$S" "make up"; SVC_OK=0; }
  done
  for S in api worker mailpit; do
    ST=$($DC ps --format '{{.Service}} {{.State}}' 2>/dev/null | awk -v s="$S" '$1==s{print $2}')
    [ "$ST" = "running" ] && ok "$S: işləyir" "svc_$S" || { bad "$S: ${ST:-işləmir}" "svc_$S" "docker compose up -d --build api worker mailpit"; SVC_OK=0; }
  done
  if $DC exec -T worker python -c 'import prometheus_client, aiosmtplib' >/dev/null 2>&1 \
     && $DC exec -T api python -c 'import prometheus_client' >/dev/null 2>&1; then
    ok "api və worker image-lərində Phase 4 paketləri var" image
  else bad "Image köhnədir (prometheus-client və ya aiosmtplib yoxdur)" image "docker compose up -d --build api worker"; SVC_OK=0; fi
  MODE=$($DC exec -T worker python -c 'from app.config import settings as s; print(s.shadow_mode, s.auto_close_enabled, s.case_backend)' 2>/dev/null | tail -1)
  read -r SHADOW AUTOCLOSE BACKEND <<<"$MODE"
  if [ "$SHADOW" = "True" ]; then ok "Shadow mode açıqdır: sistem heç nəyi özü bağlamır, insan təsdiqləyir" shadow
  elif [ "$SHADOW" = "False" ] && [ "$AUTOCLOSE" = "False" ]; then warn "Shadow mode bağlıdır, amma kill switch auto-close-u söndürür" shadow "Runbook 4.3: SHADOW_MODE=true"
  else bad "Shadow mode bağlıdır və auto-close açıqdır (${MODE:-oxunmadı})" shadow ".env: SHADOW_MODE=true, AUTO_CLOSE_ENABLED=false, sonra docker compose up -d --force-recreate worker"; fi
  [ "$AUTOCLOSE" = "False" ] && info "Kill switch: AUTO_CLOSE_ENABLED=false (avtomatik bağlama söndürülüb)"
  case "$BACKEND" in
    file|thehive) ok "Case backend-i: $BACKEND" backend ;;
    *) bad "Case backend-i oxunmadı (${BACKEND:-?})" backend ".env: CASE_BACKEND=file və ya thehive" ;;
  esac
  VTURL=$($DC exec -T worker printenv VT_BASE_URL 2>/dev/null | tr -d '[:space:]')
  case "$VTURL" in
    *toxiproxy*|*127.0.0.1*) bad "Worker test rejimindədir (VT_BASE_URL=$VTURL)" mode "docker compose up -d --force-recreate worker" ;;
    *) ok "Worker normal rejimdədir (real intel ünvanları)" mode ;;
  esac
fi

# =================================================================== 4. Kontekst və qaydalar
section "4 · Kontekst faylları və qaydalar (4.1, 4.2)"
CTX=$($PY - <<'PYEOF' 2>/dev/null
import csv
import json
import pathlib
from datetime import datetime, timezone

from app.normalize import normalize
from app.rules.engine import load_rules

hosts = {r["hostname"] for r in csv.DictReader(open("context/assets.csv", encoding="utf-8"))}
users = {r["user"] for r in csv.DictReader(open("context/identities.csv", encoding="utf-8"))}
mh, mu, n = set(), set(), 0
for f in sorted(pathlib.Path("dataset/raw").glob("*.json")):
    d = json.loads(f.read_text(encoding="utf-8"))
    a = normalize(d["source"], d["payload"], datetime.now(timezone.utc))
    n += 1
    if a.host and a.host not in hosts:
        mh.add(a.host)
    if a.user and a.user not in users:
        mu.add(a.user)
rs = load_rules()
print(f"alerts={n} hosts={len(hosts)} users={len(users)} mh={','.join(sorted(mh)) or '-'} "
      f"mu={','.join(sorted(mu)) or '-'} rules={len(rs.rules)} version={rs.version} last={rs.rules[-1].id}")
PYEOF
)
get() { echo "$CTX" | grep -oE "$1=[^ ]+" | cut -d= -f2; }
if [ -z "$CTX" ]; then bad "Kontekst və ya qayda faylı oxunmadı" context "$PY -c 'from app.rules.engine import load_rules; load_rules()'"
else
  if [ "$(get mh)" = "-" ] && [ "$(get mu)" = "-" ]; then
    ok "Kontekst dataset-i tam əhatə edir: $(get alerts) alert, $(get hosts) host, $(get users) istifadəçi" context
  else bad "Kontekstdə olmayan host: $(get mh) · istifadəçi: $(get mu)" context "context/assets.csv və identities.csv-ə əlavə edin"; fi
  ok "rules/severity.yaml etibarlıdır: $(get rules) qayda, versiya $(get version), sonuncu $(get last) (default)" rules
fi

# =================================================================== 5. Baza
section "5 · Baza: miqrasiya 0002 və append-only audit (4.2)"
if [ $SVC_OK -eq 1 ]; then
  # sonrakı fazaların miqrasiyaları da ola bilər, ona görə versiya yox, cədvəllər və trigger yoxlanır
  TBL=$(psql_q "select count(*) from information_schema.tables where table_name in ('decisions','cases')")
  TRG=$(psql_q "select count(*) from pg_trigger where tgname='audit_log_no_change'")
  if [ "$TBL" = "2" ] && [ "$TRG" = "1" ]; then ok "Miqrasiya 0002 tətbiq olunub (decisions, cases, append-only trigger)" migrate
  else bad "decisions/cases cədvəlləri və ya audit trigger-i yoxdur" migrate "make migrate"; fi
  AO=$($DC exec -T postgres psql -U soc -d alert2case 2>&1 <<'SQL'
BEGIN;
UPDATE audit_log SET event = event WHERE id = (SELECT max(id) FROM audit_log);
ROLLBACK;
SQL
)
  if echo "$AO" | grep -q "append-only"; then ok "audit_log append-only: UPDATE rədd edildi (dəyişiklik geri alındı)" appendonly
  else bad "audit_log-da UPDATE bloklanmadı" appendonly "make migrate (trigger audit_log_no_change)"; fi
else warn "Servislər işləmədiyi üçün yoxlanmadı" migrate; fi

# =================================================================== 6. Tam axın
section "6 · Tam axın: simulyatordan case-ə (4.3, 4.4, 4.6a)"
MAL=""; MAL_ANY=""; CLEAN=""
if [ $SVC_OK -eq 1 ]; then
  # dedup pəncərəsində (15 dəq) olmayan bir zərərli (üstünlük HASH) və bir təmiz alert seçilir
  CANDS=$($PY - <<'PYEOF' 2>/dev/null
import csv
import json
import pathlib
from datetime import datetime, timezone

from app.normalize import normalize

exp = {r["alert_id"]: r["verdict"] for r in csv.DictReader(open("dataset/expected.csv", encoding="utf-8"))}
for f in sorted(pathlib.Path("dataset/raw").glob("*.json")):
    d = json.loads(f.read_text(encoding="utf-8"))
    a = normalize(d["source"], d["payload"], datetime.now(timezone.utc))
    if a.external_iocs() and exp.get(f.stem) in ("malicious", "clean"):
        print(f.stem, exp[f.stem], a.fingerprint)
PYEOF
)
  while read -r REF EXP FP; do
    [ -z "$REF" ] && continue
    RECENT=$(psql_q "select count(*) from alerts where fingerprint='$FP' and last_seen > now() - interval '15 minutes'")
    [ "$RECENT" != "0" ] && continue
    if [ -z "$MAL" ] && [ "$EXP" = "malicious" ] && [[ "$REF" == HASH-* ]]; then MAL=$REF; fi
    if [ -z "$MAL_ANY" ] && [ "$EXP" = "malicious" ]; then MAL_ANY=$REF; fi
    if [ -z "$CLEAN" ] && [ "$EXP" = "clean" ]; then CLEAN=$REF; fi
  done <<<"$CANDS"
  MAL=${MAL:-$MAL_ANY}   # HASH üstündür, yoxdursa istənilən zərərli alert
fi
if [ $SVC_OK -ne 1 ]; then warn "Servislər işləmədiyi üçün yoxlanmadı" e2e
elif [ -z "$MAL" ] || [ -z "$CLEAN" ]; then
  warn "Son 15 dəqiqədə göndərilməmiş uyğun alert tapılmadı" e2e "15 dəqiqə gözləyib skripti təkrar işlədin"
else
  T0=$(psql_q "select extract(epoch from now())")   # baza saatı ilə, saniyə
  MAILS0=$(curl -s "http://localhost:8025/api/v1/messages?limit=1" | $PY -c 'import sys,json;print(json.load(sys.stdin).get("total",0))' 2>/dev/null)
  info "Göndərilir: $MAL (gözlənilən: malicious) və $CLEAN (gözlənilən: clean)"
  SIM=$($PY tools/simulator.py --only "$MAL,$CLEAN" --rate 1 2>&1 | tail -1)
  if echo "$SIM" | grep -q "Göndərildi: 2, gözlənilən cavab (202): 2"; then ok "Simulyator: 2 alert → 202" simulate
  else bad "Simulyator: ${SIM:-cavab yoxdur}" simulate "docker compose logs api --tail 20"; fi
  printf '       \033[2mgözlənilir (intel + qərar + case + bildiriş, maks. 3 dəq) '
  for _ in $(seq 1 90); do
    DONE=$(psql_q "select count(*) from alerts where source_ref in ('$MAL','$CLEAN') and received_at > to_timestamp($T0)
                   and status in ('case_created','closed_auto','case_pending')")
    NOTI=$(psql_q "select count(*) from audit_log l join alerts a on a.alert_id=l.correlation_id
                   where a.source_ref in ('$MAL','$CLEAN') and l.ts > to_timestamp($T0) and l.stage='notify'")
    [ "$DONE" = "2" ] && [ "$NOTI" = "2" ] && break
    printf '·'; sleep 2
  done
  printf '\033[0m\n'

  ROWS=$(psql_raw "select a.source_ref, a.status, d.verdict, d.rule_id, d.action, d.priority, d.shadow,
                          coalesce(c.backend,'-'), coalesce(c.case_id,'-'), coalesce(c.case_url,'-'), a.alert_id
                   from alerts a
                   left join lateral (select * from decisions x where x.alert_id=a.alert_id order by id desc limit 1) d on true
                   left join cases c on c.alert_id=a.alert_id
                   where a.source_ref in ('$MAL','$CLEAN') and a.received_at > to_timestamp($T0) order by a.source_ref")
  N=0; ALLSTAGES=1; MAL_ID=""; MAL_PRIO=""
  while IFS='|' read -r REF ST VER RULE ACT PRIO SHD CB CID CURL AID; do
    [ -z "$REF" ] && continue
    N=$((N+1))
    printf '       %-9s → %-12s qayda %-18s %-11s %-3s verdict %-10s shadow=%s  case %s\n' "$REF" "$ST" "$RULE" "$ACT" "$PRIO" "$VER" "$SHD" "$CID"
    STG=$(psql_q "select count(distinct stage) from audit_log where correlation_id='$AID'
                  and stage in ('ingest','normalize','enrich','decide','act','notify')")
    [ "$STG" != "6" ] && ALLSTAGES=0
    if [ "$REF" = "$MAL" ]; then MAL_ID=$AID; MAL_PRIO=$PRIO; MAL_ST=$ST; MAL_CB=$CB; MAL_CURL=$CURL; MAL_CID=$CID; fi
    if [ "$REF" = "$CLEAN" ]; then CL_ACT=$ACT; CL_SHD=$SHD; CL_ST=$ST; CL_RULE=$RULE; fi
  done <<<"$ROWS"

  if [ "$N" = "2" ] && [ "$DONE" = "2" ]; then ok "2/2 alert yolu sona çatdı: normalize → enrich → qərar → hərəkət" e2e
  else bad "Yalnız $N/2 alert bazada, $DONE/2 son statusa çatıb" e2e "docker compose logs worker --since 5m"; fi
  [ "$ALLSTAGES" = "1" ] && [ "$N" = "2" ] && ok "Hər alert-in 6 mərhələsi audit-dədir (ingest, normalize, enrich, decide, act, notify)" stages \
    || bad "Bəzi mərhələlər audit-də yoxdur" stages "docker compose logs worker --since 5m"

  case "$MAL_ST" in
    case_created)
      if [ "$MAL_CB" = "file" ]; then
        [ -f "$MAL_CURL" ] && ok "$MAL case yaradıldı: $MAL_CURL (fayl backend-i)" case \
          || bad "Case bazada var, amma fayl tapılmadı: $MAL_CURL" case "Worker /code mount-unu yoxlayın"
      else ok "$MAL case yaradıldı: TheHive $MAL_CID" case; fi ;;
    case_pending) bad "$MAL üçün case yaradılmadı (case DLQ-dadır)" case "CASE_BACKEND / TheHive-ı yoxlayın; housekeeping 2 dəqiqədən bir təkrar sınayır" ;;
    *) bad "$MAL: zərərli alert üçün case gözlənilirdi, status: ${MAL_ST:-?}" case "Qızıl qayda: malicious heç vaxt bağlanmamalıdır" ;;
  esac

  if [ "$CL_SHD" = "t" ] && [ "$CL_ACT" = "create_case" ]; then
    ok "Shadow mode işlədi: $CLEAN bağlana bilərdi ($CL_RULE), amma case açıldı və shadow işarələndi" shadowrun
  elif [ "$CL_ST" = "closed_auto" ] && [ "$SHADOW" = "True" ]; then
    bad "$CLEAN shadow mode açıq olduğu halda avtomatik bağlandı" shadowrun "app/rules/guards.py"
  elif [ "$CL_ST" = "closed_auto" ]; then
    ok "$CLEAN avtomatik bağlandı ($CL_RULE), shadow mode bağlıdır" shadowrun
  else
    warn "$CLEAN üçün auto-close namizədi çıxmadı ($CL_RULE → $CL_ACT): shadow bu qaçışda yoxlanmadı" shadowrun "Bu normaldır (intel nəticəsindən asılıdır); shadow unit testlərdə yoxlanır"
  fi

  GOLD=$(psql_q "select (select count(*) from decisions where verdict='malicious' and action='auto_close')
                      + (select count(*) from alerts where status='closed_auto' and doc->'enrichment'->>'verdict'='malicious')")
  [ "$GOLD" = "0" ] && ok "Qızıl qayda: bazada heç bir zərərli alert avtomatik bağlanmayıb" golden \
    || bad "Qızıl qayda pozulub: $GOLD zərərli alert auto_close" golden "Dərhal: AUTO_CLOSE_ENABLED=false və komandaya xəbər verin"
  CDLQ=$(rcli XLEN cases.dlq | tr -d '[:space:]')
  [ "${CDLQ:-0}" = "0" ] && ok "Case DLQ boşdur: gözləyən case yoxdur" casedlq \
    || warn "Case DLQ-da ${CDLQ} alert gözləyir" casedlq "Case backend-ini yoxlayın; housekeeping 2 dəqiqədən bir təkrar sınayır"

  # ================================================================= 7. Bildiriş
  section "7 · Bildiriş (4.5)"
  NEV=$(psql_raw "select event, payload->>'channels' from audit_log where correlation_id='$MAL_ID' and stage='notify' order by id desc limit 1")
  EV=${NEV%%|*}; CHS=$(echo "${NEV#*|}" | tr -d '[]" ')
  case "$EV" in
    sent) ok "$MAL ($MAL_PRIO) bildirişi göndərildi: $CHS" notify ;;
    throttled) ok "$MAL ($MAL_PRIO): son 30 dəqiqədə eyni alert bildirilib, throttle işlədi" notify ;;
    skipped) warn "$MAL prioriteti $MAL_PRIO: bildiriş yalnız P1/P2 üçündür" notify ;;
    failed) bad "$MAL ($MAL_PRIO): heç bir kanal işləmədi" notify "docker compose logs worker --since 5m | grep -i bildiriş" ;;
    *) bad "Bildiriş audit-də tapılmadı" notify ;;
  esac
  if echo "$CHS" | grep -q email; then
    MAILS1=$(curl -s "http://localhost:8025/api/v1/messages?limit=1" | $PY -c 'import sys,json;print(json.load(sys.stdin).get("total",0))' 2>/dev/null)
    if [ -n "$MAILS1" ] && [ "${MAILS1:-0}" -gt "${MAILS0:-0}" ] 2>/dev/null; then ok "Email Mailpit-ə çatdı (http://localhost:8025)" email
    else warn "Email göndərildi, amma Mailpit-də yeni məktub görünmür" email "http://localhost:8025"; fi
  fi
fi

# =================================================================== 8. Audit
section "8 · Audit zənciri və timeline (4.7)"
if [ $SVC_OK -eq 1 ]; then
  VA=$($DC exec -T worker python -m tools.verify_audit 2>&1 | tail -1)
  case "$VA" in OK:*) ok "Audit zənciri: ${VA#OK: }" chain ;; *) bad "Audit zənciri: ${VA:-yoxlanmadı}" chain "docker compose exec worker python -m tools.verify_audit" ;; esac
  TOKEN=$(envval ADMIN_TOKEN)
  if [ -n "$MAL_ID" ] && [ -n "$TOKEN" ]; then
    TL=$(curl -s -H "X-Admin-Token: $TOKEN" "http://localhost:8000/alerts/$MAL_ID/timeline" \
         | $PY -c 'import sys,json;d=json.load(sys.stdin);print(len(d), d[-1]["t_plus_s"]) if isinstance(d,list) and d else print("0 0")' 2>/dev/null)
    read -r TLN TLS <<<"$TL"
    [ "${TLN:-0}" -ge 6 ] 2>/dev/null && ok "Timeline endpoint-i: $MAL üçün $TLN addım, alert-dən bildirişə $TLS s" timeline \
      || bad "Timeline endpoint-i cavab vermədi" timeline "curl -H 'X-Admin-Token: …' localhost:8000/alerts/<id>/timeline"
  else warn "Timeline yoxlanmadı (alert göndərilmədi və ya ADMIN_TOKEN boşdur)" timeline; fi
  unset TOKEN
else warn "Servislər işləmədiyi üçün yoxlanmadı" chain; fi

# =================================================================== 9. Metrikalar
section "9 · Metrikalar, Prometheus və Grafana (4.7)"
if [ $SVC_OK -eq 1 ]; then
  WM=$($DC exec -T worker python -c 'import urllib.request as u; print(u.urlopen("http://localhost:9100/metrics", timeout=5).read().decode())' 2>/dev/null | grep -c '^alert2case_')
  [ "${WM:-0}" -gt 0 ] && ok "Worker metrikaları (:9100): $WM alert2case sətri" wmetrics || bad "Worker metrikaları oxunmadı" wmetrics "docker compose up -d --build worker"
  AM=$(curl -s -o /dev/null -w '%{http_code}' -L http://localhost:8000/metrics/)
  [ "$AM" = "200" ] && ok "API /metrics endpoint-i: 200" ametrics || bad "API /metrics: HTTP ${AM:-?}" ametrics "docker compose up -d --build api"
  if curl -s -m 3 http://localhost:9090/-/ready >/dev/null 2>&1; then
    UP=$(curl -s http://localhost:9090/api/v1/targets | $PY -c 'import sys,json;t=json.load(sys.stdin)["data"]["activeTargets"];print(sum(x["health"]=="up" for x in t), len(t))' 2>/dev/null)
    read -r U T <<<"$UP"
    [ "${U:-0}" = "${T:-x}" ] && ok "Prometheus: $U/$T hədəf UP (api, worker)" prom || warn "Prometheus: ${U:-0}/${T:-?} hədəf UP" prom "http://localhost:9090/targets"
    GPW=$(envval GRAFANA_ADMIN_PASSWORD)
    GD=$(curl -s -m 5 -u "admin:$GPW" "http://localhost:3000/api/search?query=alert2case" 2>/dev/null | grep -c '"title"')
    unset GPW
    [ "${GD:-0}" -gt 0 ] && ok "Grafana: alert2case paneli yüklənib (http://localhost:3000)" grafana \
      || warn "Grafana-da alert2case paneli tapılmadı" grafana "make up-obs; parol .env-dəki GRAFANA_ADMIN_PASSWORD"
  else
    warn "Prometheus və Grafana işləmir" prom "make up-obs, sonra skripti təkrar işlədin"
  fi
else warn "Servislər işləmədiyi üçün yoxlanmadı" wmetrics; fi

# =================================================================== 10. n8n
section "10 · n8n axını (4.6b)"
if $PY -c 'import json; [json.load(open(f, encoding="utf-8")) for f in ("n8n/alert2case-pipeline.json", "n8n/alert2case-errors.json")]' 2>/dev/null; then
  ok "n8n workflow JSON-ları repoda və etibarlıdır" n8nfiles
else bad "n8n/alert2case-pipeline.json və ya alert2case-errors.json yoxdur/xətalıdır" n8nfiles "git pull"; fi
if [ $SVC_OK -eq 1 ]; then
  ST=$($DC ps --format '{{.Service}} {{.State}}' 2>/dev/null | awk '$1=="n8n"{print $2}')
  [ "$ST" = "running" ] && ok "n8n işləyir (http://localhost:5678)" n8n || warn "n8n: ${ST:-işləmir}" n8n "make up"
  SC=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' http://localhost:8000/stage/normalize)
  [ "$SC" = "403" ] && ok "Mərhələ endpoint-ləri (/stage/*) var və admin token tələb edir" stagesapi \
    || bad "/stage/normalize tokensiz: HTTP ${SC:-?} (403 gözlənilirdi)" stagesapi "docker compose up -d --build api"
fi
info "Əl ilə: n8n-də 'alert2case pipeline' və 'errors' workflow-ları import və publish olunub? (runbook 4.6b)"

# =================================================================== 11. Testlər
section "11 · Testlər (4.8)"
MISSING=""
for F in tests/unit/test_guards.py tests/unit/test_case.py tests/unit/test_case_notify.py \
         tests/unit/test_rules_engine.py tests/unit/test_context.py tests/unit/test_pipeline.py; do
  [ -f "$F" ] || MISSING="$MISSING $F"
done
[ -z "$MISSING" ] && ok "Phase 4 test faylları yerindədir" files || bad "Yoxdur:$MISSING" files "git pull"
TEST=$($PY -m pytest tests/unit -p no:cacheprovider --cov --cov-fail-under=85 2>&1 | tail -3)
if echo "$TEST" | grep -qE '[0-9]+ passed' && ! echo "$TEST" | grep -qE '[0-9]+ failed' && echo "$TEST" | grep -q "coverage of 85% reached"; then
  ok "pytest: $(echo "$TEST" | grep -oE '[0-9]+ passed'), $(echo "$TEST" | grep -oE 'Total coverage: [0-9.]+%')" tests
else bad "pytest: $(echo "$TEST" | tail -1)" tests "pytest tests/unit ilə baxın"; fi
if [ $SVC_OK -eq 1 ]; then
  TB=$($DC logs worker --since 10m 2>/dev/null | grep -c Traceback)
  [ "$TB" = "0" ] && ok "Worker log-unda son 10 dəqiqədə traceback yoxdur" traceback || warn "Worker log-unda $TB traceback" traceback "docker compose logs worker --since 10m | grep -B3 -A25 Traceback"
fi

# =================================================================== Nəticə
printf '\n\033[1mNƏTİCƏ:\033[0m %d OK · %d FAIL · %d WARN\n' "$PASS" "$FAILN" "$WARNN"
if [ $FAILN -eq 0 ]; then printf '\033[32mPhase 4 bu kompüterdə tam işləyir: alert-dən case-ə və bildirişə qədər.\033[0m\n'
else printf '\033[31mFAIL olan sətirlərin altındakı → göstərişə əməl edin.\033[0m\n'; fi
printf '\nQrupa göndərmək üçün:\nP4EXIT %s |%s\n' "${WHO:-?}" "$SUMMARY"
[ $FAILN -eq 0 ]
