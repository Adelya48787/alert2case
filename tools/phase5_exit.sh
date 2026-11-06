#!/usr/bin/env bash
# alert2case · Phase 5 çıxış yoxlaması
# Hər üzv öz kompüterində, repo qovluğunda, main branch-da işlədir:
#   tools/phase5_exit.sh
# Nə edir: runbook-un ✓5 siyahısını yoxlayır. dataset/demo-dan 11 korrelyasiya demo alert-ini
# ssenari sırası ilə bir-bir göndərir və C1, C3, C4-ün işə düşdüyünü, case sayının azaldığını
# bazadan və audit-dən oxuyur. Bir demo alert-ə əl ilə rəy yazır (analyst=p5exit, sistemin öz
# hökmü ilə razı), replay və tuner-i (--apply olmadan) işlədir. Real intel API-yə ~10-20 sorğu
# gedir, VirusTotal limiti üzündən 3-5 dəqiqə çəkir. Kodu, .env-i və repo fayllarını dəyişmir
# (tuner-in yazdığı təklif faylı geri qaytarılır). Açarlar ekrana çıxmır.

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
# </dev/null: docker compose exec stdin-i oxuyur; olmasa, "while read" dövrünün qalan sətirlərini udur
psql_q() { $DC exec -T postgres psql -U soc -d alert2case -tAc "$1" </dev/null 2>/dev/null | tr -d '[:space:]'; }
psql_raw() { $DC exec -T postgres psql -U soc -d alert2case -tA -F '|' -c "$1" </dev/null 2>/dev/null; }
wpy()    { $DC exec -T worker python "$@" </dev/null 2>&1; }
envval() { grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2-; }   # dəyər yalnız dəyişənə yazılır, çap olunmur
DEMO=dataset/demo

WHO=$(git config user.name 2>/dev/null)
printf '\033[1malert2case · Phase 5 çıxış yoxlaması\033[0m\n'
printf 'Üzv: %s · Tarix: %s\n' "${WHO:-?}" "$(date '+%Y-%m-%d %H:%M')"

# =================================================================== 1. Repo
section "1 · Repo və Python"
BR=$(git branch --show-current)
git fetch -q origin main 2>/dev/null
BEHIND=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo "?")
if [ "$BR" = "main" ] && [ "$BEHIND" = "0" ]; then ok "main branch-dasınız, GitHub ilə eynidir" main
elif [ "$BR" != "main" ]; then bad "Hazırda '$BR' branch-dasınız" main "git switch main && git pull"
else bad "main GitHub-dan $BEHIND commit geridədir" main "git pull"; fi
CHG=$(git status --porcelain --untracked-files=no 2>/dev/null)
if [ -z "$CHG" ]; then ok "İzlənən fayllarda lokal dəyişiklik yoxdur" localchg
else warn "Lokal dəyişiklik var: $(echo "$CHG" | awk '{print $2}' | head -3 | tr '\n' ' ')" localchg "git diff ilə baxın; rules/ və ya dataset/ dəyişibsə nəticə fərqli olar"; fi
NDEMO=$(ls "$DEMO"/DEMO-*.json 2>/dev/null | wc -l | tr -d ' ')
[ "$NDEMO" = "11" ] && ok "Korrelyasiya demo alert-ləri yerindədir (dataset/demo, 11 fayl)" demofiles \
  || bad "dataset/demo-da $NDEMO fayl var (11 gözlənilir)" demofiles "git pull"

# =================================================================== 2. Servislər
section "2 · Servislər"
SVC_OK=1
if ! docker info >/dev/null 2>&1; then bad "Docker işləmir" docker "Docker Desktop-u açın"; SVC_OK=0
else
  for S in postgres redis; do
    ST=$($DC ps --format '{{.Service}} {{.Health}}' 2>/dev/null | awk -v s="$S" '$1==s{print $2}')
    [ "$ST" = "healthy" ] && ok "$S: healthy" "svc_$S" || { bad "$S: ${ST:-işləmir}" "svc_$S" "make up"; SVC_OK=0; }
  done
  for S in api worker; do
    ST=$($DC ps --format '{{.Service}} {{.State}}' 2>/dev/null | awk -v s="$S" '$1==s{print $2}')
    [ "$ST" = "running" ] && ok "$S: işləyir" "svc_$S" || { bad "$S: ${ST:-işləmir}" "svc_$S" "docker compose up -d --build api worker"; SVC_OK=0; }
  done
  VTURL=$($DC exec -T worker printenv VT_BASE_URL </dev/null 2>/dev/null | tr -d '[:space:]')
  case "$VTURL" in
    *toxiproxy*|*127.0.0.1*) bad "Worker test rejimindədir (VT_BASE_URL=$VTURL)" mode "docker compose up -d --force-recreate worker" ;;
    *) ok "Worker normal rejimdədir (real intel ünvanları)" mode ;;
  esac
fi

# =================================================================== 3. Baza və qaydalar
section "3 · Baza və qaydalar (5.1, 5.3)"
if [ $SVC_OK -eq 1 ]; then
  TBL=$(psql_q "select count(*) from information_schema.tables where table_name in ('feedback','case_links')")
  [ "$TBL" = "2" ] && ok "Miqrasiya 0003 tətbiq olunub (feedback, case_links)" migrate || bad "feedback/case_links cədvəlləri yoxdur" migrate "make migrate"
fi
[ -n "$(envval FEEDBACK_TOKEN)" ] && ok "FEEDBACK_TOKEN doludur (dəyər göstərilmir)" fbtoken \
  || bad "FEEDBACK_TOKEN boşdur" fbtoken 'echo "FEEDBACK_TOKEN=$(openssl rand -hex 24)" >> .env, sonra docker compose up -d --force-recreate api'
CFG=$($PY - <<'PYEOF' 2>&1
import yaml
c = yaml.safe_load(open("rules/correlation.yaml", encoding="utf-8"))
w = yaml.safe_load(open("rules/weights.yaml", encoding="utf-8"))
on = [k for k, v in c["rules"].items() if v.get("enabled")]
print(f"cfg {c['window_hours']} {','.join(on)} {w['version']}")
PYEOF
)
if echo "$CFG" | grep -q '^cfg '; then
  read -r _ WINH ON WV <<<"$(echo "$CFG" | grep '^cfg ')"
  ok "rules/correlation.yaml etibarlıdır: pəncərə $WINH saat, aktiv qaydalar: $ON" corrcfg
  ok "rules/weights.yaml versiyası: $WV" weights
else bad "Qayda faylları oxunmadı: $(echo "$CFG" | tail -1 | cut -c1-120)" corrcfg "git pull"; fi

# =================================================================== 4. Korrelyasiya demosu
section "4 · Korrelyasiya: demo ssenariləri (5.3)"
DEMO_IDS=()
send_wait() {   # 1 demo alert göndərir və son statusa çatmasını gözləyir (maks. 120 s)
  local ref=$1 t0 out code
  t0=$(psql_q "select extract(epoch from now())")
  out=$($PY tools/simulator.py --dataset "$DEMO" --only "$ref" --rate 1 2>&1 | tail -1)
  echo "$out" | grep -q "gözlənilən cavab (202): 1" || { echo "send-fail"; return; }
  for _ in $(seq 1 60); do
    code=$(psql_q "select status from alerts where source_ref='$ref' and received_at > to_timestamp($t0)
                   and status in ('case_created','closed_auto','case_pending') order by received_at desc limit 1")
    [ -n "$code" ] && { echo "$code"; return; }
    sleep 2
  done
  echo "timeout"
}
if [ $SVC_OK -ne 1 ]; then warn "Servislər işləmədiyi üçün yoxlanmadı" corr
else
  RECENT=$(psql_q "select count(*) from alerts where source_ref like 'DEMO-%' and last_seen > now() - interval '15 minutes'")
  if [ "$RECENT" != "0" ]; then
    warn "Demo alert-ləri son 15 dəqiqədə göndərilib, dublikat sayılacaqlar" corr "15 dəqiqə gözləyib skripti təkrar işlədin"
  else
    T0=$(psql_q "select extract(epoch from now())")
    info "11 alert bir-bir göndərilir (ssenari sırası vacibdir), 3-5 dəqiqə çəkə bilər"
    FAILSEND=""
    for REF in DEMO-C1-A DEMO-C1-B DEMO-C3-URL DEMO-C3-HASH DEMO-C4-1 DEMO-C4-2 DEMO-C4-3 DEMO-C4-4 DEMO-C4-5 DEMO-C4-6 DEMO-C4-7; do
      R=$(send_wait "$REF")
      printf '       \033[2m%-13s → %s\033[0m\n' "$REF" "$R"
      case "$R" in case_created|closed_auto|case_pending) ;; *) FAILSEND="$FAILSEND $REF" ;; esac
    done
    [ -z "$FAILSEND" ] && ok "11/11 demo alert emal olundu" corrsend || bad "Emal olunmayan:$FAILSEND" corrsend "docker compose logs worker --since 10m"

    EV=$(psql_raw "select a.source_ref, l.event from audit_log l join alerts a on a.alert_id = l.correlation_id
                   where l.stage = 'correlate' and a.source_ref like 'DEMO-%' and a.received_at > to_timestamp($T0)")
    has() { echo "$EV" | grep -q "^$1|$2$"; }
    C1CASE=$(psql_raw "select c.case_id from cases c join alerts a using (alert_id) where a.source_ref in ('DEMO-C1-A','DEMO-C1-B')
                       and a.received_at > to_timestamp($T0)" | sort -u | grep -c .)
    if has DEMO-C1-B same_ioc && [ "$C1CASE" = "1" ]; then ok "C1 eyni IOC: ikinci phishing alert-i yeni case açmadı, birincinin case-inə bağlandı" c1
    else bad "C1 işləmədi (DEMO-C1-B same_ioc yoxdur və ya $C1CASE case)" c1 "Redis indeksi: make reset-data-dan sonra təkrar yoxlayın"; fi

    # korrelyasiya qərarı decide-dən sonra dəyişir: son prioritet alert-in öz sənədindədir, decisions cədvəlində yox
    C3P=$(psql_q "select doc->'decision'->>'priority' from alerts where source_ref='DEMO-C3-HASH'
                  and received_at > to_timestamp($T0) order by received_at desc limit 1")
    if has DEMO-C3-HASH host_chain && [ "$C3P" = "P1" ]; then ok "C3 hostda zəncir: WS-034-də URL → fayl, fayl alert-i P1 oldu" c3
    else bad "C3 işləmədi (host_chain yoxdur və ya prioritet ${C3P:-?})" c3 "Proxy alert-də host.name oxunurmu? git pull"; fi

    NCAMP=$(echo "$EV" | grep -c "|bruteforce_campaign$"); NLINK=$(echo "$EV" | grep -c "|bruteforce_link$")
    if [ "$NCAMP" -ge 1 ] || [ "$NLINK" -ge 1 ]; then ok "C4 brute force: kampaniya $NCAMP dəfə açıldı, $NLINK login ona bağlandı" c4
    else bad "C4 işləmədi: 185.220.101.0/24 kampaniyası yaranmadı" c4 "docker compose logs worker --since 10m"; fi

    NA=$(psql_q "select count(*) from alerts where source_ref like 'DEMO-%' and received_at > to_timestamp($T0)")
    NC=$(psql_q "select count(distinct c.case_id) from cases c join alerts a using (alert_id) where a.source_ref like 'DEMO-%'
                 and a.received_at > to_timestamp($T0)")
    if [ "${NC:-0}" -gt 0 ] && [ "${NC:-0}" -lt "${NA:-0}" ] 2>/dev/null; then ok "Case sayı azaldı: $NA alert → $NC case" casecount
    else bad "Case sayı azalmadı: $NA alert → $NC case" casecount; fi
    DEMO_ID=$(psql_q "select alert_id from alerts where source_ref='DEMO-C1-A' and received_at > to_timestamp($T0) limit 1")
  fi
fi

# =================================================================== 5. Rəy
section "5 · Analitik rəyi (5.1)"
if [ $SVC_OK -eq 1 ]; then
  WH=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' http://localhost:8000/feedback/thehive)
  [ "$WH" = "403" ] && ok "TheHive webhook-u tokensiz sorğunu rədd edir (403)" webhook || bad "/feedback/thehive tokensiz: HTTP ${WH:-?}" webhook "docker compose up -d --build api"
  [ -z "${DEMO_ID:-}" ] && DEMO_ID=$(psql_q "select a.alert_id from alerts a join decisions d using (alert_id) order by a.received_at desc limit 1")
  TOKEN=$(envval ADMIN_TOKEN)
  if [ -n "$DEMO_ID" ] && [ -n "$TOKEN" ]; then
    VER=$(psql_q "select verdict from decisions where alert_id='$DEMO_ID' order by id desc limit 1")
    [ "$VER" = "unknown" ] && VER=suspicious
    N0=$(psql_q "select count(*) from feedback where alert_id='$DEMO_ID'")
    FB=$(curl -s -H "X-Admin-Token: $TOKEN" -H 'Content-Type: application/json' -X POST http://localhost:8000/feedback \
         -d "{\"alert_id\":\"$DEMO_ID\",\"human_verdict\":\"$VER\",\"analyst\":\"p5exit\",\"source\":\"manual\",\"comment\":\"phase5_exit yoxlamasi\"}")
    N1=$(psql_q "select count(*) from feedback where alert_id='$DEMO_ID'")
    if echo "$FB" | grep -q '"saved":true' && [ "${N1:-0}" -gt "${N0:-0}" ] 2>/dev/null; then ok "Əl ilə rəy (/feedback) bazaya yazıldı və audit-ə düşdü" feedback
    else bad "Əl ilə rəy yazılmadı: $(echo "$FB" | cut -c1-100)" feedback "ADMIN_TOKEN və api loqunu yoxlayın"; fi
  else warn "Rəy yoxlanmadı (alert yoxdur və ya ADMIN_TOKEN boşdur)" feedback; fi
  unset TOKEN
  info "Əl ilə: TheHive istifadə edirsinizsə, bir case-i 'False Positive' ilə bağlayın və rəyin bazaya düşdüyünü yoxlayın (runbook 5.1)"
fi

# =================================================================== 6. Replay və tuner
section "6 · Replay və tuner (5.2)"
if [ $SVC_OK -eq 1 ]; then
  RP=$(wpy -m tools.replay | grep "^{" | tail -1)
  FN=$(echo "$RP" | grep -oE "'fn': [0-9]+" | grep -oE '[0-9]+$'); NR=$(echo "$RP" | grep -oE "'n': [0-9]+" | grep -oE '[0-9]+$')
  RC=$(echo "$RP" | grep -oE "'recall': [0-9.]+" | grep -oE '[0-9.]+$')
  if [ -z "$FN" ]; then bad "Replay işləmədi" replay "docker compose exec worker python -m tools.replay"
  elif [ "$FN" = "0" ]; then ok "Replay: $NR alert, FN 0, recall ${RC:-?}: auto-close açılsaydı heç bir zərərli alert bağlanmazdı" replay
  else bad "Replay: FN $FN, $(echo "$RP" | grep -oE "'fn_alerts': \[[^]]*\]")" replay "Qızıl qayda: bu alert-lər bağlanardı. Komandaya xəbər verin"; fi
  PRE=$(git status --porcelain -- docs/feedback 2>/dev/null)
  TN=$(wpy -m tools.tuner | grep -E "qərar:" | tail -1 | sed 's/^- //')
  # tuner həmişə docs/feedback/proposal-<tarix>.md yazır: yoxlama repoda iz qoymasın
  git status --porcelain -- docs/feedback 2>/dev/null | while read -r ST F; do
    echo "$PRE" | grep -qF " $F" && continue
    if [ "$ST" = "??" ]; then rm -f "$F"; else git checkout -q -- "$F"; fi
  done
  [ -n "$TN" ] && ok "Tuner işləyir (--apply olmadan): $TN" tuner || bad "Tuner işləmədi" tuner "docker compose exec worker python -m tools.tuner"
fi
info "Əl ilə: tuner PR-ı (tuner/<tarix> branch-ı) komanda tərəfindən review olunub? (runbook 5.4)"

# =================================================================== 7. Testlər
section "7 · Testlər (5.4)"
MISSING=""
for F in tests/unit/test_correlation.py tests/unit/test_feedback_loop.py tests/unit/test_feedback_collector.py \
         tests/unit/test_replay.py tests/unit/test_tuner.py tests/unit/test_demo_alerts.py; do
  [ -f "$F" ] || MISSING="$MISSING $F"
done
[ -z "$MISSING" ] && ok "Phase 5 test faylları yerindədir" files || bad "Yoxdur:$MISSING" files "git pull"
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
if [ $FAILN -eq 0 ]; then printf '\033[32mPhase 5 bu kompüterdə tam işləyir: rəy, replay, tuner və korrelyasiya.\033[0m\n'
else printf '\033[31mFAIL olan sətirlərin altındakı → göstərişə əməl edin.\033[0m\n'; fi
printf '\nQrupa göndərmək üçün:\nP5EXIT %s |%s\n' "${WHO:-?}" "$SUMMARY"
[ $FAILN -eq 0 ]
