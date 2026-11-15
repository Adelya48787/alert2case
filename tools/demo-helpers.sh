# alert2case · təqdimat köməkçiləri (runbook üçün qısa əmrlər)
#
#   cd ~/projects/alert2case && source tools/demo-helpers.sh
#
# Hər yeni terminalda bir dəfə "source" edin. Admin token dəyişənə oxunur, ekrana çıxmır.
# Əmrlərin siyahısı üçün: a2c

if [ ! -f docker-compose.yml ] || [ ! -d app ]; then
  echo "Repo qovluğundan source edin: cd ~/projects/alert2case && source tools/demo-helpers.sh"
  return 1 2>/dev/null || exit 1
fi

T=$(grep -E '^ADMIN_TOKEN=' .env | cut -d= -f2-)
PYV=.venv/bin/python

# --- alert göndərmək
sim()   { $PYV tools/simulator.py "$@"; }                          # dataset/raw: sim --only HASH-02
demo()  { $PYV tools/simulator.py --dataset dataset/demo "$@"; }   # dataset/demo: demo --only DEMO-C1-A
n8n()   { $PYV tools/send_n8n.py "$@"; }                           # n8n yolu: n8n --only HASH-02

# --- təmiz başlanğıc: alert, case, audit, korrelyasiya silinir; intel cache qalır (VT limiti xərclənmir)
fresh() {
  local out
  if out=$(make -s reset-keep-cache 2>&1); then
    echo "Təmiz başlanğıc: alert-lər silindi, intel cache qaldı. (TheHive-dakı köhnə case-lər qalır)"
  else
    echo "fresh alınmadı (konteynerlər işləyirmi? make ps):"; printf '%s\n' "$out" | tail -5; return 1
  fi
}

# --- baxmaq
q()     { docker compose exec -T postgres psql -U soc -d alert2case -c "$1"; }
cnt()   { q "SELECT count(*) AS alert_sayi FROM alerts"; }
last()  { q "SELECT left(alert_id::text,8) AS alert, source_ref, alert_type, occurrence_count AS say, status, to_char(received_at AT TIME ZONE 'Asia/Baku','HH24:MI:SS') AS vaxt FROM alerts ORDER BY received_at DESC LIMIT ${1:-5}"; }
dec()   { q "SELECT a.source_ref, d.rule_id, d.verdict, d.priority, d.action, d.shadow, a.doc->'enrichment'->>'status' AS enrichment FROM alerts a JOIN decisions d USING (alert_id) ORDER BY d.decided_at DESC LIMIT ${1:-5}"; }
why()   { q "SELECT jsonb_array_elements_text(d.reasons) AS sebebler FROM alerts a JOIN decisions d USING (alert_id) WHERE a.source_ref='$1' ORDER BY d.decided_at DESC LIMIT 20"; }
intel() { q "SELECT p->>'provider' AS provider, p->>'ioc_type' AS ioc, p->>'status' AS status, p->>'score' AS skor, p->>'cached' AS cache FROM alerts a, jsonb_array_elements(a.doc->'enrichment'->'providers') p WHERE a.source_ref='$1'"; }
corr()  { q "SELECT to_char(ts AT TIME ZONE 'Asia/Baku','HH24:MI:SS') AS vaxt, stage, event, payload FROM audit_log WHERE stage IN ('correlate','act') AND event IN ('same_ioc','same_user','host_chain','bruteforce_campaign','bruteforce_link','case_linked') ORDER BY id DESC LIMIT 15"; }
tl() {
  local id
  id=$(docker compose exec -T postgres psql -U soc -d alert2case -tAc "SELECT alert_id FROM alerts WHERE source_ref='$1' ORDER BY received_at DESC LIMIT 1" | tr -d '[:space:]')
  [ -n "$id" ] || { echo "$1 tapılmadı (dublikat ola bilər və ya hələ emal olunmayıb)"; return 1; }
  curl -s -H "X-Admin-Token: $T" "localhost:8000/alerts/$id/timeline" \
    | $PYV -c "import json,sys; [print(f\"+{e['t_plus_s']:>7.2f} s  {e['stage']:<10} {e['event']}\") for e in json.load(sys.stdin)]"
}
queues() {
  docker compose exec -T redis redis-cli XINFO GROUPS alerts.in | paste - - | grep -E "^(pending|lag)" | sed 's/^/alerts.in  /'
  echo "alerts.dlq $(docker compose exec -T redis redis-cli XLEN alerts.dlq)"
  echo "cases.dlq  $(docker compose exec -T redis redis-cli XLEN cases.dlq)"
}
dlq()   { curl -s -H "X-Admin-Token: $T" "localhost:8000/dlq" | $PYV -m json.tool; }
fb()    { q "SELECT source, auto_verdict, human_verdict, rule_id, to_char(created_at AT TIME ZONE 'Asia/Baku','HH24:MI:SS') AS vaxt FROM feedback ORDER BY id DESC LIMIT 3"; }
auditok() { docker compose exec -T api python -m tools.verify_audit; }
token() { [ -n "$T" ] || { echo "ADMIN_TOKEN .env-də boşdur"; return 1; }; printf %s "$T" | clip.exe && echo "Admin token panoya kopyalandı (ekrana çıxmadı). Paneldə Ctrl+V."; }

# --- xüsusi hallar
kod()   { curl -s -o /dev/null -w "cavab: %{http_code}\n" "$@"; }
big()   { head -c 300000 /dev/zero | tr '\0' 'A' | curl -s -o /dev/null -w "cavab: %{http_code}\n" -X POST --data-binary @- -H "Content-Type: application/json" localhost:8000/ingest/edr; }
badjson() {
  $PYV - <<'PY'
import hashlib, hmac, os
import httpx
from dotenv import load_dotenv
load_dotenv()
body = b"not-json"
sig = "sha256=" + hmac.new(os.environ["WEBHOOK_HMAC_SECRET"].encode(), body, hashlib.sha256).hexdigest()
r = httpx.post("http://localhost:8000/ingest/edr", content=body, headers={"X-Signature": sig})
print("cavab:", r.status_code)
PY
}
vtclear() { n=$(docker compose exec -T redis sh -c "redis-cli --scan --pattern 'intel:v1:virustotal:*' | xargs -r redis-cli DEL" | tr -d '[:space:]'); echo "Silinən VT cache açarı: ${n:-0}"; }

a2c() {
  cat <<'TXT'
Göndər:  sim --only HASH-02 · demo --only DEMO-C1-A · n8n --only HASH-02 · fresh
Bax:     last · dec · why HASH-02 · intel HASH-02 · tl HASH-02 · corr · queues · dlq · fb · cnt · auditok
Xüsusi:  kod -X POST localhost:8000/ingest/firewall · big · badjson · vtclear · token
TXT
}
echo "alert2case köməkçiləri yükləndi. Siyahı: a2c"
