#!/usr/bin/env bash
# alert2case · production image yoxlaması (Task 6.5)
# Repo qovluğunda, `make up-prod`-dan sonra işlədilir:
#   tools/prod_check.sh
# Nə edir: image-in məzmununu (root olmayan istifadəçi, sirr və test faylı yoxdur), container-lərin
# sərtləşdirilməsini (read-only, cap_drop, no-new-privileges, kod mount olunmur) və bir alert-in
# prod worker-dən keçdiyini yoxlayır. Bir demo alert göndərir (real intel API-yə 1-3 sorğu).
# Kodu, .env-i və repo fayllarını dəyişmir. Açarlar ekrana çıxmır.

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
DC="docker compose -f docker-compose.yml -f docker-compose.prod.yml"
IMG="alert2case:${APP_VERSION:-1.0.0}"
# </dev/null: docker compose exec stdin-i oxuyur
dex()    { $DC exec -T "$1" sh -c "$2" </dev/null 2>&1; }
psql_q() { $DC exec -T postgres psql -U soc -d alert2case -tAc "$1" </dev/null 2>/dev/null | tr -d '[:space:]'; }

printf '\033[1malert2case · production image yoxlaması (6.5)\033[0m\n'
printf 'Image: %s · Tarix: %s\n' "$IMG" "$(date '+%Y-%m-%d %H:%M')"

# =================================================================== 1. Alətlər
section "1 · Alətlər"
if ! docker info >/dev/null 2>&1; then bad "Docker işləmir" docker "Docker Desktop-u açın"; exit 1; fi
CV=$(docker compose version --short 2>/dev/null | sed 's/^v//')
if [ -n "$CV" ] && [ "$(printf '%s\n2.24.0\n' "$CV" | sort -V | head -1)" = "2.24.0" ]; then
  ok "Docker Compose $CV (2.24+ lazımdır: !override)" compose
else bad "Docker Compose ${CV:-?}: 2.24-dən köhnədir" compose "Docker Desktop-u yeniləyin"; fi
for F in Dockerfile docker-compose.prod.yml .dockerignore; do
  [ -f "$F" ] || bad "$F yoxdur" files "git pull"
done
[ -f Dockerfile ] && [ -f docker-compose.prod.yml ] && [ -f .dockerignore ] && ok "Dockerfile, docker-compose.prod.yml, .dockerignore yerindədir" files
$DC config -q 2>/dev/null && ok "Prod compose konfiqurasiyası etibarlıdır" config \
  || bad "docker compose config xəta verir" config "$DC config | head"

# =================================================================== 2. Image
section "2 · Image"
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  bad "$IMG image-i yoxdur" image "make up-prod"
else
  SIZE=$(docker image inspect "$IMG" --format '{{.Size}}')
  MB=$((SIZE / 1024 / 1024))
  [ "$MB" -lt 500 ] && ok "Image ölçüsü: $MB MB" size || warn "Image ölçüsü: $MB MB (500 MB-dan böyük)" size ".dockerignore və COPY sətirlərini yoxlayın"
  UID_=$(docker run --rm --entrypoint id "$IMG" -u 2>/dev/null)
  [ "$UID_" = "10001" ] && ok "Proses root olmayan istifadəçi ilə işləyir (uid 10001)" nonroot \
    || bad "Image-in istifadəçisi: uid ${UID_:-?}" nonroot "Dockerfile-da USER app sətrini yoxlayın"
  LS=$(docker run --rm --entrypoint sh "$IMG" -c 'ls -A /app' 2>/dev/null | tr '\n' ' ')
  info "/app: $LS"
  LEAK=""
  for X in .env .git tests dataset docs tools .venv; do
    docker run --rm --entrypoint sh "$IMG" -c "test -e /app/$X" 2>/dev/null && LEAK="$LEAK $X"
  done
  [ -z "$LEAK" ] && ok "Image-də .env, .git, tests, dataset, docs, tools, .venv yoxdur" noleak \
    || bad "Image-də olmamalı olanlar var:$LEAK" noleak ".dockerignore və Dockerfile-dakı COPY sətirləri"
  NEED=""
  for X in app rules context migrations alembic.ini var/cases; do
    docker run --rm --entrypoint sh "$IMG" -c "test -e /app/$X" 2>/dev/null || NEED="$NEED $X"
  done
  [ -z "$NEED" ] && ok "İşləmək üçün lazım olanlar yerindədir (app, rules, context, migrations)" need \
    || bad "Image-də çatışmır:$NEED" need "Dockerfile-dakı COPY sətirləri"
fi

# =================================================================== 3. Container-lər
section "3 · Container-lər"
SVC_OK=1
for S in api worker; do
  H=""
  for _ in $(seq 1 30); do
    H=$($DC ps --format '{{.Service}} {{.Health}}' 2>/dev/null | awk -v s="$S" '$1==s{print $2}')
    [ "$H" = "healthy" ] && break
    [ "$H" = "unhealthy" ] && break
    sleep 3
  done
  [ "$H" = "healthy" ] && ok "$S: healthy" "svc_$S" || { bad "$S: ${H:-işləmir}" "svc_$S" "$DC logs $S --tail 30"; SVC_OK=0; }
done
if [ $SVC_OK -eq 1 ]; then
  for S in api worker; do
    CID=$($DC ps -q "$S" 2>/dev/null)
    IMGS=$(docker inspect "$CID" --format '{{.Config.Image}}' 2>/dev/null)
    RO=$(docker inspect "$CID" --format '{{.HostConfig.ReadonlyRootfs}}' 2>/dev/null)
    CAP=$(docker inspect "$CID" --format '{{.HostConfig.CapDrop}}' 2>/dev/null)
    SEC=$(docker inspect "$CID" --format '{{.HostConfig.SecurityOpt}}' 2>/dev/null)
    U=$(dex "$S" 'id -u')
    if [ "$IMGS" = "$IMG" ] && [ "$RO" = "true" ] && echo "$CAP" | grep -q ALL && echo "$SEC" | grep -q no-new-privileges && [ "$U" = "10001" ]; then
      ok "$S: prod image, read-only, cap_drop ALL, no-new-privileges, uid 10001" "hard_$S"
    else
      bad "$S: image=$IMGS read_only=$RO cap_drop=$CAP security=$SEC uid=$U" "hard_$S" "make up-prod"
    fi
    dex "$S" 'test -e /code' >/dev/null && bad "$S: /code mövcuddur (dev mount qalıb)" "mount_$S" "make up-prod" \
      || ok "$S: kod mount olunmur (/code yoxdur)" "mount_$S"
  done
  W1=$(dex worker 'touch /app/x 2>&1 && echo yazdı || echo yazmadı' | tail -1)
  W2=$(dex worker 'touch /app/var/.w && rm /app/var/.w && echo yazdı || echo yazmadı' | tail -1)
  W3=$(dex worker 'touch /tmp/.w && rm /tmp/.w && echo yazdı || echo yazmadı' | tail -1)
  if [ "$W1" = "yazmadı" ] && [ "$W2" = "yazdı" ] && [ "$W3" = "yazdı" ]; then
    ok "Yazma yalnız /app/var (volume) və /tmp-yə mümkündür" rofs
  else bad "Yazma testi: /app=$W1, /app/var=$W2, /tmp=$W3" rofs "case_files volume köhnədirsə: docker volume rm alert2case_case_files"; fi
fi

# =================================================================== 4. Bir alert prod worker-dən keçir
section "4 · Bir alert prod worker-dən keçir"
if [ $SVC_OK -ne 1 ]; then warn "Container-lər healthy olmadığı üçün yoxlanmadı" flow
elif [ ! -x "$PY" ]; then warn ".venv yoxdur, alert göndərilmədi" flow "python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt"
else
  REF=DEMO-C1-A
  T0=$(psql_q "select extract(epoch from now())")
  OUT=$($PY tools/simulator.py --dataset dataset/demo --only "$REF" --rate 1 2>&1 | tail -1)
  if ! echo "$OUT" | grep -q "gözlənilən cavab (202): 1"; then bad "API alert-i qəbul etmədi" flow "$DC logs api --tail 30"
  else
    # Gözləmə: ya "act" mərhələsi (yeni alert, tam yol), ya da "duplicate" hadisəsi (dedup) görünənə qədər.
    # Yalnız "normalize" görünəndə dayanmırıq: o, yeni alert-də də yolun ortasıdır.
    EV=""; DUP=""
    for _ in $(seq 1 60); do
      EV=$(psql_q "select string_agg(distinct l.stage, ',') from audit_log l join alerts a on a.alert_id = l.correlation_id
                   where a.source_ref = '$REF' and l.ts > to_timestamp($T0)")
      DUP=$(psql_q "select count(*) from audit_log l join alerts a on a.alert_id = l.correlation_id
                    where a.source_ref = '$REF' and l.ts > to_timestamp($T0) and l.event = 'duplicate'")
      echo "$EV" | grep -q act && break
      [ "${DUP:-0}" != "0" ] && break
      sleep 3
    done
    if echo "$EV" | grep -q act; then ok "Alert prod worker-dən keçdi və hərəkət mərhələsinə çatdı (audit: $EV)" flow
    elif [ "${DUP:-0}" != "0" ]; then ok "Alert prod worker tərəfindən emal olundu (dublikat sayıldı, audit: $EV)" flow
      info "Tam yol üçün: make reset-data, sonra skripti təkrar işlədin"
    else bad "Alert 3 dəqiqədə hərəkət mərhələsinə çatmadı (audit: ${EV:-yoxdur})" flow "$DC logs worker --tail 30"; fi
    NC=$(dex worker 'ls /app/var/cases 2>/dev/null | wc -l' | tr -d '[:space:]')
    [ "${NC:-0}" -gt 0 ] 2>/dev/null && ok "Case faylları volume-dadır: /app/var/cases ($NC fayl)" casefiles \
      || warn "/app/var/cases boşdur" casefiles "CASE_BACKEND=thehive-dirsə, normaldır"
  fi
fi
TB=$($DC logs worker api --since 10m 2>/dev/null | grep -cE "Traceback|Read-only file system|PermissionError")
[ "$TB" = "0" ] && ok "Son 10 dəqiqədə Traceback, Read-only və PermissionError yoxdur" traceback \
  || bad "Loglarda $TB xəta sətri var" traceback "$DC logs worker api --since 10m | grep -B3 -E 'Traceback|Read-only|PermissionError'"

# =================================================================== Nəticə
printf '\n\033[1mNƏTİCƏ: %s OK · %s FAIL · %s WARN\033[0m\n' "$PASS" "$FAILN" "$WARNN"
if [ "$FAILN" -eq 0 ]; then printf '\033[32mProduction image hazırdır.\033[0m Dev-ə qayıtmaq: make down-prod\n'
else printf '\033[31mFAIL olan sətirlərin altındakı → göstərişə əməl edin.\033[0m\n'; fi
printf '\nPRODCHECK %s |%s\n' "$(git config user.name 2>/dev/null || echo ?)" "$SUMMARY"
[ "$FAILN" -eq 0 ]
