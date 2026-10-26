#!/usr/bin/env bash
# alert2case mühit yoxlaması: hər sətir OK olmalıdır
FAIL=0
ok()   { printf '  \033[32mOK  \033[0m %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=1; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$1"; }
check() {  # check "ad" əmr...
  local name="$1"; shift
  local out
  if out=$("$@" 2>&1); then ok "$name: $(printf '%s' "$out" | head -1)"
  else bad "$name: $(printf '%s' "$out" | head -1)"; fi
}

echo "== Alətlər"
check git      git --version
check curl     bash -c 'curl --version | head -1'
check make     bash -c 'make --version | head -1'
check jq       jq --version
check openssl  openssl version
check uv       uv --version
check "python 3.12" uv python find 3.12

echo "== Docker"
check docker   docker --version
check compose  docker compose version
check "docker daemon" docker info --format 'server {{.ServerVersion}}'
check "hello-world" bash -c 'docker run --rm hello-world | grep -m1 "Hello from Docker"'

echo "== Git və GitHub"
check "git user.name"  git config --global user.name
check "git user.email" git config --global user.email
check "git autocrlf=input" bash -c '[ "$(git config --global core.autocrlf)" = input ] && echo input'
check "github ssh" bash -c 'ssh -T -o BatchMode=yes -o ConnectTimeout=10 git@github.com 2>&1 | grep -o "Hi [^!]*"'

echo "== Mühit"
if grep -qi microsoft /proc/version 2>/dev/null; then
  ok "WSL aşkarlandı"
  case "$PWD" in /mnt/*) warn "cari qovluq /mnt/ altındadır, layihəni ~/projects altında saxlayın";; esac
fi
if command -v free >/dev/null; then
  mem=$(free -g | awk '/^Mem:/{print $2}')
  [ "${mem:-0}" -ge 7 ] && ok "RAM: ${mem} GB görünür" || warn "RAM: ${mem} GB görünür (TheHive üçün azdır)"
fi

echo
[ "$FAIL" -eq 0 ] && echo "NƏTİCƏ: hazırsınız" || echo "NƏTİCƏ: FAIL sətirlərini düzəldin"
exit "$FAIL"
