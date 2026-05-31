#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
OUT="$ROOT/run-output"
MODE="${1:-breakin}"
CC_BIN="${CC:-gcc}"

OLD_SQLITE="$ROOT/third_party/sqlite-3.53.1"
TRUNK_SQLITE="$ROOT/third_party/sqlite-trunk"
POC="$ROOT/poc/sqlite_authorizer_xfer_poc.c"
OLD_BIN="$BUILD/sqlite-authorizer-xfer-old"
TRUNK_BIN="$BUILD/sqlite-authorizer-xfer-trunk"

mkdir -p "$BUILD" "$OUT"

build_one() {
  local srcdir="$1"
  local outbin="$2"
  "$CC_BIN" -O2 -g -DSQLITE_THREADSAFE=0 \
    -I "$srcdir" \
    "$POC" "$srcdir/sqlite3.c" \
    -ldl -lpthread -lm -o "$outbin"
}

run_mode() {
  local mode="$1"
  local old_log="$OUT/${mode}-old.log"
  local trunk_log="$OUT/${mode}-trunk.log"
  local summary="$OUT/${mode}-validation.txt"
  local old_expect=""
  local trunk_expect=""

  case "$mode" in
    breakin)
      old_expect="RESULT=VULNERABLE_REMOTE_ADMIN_BREAKIN"
      trunk_expect="RESULT=SAFE_NO_ADMIN_BREAKIN"
      ;;
    xfer)
      old_expect="RESULT=VULNERABLE_REMOTE_EXFIL"
      trunk_expect="RESULT=SAFE_NO_EXFIL"
      ;;
    vacuum)
      old_expect="RESULT=VULNERABLE_REMOTE_VACUUM_EXFIL"
      trunk_expect="RESULT=SAFE_NO_VACUUM_EXFIL"
      ;;
    *)
      echo "unknown mode: $mode" >&2
      return 2
      ;;
  esac

  "$OLD_BIN" "$mode" > "$old_log" 2>&1
  old_status=$?
  "$TRUNK_BIN" "$mode" > "$trunk_log" 2>&1
  trunk_status=$?

  {
    printf 'SQLite authorizer xfer bypass validation\n'
    printf 'mode: %s\n' "$mode"
    printf 'old-status: %d\n' "$old_status"
    printf 'trunk-status: %d\n' "$trunk_status"
    printf '\nold log:\n'
    sed -n '1,220p' "$old_log"
    printf '\ntrunk log:\n'
    sed -n '1,220p' "$trunk_log"
  } | tee "$summary"

  if [ "$old_status" -eq 3 ] \
    && [ "$trunk_status" -eq 0 ] \
    && grep -q "$old_expect" "$old_log" \
    && grep -q "$trunk_expect" "$trunk_log"; then
    printf 'validation: PASS\n'
    return 0
  fi

  printf 'validation: FAIL\n'
  return 1
}

build_one "$OLD_SQLITE" "$OLD_BIN" || exit 2
build_one "$TRUNK_SQLITE" "$TRUNK_BIN" || exit 2

if [ "$MODE" = "all" ]; then
  run_mode breakin || exit 1
  run_mode xfer || exit 1
  run_mode vacuum || exit 1
else
  run_mode "$MODE"
fi
