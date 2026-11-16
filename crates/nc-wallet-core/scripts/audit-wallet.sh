#!/usr/bin/env bash
# The dependency audit for Nowcoin Omega: the RustSec advisories that reach the wallet's own code.
#
# `cargo audit` reads the workspace's Cargo.lock, which also holds crates only the tests use (k256 0.13, which checks
# signatures independently of the signing path). An advisory there says nothing about the shipped engine, yet it turns
# the plain audit red whatever the engine holds, so a red audit stops meaning anything for a release. This lists the crates the wallet is built
# from: the normal (not dev, not build) dependencies of nc-wallet-ffi, the Android app's library, and of
# nc-wallet-wasm, the extension's engine, for each target they are built for. It fails when an advisory names one of
# them at the version the lock holds. A vulnerability fails, and so do the warnings that a crate is unsound or that a
# version was yanked, unless the advisory is in ALLOWED below with the date and the reason. A plain `cargo audit`
# still reports every advisory in the workspace.
#
#   crates/nc-wallet-core/scripts/audit-wallet.sh              the wallet's audit (cargo audit fetches its database)
#   crates/nc-wallet-core/scripts/audit-wallet.sh --self-test  the script's own check: a hit fails, a miss passes
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"

# Advisories allowed in the wallet's graph, one per line: "ID  YYYY-MM-DD  why". None at present.
ALLOWED=()

TARGETS=(wasm32-unknown-unknown aarch64-linux-android armv7-linux-androideabi)

# "name version" for every crate the wallet is built from, one per line.
wallet_graph() {
  for target in "${TARGETS[@]}"; do
    cargo tree --locked -e normal -p nc-wallet-ffi -p nc-wallet-wasm --target "$target" --prefix none --format '{p}'
  done | awk '{ v = $2; sub(/^v/, "", v); print $1 " " v }' | sort -u
}

# cargo audit's JSON report on stdin; out: "name version<TAB>id<TAB>kind<TAB>title" for each advisory that fails.
advisories() {
  jq -r '
    [ (.vulnerabilities.list // [])[]
        | {id: .advisory.id, kind: "vulnerability", p: .package, title: .advisory.title} ]
    + [ (.warnings // {}) | to_entries[] | select(.key == "unsound" or .key == "yanked") | .value[]
        | {id: (.advisory.id // "yanked"), kind: .kind, p: .package,
           title: (.advisory.title // "a yanked version")} ]
    | .[] | "\(.p.name) \(.p.version)\t\(.id)\t\(.kind)\t\(.title)"'
}

allowed() {
  local entry
  for entry in "${ALLOWED[@]}"; do
    [[ "${entry%% *}" == "$1" ]] && return 0
  done
  return 1
}

# $1: cargo audit's JSON report; $2: the wallet's graph. Says what reaches the wallet; fails if any is not allowed.
check() {
  local report=$1 graph=$2 failed=0 package id kind title
  while IFS=$'\t' read -r package id kind title; do
    [[ -n "$package" ]] || continue
    grep -qxF "$package" <<<"$graph" || continue
    if allowed "$id"; then
      echo "allowed in the wallet: $package, $id ($kind): $title"
    else
      echo "IN THE WALLET: $package, $id ($kind): $title"
      failed=1
    fi
  done < <(advisories <<<"$report")
  return "$failed"
}

# A report with one advisory of `kind` (vulnerability or unsound) against `name` at `version`.
fixture() {
  local kind=$1 name=$2 version=$3
  jq -n --arg kind "$kind" --arg name "$name" --arg version "$version" '
    {id: "RUSTSEC-0000-0000", title: "a fixture"} as $advisory
    | {name: $name, version: $version} as $package
    | if $kind == "vulnerability"
      then {vulnerabilities: {found: true, count: 1, list: [{advisory: $advisory, package: $package}]}, warnings: {}}
      else {vulnerabilities: {found: false, count: 0, list: []},
            warnings: {($kind): [{kind: $kind, advisory: $advisory, package: $package}]}}
      end'
}

if [[ "${1:-}" == "--self-test" ]]; then
  graph=$(wallet_graph)
  # The wallet's crypto-bigint is 0.7 (k256 0.14); the tests' 0.5.5 is not in the wallet.
  bigint=$(grep -m1 '^crypto-bigint 0\.7\.' <<<"$graph" || true)
  [[ -n "$bigint" ]] || { echo "self-test: the wallet's graph has no crypto-bigint 0.7"; exit 1; }
  if check "$(fixture vulnerability crypto-bigint "${bigint#* }")" "$graph" >/dev/null; then
    echo "self-test: an advisory against the wallet's $bigint passed"
    exit 1
  fi
  if ! check "$(fixture vulnerability crypto-bigint 0.5.5)" "$graph" >/dev/null; then
    echo "self-test: an advisory against crypto-bigint 0.5.5, which only the tests use, failed"
    exit 1
  fi
  if check "$(fixture unsound "${bigint%% *}" "${bigint#* }")" "$graph" >/dev/null; then
    echo "self-test: an unsound warning against the wallet's $bigint passed"
    exit 1
  fi
  if check "$(fixture unmaintained "${bigint%% *}" "${bigint#* }")" "$graph" >/dev/null; then
    :
  else
    echo "self-test: an unmaintained notice, which is reported but not a failure, failed"
    exit 1
  fi
  echo "self-test: ok ($(wc -l <<<"$graph") crates in the wallet's graph)"
  exit 0
fi

graph=$(wallet_graph)
# cargo audit exits 1 when it finds anything in the workspace; the report is what is read.
report=$(cargo audit --json 2>/dev/null || true)
if ! jq -e '.vulnerabilities' >/dev/null 2>&1 <<<"$report"; then
  echo "cargo audit gave no report (is the advisory database reachable?)"
  exit 2
fi
echo "The wallet is built from $(wc -l <<<"$graph") crates."
if check "$report" "$graph"; then
  echo "No advisory reaches the wallet. (Vulnerabilities in the whole workspace: $(jq '.vulnerabilities.count' <<<"$report"); cargo audit lists them.)"
else
  echo "An advisory reaches the wallet: update the crate, or allow it in $0 with the date and why."
  exit 1
fi
