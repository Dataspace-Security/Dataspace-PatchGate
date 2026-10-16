#!/usr/bin/env bash
# Secret + artifact audit of the PatchGate tree, WITHOUT touching the real tree's git state.
#
#   release/audit-tree.sh            # summary + findings (exit 1 on any HIGH finding not allow-listed)
#   release/audit-tree.sh --list     # also print every file that WOULD be committed by `git add -A`
#
# How: a scratch repository is created in $TMPDIR and pointed at this tree as its work tree
# (`git --git-dir=<tmp> --work-tree=<root> ls-files --others --exclude-standard`). That is exactly the set
# `git add -A` would stage in a fresh repository, honouring every .gitignore in the tree. No .git directory
# is ever created inside the tree. The global excludes file is ignored on purpose (a teammate's machine may
# not have it). If the tree already IS a git repository, its tracked files are scanned as well.
#
# Findings never print secret values — only "<file>:<line>  <rule>".
# Documented false positives: release/secret-scan-allowlist.txt  ("<path>:<rule>" or "<path>:*").
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOWLIST="$ROOT/release/secret-scan-allowlist.txt"
LIST=0
MAX_MB=5
for a in "$@"; do
  case "$a" in
    --list) LIST=1 ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'unknown option %s\n' "$a" >&2; exit 2 ;;
  esac
done
command -v git >/dev/null || { echo "git is required" >&2; exit 2; }

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/pg-audit.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT
git init -q "$SCRATCH/repo"
G=(git -c core.excludesFile=/dev/null -c core.quotePath=false --git-dir="$SCRATCH/repo/.git" --work-tree="$ROOT")
FILES="$SCRATCH/files.txt"
ALL="$SCRATCH/all.txt"
# Every file in the tree. Pruned for speed: .git dirs (never committed) and dependency/build dirs, which
# are verified to be ignored right below (a pruned dir that is NOT ignored fails the audit).
(cd "$ROOT" && find . \( -name node_modules -o -name '.next*' -o -name .git \) -prune -o \( -type f -o -type l \) -print) \
  | sed 's|^\./||' > "$ALL"
pruned_not_ignored="$(cd "$ROOT" && find . \( -name node_modules -o -name '.next*' \) -type d -prune -print | sed 's|^\./||; s|$|/x|' \
  | "${G[@]}" check-ignore --no-index -v -n --stdin | awk -F'\t' '$1 == "::" || $1 ~ /:!/ { sub(/\/x$/, "", $2); print $2 }')"
# check-ignore --no-index applies every .gitignore along each path, also across nested repositories.
# Not ignored = no matching pattern ("::") or the last matching pattern is a negation ("!…").
"${G[@]}" check-ignore --no-index -v -n --stdin < "$ALL" \
  | awk -F'\t' '$1 == "::" || $1 ~ /:!/ { print $2 }' | sort -u > "$FILES"
COUNT="$(wc -l < "$FILES" | tr -d ' ')"
NESTED="$(cd "$ROOT" && find . -mindepth 2 -name node_modules -prune -o -name .git -print | sed 's|^\./||; s|/\.git$||')"

printf '==> Files that would be committed by `git add -A`: %s (of %s on disk outside pruned dirs)\n' "$COUNT" "$(wc -l < "$ALL" | tr -d ' ')"
[ "$LIST" = 1 ] && sed 's/^/    /' "$FILES"
if [ -n "$pruned_not_ignored" ]; then
  printf '    FAIL  dependency/build directories NOT ignored:\n'; printf '%s\n' "$pruned_not_ignored" | sed 's/^/      /'
fi
if [ -n "$NESTED" ]; then
  printf '    WARN  nested git repositories (a root repo would store them as gitlinks and NOT commit their files;\n'
  printf '          remove or move their .git before `git init` at the root — the user decides):\n'
  printf '%s\n' "$NESTED" | sed 's/^/      /'
fi

# ------------------------------------------------------------ forbidden paths that slipped past the ignores
printf '\n==> Forbidden path check\n'
FORBIDDEN='(^|/)(node_modules|\.next[^/]*|dist|coverage|test-results|repo-data|secrets[^/]*)(/|$)|(^|/)\.env($|\.)|\.(pem|key|p12|pfx|jks|age|tar|tar\.gz|tgz|zip|msi|exe|cab)$|(^|/)(lab-users|provision)\.json$|^deploy/(secrets|backups)/|^lab/(certs/out|sandbox/generated|pc-kit/generated)/|^lab/connector/[^/]+/etc/'
ALLOWED_PATHS='^patchgate-connector/test/fixtures/(localhost\.key|localhost\.pem|test-ca\.pem)$|(^|/)\.env(\.[A-Za-z0-9_-]+)?\.example$'
bad_paths="$(grep -E "$FORBIDDEN" "$FILES" | grep -Ev "$ALLOWED_PATHS" || true)"
if [ -n "$bad_paths" ]; then
  printf '    FAIL  forbidden paths would be committed:\n'; printf '%s\n' "$bad_paths" | sed 's/^/      /'
else
  printf '    ok    no secret/build/bulky paths in the commit set\n'
fi
fixtures="$(grep -E "$ALLOWED_PATHS" "$FILES" || true)"
[ -z "$fixtures" ] || { printf '    note  allow-listed (documented test fixtures / examples):\n'; printf '%s\n' "$fixtures" | sed 's/^/      /'; }

# ------------------------------------------------------------ large files
printf '\n==> Files larger than %s MB\n' "$MAX_MB"
big=0
LIMIT=$((MAX_MB * 1024 * 1024))
while IFS=$'\t' read -r s f; do
  [ -n "$f" ] || continue
  if [ "$s" -gt "$LIMIT" ]; then printf '    WARN  %s (%s bytes)\n' "$f" "$s"; big=$((big + 1)); fi
done < <(cd "$ROOT" && tr '\n' '\0' < "$FILES" | xargs -0 stat -c $'%s\t%n' -- 2>/dev/null || true)
[ "$big" -gt 0 ] || printf '    ok    none\n'

# ------------------------------------------------------------ content scan
# rule-name|severity|extended regex   (HIGH = fails the audit unless allow-listed; REVIEW = report only)
RULES=(
  'private-key|HIGH|-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----'
  'aws-access-key|HIGH|(^|[^A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}([^A-Z0-9]|$)'
  'github-token|HIGH|(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}'
  'slack-token|HIGH|xox[abprs]-[A-Za-z0-9-]{10,}'
  'jwt|REVIEW|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
  'patchgate-secret-assignment|HIGH|(AUDIT_HMAC_KEY|AUTH_ENC_KEY(_PREVIOUS)?|WORKER_TOKEN|WSUS_TOKEN|METRICS_TOKEN|TACTICAL_API_KEY|JOB_SIGNER_TOKEN|OIDC_CLIENT_SECRET|GITHUB_TOKEN|DB_PASSWORD|POSTGRES_PASSWORD|SMTP_PASS(WORD)?|WEBHOOK_SECRET|COSIGN_PASSWORD|REGISTRY_PASSWORD)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?[A-Za-z0-9+/_.=-]{20,}'
  'password-literal|REVIEW|(password|passwd|pwd)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"'[:space:]$<{]{8,}["'"'"']'
  'url-credentials|REVIEW|[a-z][a-z0-9+.-]*://[^/:@[:space:]"'"'"']+:[^/@[:space:]"'"'"'$<{]{6,}@'
  'enrolment-code|REVIEW|(^|[^A-Z0-9-])[A-Z0-9]{4}(-[A-Z0-9]{4}){4}([^A-Z0-9-]|$)'
  'hex-secret-near-name|REVIEW|(secret|token|key|passw)[A-Za-z_]*["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?[0-9a-fA-F]{48,}'
)
# Values that are obviously placeholders / test data never count (applied to the matched line only).
PLACEHOLDER='replace[-_]|change[-_]?me|example|placeholder|your[-_]|<[a-z_-]+>|x{6,}|dummy|dev-only|test-only|redacted|\.\.\.|\$\{|\$\(|process\.env|repeat\('

allowed() { # file rule
  [ -f "$ALLOWLIST" ] || return 1
  grep -v '^[[:space:]]*#' "$ALLOWLIST" | grep -qxF -e "$1:$2" -e "$1:*"
}

printf '\n==> Content scan (%s rules, values are never printed)\n' "${#RULES[@]}"
HIGH=0; REVIEW=0; ALLOWED=0
FINDINGS="$SCRATCH/findings.txt"; : > "$FINDINGS"
SCANLIST="$SCRATCH/scan.txt"
grep -v 'package-lock\.json$' "$FILES" > "$SCANLIST" || true   # lockfiles: integrity hashes only
for r in "${RULES[@]}"; do
  name="${r%%|*}"; rest="${r#*|}"; sev="${rest%%|*}"; re="${rest#*|}"
  # One grep per rule over the whole set (-I skips binaries). Only "<file>:<line>" leaves this pipeline.
  (cd "$ROOT" && tr '\n' '\0' < "$SCANLIST" | xargs -0 grep -InHE -e "$re" -- 2>/dev/null || true) \
    | grep -viE -e "$PLACEHOLDER" \
    | awk -F: '{ a[$1] = (a[$1] == "" ? $2 : a[$1] "," $2) } END { for (f in a) print f "\t" a[f] }' \
    > "$SCRATCH/rule.txt" || true
  while IFS=$'\t' read -r f lines; do
    [ -n "$f" ] || continue
    if allowed "$f" "$name"; then ALLOWED=$((ALLOWED + 1)); continue; fi
    printf '%s\t%s\t%s:%s\n' "$sev" "$name" "$f" "$lines" >> "$FINDINGS"
    if [ "$sev" = HIGH ]; then HIGH=$((HIGH + 1)); else REVIEW=$((REVIEW + 1)); fi
  done < "$SCRATCH/rule.txt"
done
if [ -s "$FINDINGS" ]; then
  sort "$FINDINGS" | awk -F'\t' '{ printf "    %-6s %-28s %s\n", $1, $2, $3 }'
else
  printf '    ok    no findings\n'
fi

printf '\n==> Summary: %s files · HIGH %s · REVIEW %s · allow-listed %s · forbidden paths %s · large %s\n' \
  "$COUNT" "$HIGH" "$REVIEW" "$ALLOWED" "$( [ -n "$bad_paths" ] && printf '%s' "$bad_paths" | wc -l | tr -d ' ' || echo 0)" "$big"
if [ "$HIGH" -gt 0 ] || [ -n "$bad_paths" ] || [ -n "$pruned_not_ignored" ]; then
  printf 'AUDIT FAILED: ignore the file (root .gitignore) or allow-list a documented false positive in %s\n' "${ALLOWLIST#"$ROOT"/}" >&2
  exit 1
fi
printf 'AUDIT PASSED\n'
