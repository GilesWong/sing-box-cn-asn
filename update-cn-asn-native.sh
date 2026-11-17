#!/bin/bash
# Native (systemd) CN-ASN ruleset updater for sing-box.
# Downloads the latest GitHub release, validates it against a temporary copy
# of the config, installs it atomically, and rolls back if the service fails.
set -euo pipefail

GITHUB_REPO=${GITHUB_REPO:-GilesWong/sing-box-cn-asn}
BASE=${BASE:-/etc/sing-box}
SERVICE=${SINGBOX_SERVICE:-sing-box}
HEALTH_PORTS=${HEALTH_PORTS:-"28345 28346"}
DRY_RUN=${DRY_RUN:-0}

OUT="$BASE/rulesets/cn-asn.json"
TMP="$OUT.new"
PREV="$OUT.prev"
LOCK=${LOCK:-/run/lock/sing-box-cn-asn.lock}
DL="https://github.com/$GITHUB_REPO/releases/latest/download"
CHECK_DIR=""

log() { printf '%s %s\n' "$(date -Is)" "$*"; }
die() { log "ERROR: $*"; exit 1; }
cleanup() {
    if [ -n "$CHECK_DIR" ]; then
        rm -rf "$CHECK_DIR"
    fi
    return 0
}
trap cleanup EXIT

restore_previous() {
    if [ -f "$PREV" ]; then
        mv -f "$PREV" "$OUT"
        systemctl restart "$SERVICE" || log "ERROR: rollback restart failed"
    else
        log "ERROR: no previous ruleset available for rollback"
    fi
    return 0
}

command -v curl >/dev/null || die "curl not found"
command -v sha256sum >/dev/null || die "sha256sum not found"
command -v sing-box >/dev/null || die "sing-box not found"
command -v python3 >/dev/null || die "python3 not found"
command -v runuser >/dev/null || die "runuser not found"
command -v systemctl >/dev/null || die "systemctl not found"
systemctl cat "$SERVICE" >/dev/null 2>&1 || die "service $SERVICE not found"
[ -f "$BASE/config.json" ] || die "$BASE/config.json not found"

mkdir -p "$(dirname "$LOCK")"
exec 9>"$LOCK"
flock -n 9 || { log "another update is running, skip"; exit 0; }

mkdir -p "$BASE/rulesets"
chown root:sing-box "$BASE/rulesets" 2>/dev/null || true
chmod 0750 "$BASE/rulesets" 2>/dev/null || true

log "downloading $DL/cn-asn.json"
curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
    -o "$TMP" "$DL/cn-asn.json" || die "download failed"
EXPECT=$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 30 \
    "$DL/cn-asn.json.sha256" | awk '{print $1}') || die "checksum download failed"
GOT=$(sha256sum "$TMP" | awk '{print $1}')
[ -n "$EXPECT" ] && [ "$EXPECT" = "$GOT" ] || {
    rm -f "$TMP"
    die "checksum mismatch (expect=$EXPECT got=$GOT)"
}

LAST_MODIFIED=$(curl -fsSIL --connect-timeout 8 --max-time 20 \
    "$DL/cn-asn.json" 2>/dev/null \
    | awk -F': ' 'tolower($1)=="last-modified"{print $2}' \
    | tr -d '\r' | tail -n1 || true)
if [ -n "$LAST_MODIFIED" ]; then
    LM_EPOCH=$(date -d "$LAST_MODIFIED" +%s 2>/dev/null || true)
    if [ -n "$LM_EPOCH" ]; then
        AGE=$(( $(date +%s) - LM_EPOCH ))
        [ "$AGE" -le 259200 ] || \
            log "WARN: latest release is $((AGE / 86400)) days old ($LAST_MODIFIED); GitHub Actions may be stalled"
    fi
fi

if [ -f "$OUT" ]; then
    OLD_SUM=$(sha256sum "$OUT" | awk '{print $1}')
    if [ "$GOT" = "$OLD_SUM" ]; then
        rm -f "$TMP"
        log "ruleset unchanged ($GOT), skip restart"
        exit 0
    fi
else
    rm -f "$PREV"
fi

chown root:sing-box "$TMP"
chmod 0640 "$TMP"

CHECK_DIR=$(mktemp -d /run/sing-box-cn-asn-check.XXXXXX)
chmod 0750 "$CHECK_DIR"
chown root:sing-box "$CHECK_DIR"
python3 - "$BASE/config.json" "$TMP" "$CHECK_DIR/config.json" <<'PY'
import json
import sys

src, ruleset, dst = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src, encoding="utf-8") as f:
    config = json.load(f)

found = False
for entry in config.get("route", {}).get("rule_set", []):
    if entry.get("tag") == "asn-cn":
        entry["type"] = "local"
        entry["format"] = "source"
        entry["path"] = ruleset
        entry.pop("url", None)
        entry.pop("download_detour", None)
        entry.pop("update_interval", None)
        found = True
        break
if not found:
    raise SystemExit("asn-cn rule_set not found; apply the config patch first")

with open(dst, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
PY
chown root:sing-box "$CHECK_DIR/config.json"
chmod 0640 "$CHECK_DIR/config.json"
runuser -u sing-box -- sing-box check -c "$CHECK_DIR/config.json" || {
    rm -f "$TMP"
    die "sing-box check failed for staged ruleset"
}
rm -rf "$CHECK_DIR"
CHECK_DIR=""

if [ "$DRY_RUN" = "1" ]; then
    rm -f "$TMP"
    log "DRY_RUN complete; staged ruleset is valid, not installed"
    exit 0
fi

if [ -f "$OUT" ]; then
    cp -a "$OUT" "$PREV"
fi
log "installing $OUT"
mv -f "$TMP" "$OUT"

START_EPOCH=$(date +%s)
systemctl restart "$SERVICE" || {
    log "restart failed, restoring previous ruleset"
    restore_previous
    exit 1
}

healthy=0
for _ in $(seq 1 10); do
    sleep 2
    systemctl is-active --quiet "$SERVICE" || continue
    ok=1
    for port in $HEALTH_PORTS; do
        if ! ss -H -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$port$"; then
            ok=0
            break
        fi
    done
    if [ "$ok" = "1" ]; then
        healthy=1
        break
    fi
done

if [ "$healthy" != "1" ]; then
    log "health check failed (service inactive or ports missing), restoring previous ruleset"
    restore_previous
    exit 1
fi

if journalctl -u "$SERVICE" --since "@$START_EPOCH" --no-pager -o cat 2>/dev/null \
    | grep -Eiq 'FATAL|panic'; then
    log "FATAL/panic in journal after restart, restoring previous ruleset"
    restore_previous
    exit 1
fi

rm -f "$PREV"
log "ruleset updated and service healthy: $(stat -c %s "$OUT") bytes"
