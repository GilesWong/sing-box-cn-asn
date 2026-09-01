#!/bin/bash
# Update CN-ASN ruleset for sing-box by downloading the latest GitHub release asset.
# Deploys atomically, restarts sing-box, verifies health, rolls back on failure.
# Needs only curl + docker compose on the target machine.
#
# Overrides via environment: GITHUB_REPO, BASE, SINGBOX_CONTAINER, HEALTH_PORT
set -o pipefail

GITHUB_REPO=${GITHUB_REPO:-GilesWong/sing-box-cn-asn}
BASE=${BASE:-/root/compose/sing-box}
CONTAINER=${SINGBOX_CONTAINER:-sing-box}
HEALTH_PORT=${HEALTH_PORT:-51899}
OUT=$BASE/rulesets/cn-asn.json
LOCK=/tmp/cn-asn.lock
LOG=$BASE/rulesets/update.log
DL=https://github.com/$GITHUB_REPO/releases/latest/download

exec >>"$LOG" 2>&1
echo "=== update start $(date -Is) ==="

exec 9>"$LOCK"
flock -n 9 || { echo "another update is running, skip"; exit 0; }

command -v curl >/dev/null || { echo "FATAL: curl not found"; exit 1; }
mkdir -p "$BASE/rulesets"

OLD_SIZE=$(stat -c %s "$OUT" 2>/dev/null || echo 0)
if [ "$OLD_SIZE" -gt 0 ]; then cp "$OUT" "$OUT.prev"; fi

TMP=$OUT.new
curl -fsSL --retry 3 --connect-timeout 15 -o "$TMP" "$DL/cn-asn.json" || {
    echo "download failed, keeping previous ruleset, no restart"
    exit 1
}

EXPECT=$(curl -fsSL --retry 3 --connect-timeout 15 "$DL/cn-asn.json.sha256" | awk '{print $1}')
GOT=$(sha256sum "$TMP" 2>/dev/null | awk '{print $1}')
if [ -z "$EXPECT" ] || [ "$EXPECT" != "$GOT" ]; then
    echo "checksum mismatch (expect=$EXPECT got=$GOT), keeping previous ruleset, no restart"
    rm -f "$TMP"
    exit 1
fi

if [ "$OLD_SIZE" -gt 0 ]; then
    OLD_SUM=$(sha256sum "$OUT" | awk '{print $1}')
    if [ "$GOT" = "$OLD_SUM" ]; then
        echo "ruleset unchanged, skip restart"
        rm -f "$TMP" "$OUT.prev"
        echo "=== update done $(date -Is) ==="
        exit 0
    fi
fi

mv "$TMP" "$OUT"
echo "ruleset updated: $OLD_SIZE -> $(stat -c %s "$OUT") bytes, restarting sing-box"

docker compose -f "$BASE/compose.yml" restart sing-box || {
    echo "FATAL: docker restart failed"; exit 1;
}

sleep 5
if docker ps --filter name="$CONTAINER" --filter status=running | grep -q "$CONTAINER" \
   && ss -tln | grep -q ":$HEALTH_PORT " \
   && ! docker logs "$CONTAINER" --since 2m 2>&1 | grep -q FATAL; then
    echo "healthy after restart, update complete"
    rm -f "$OUT.prev"
    echo "=== update done $(date -Is) ==="
    exit 0
fi

echo "health check FAILED, rolling back ruleset and restarting"
if [ -f "$OUT.prev" ]; then mv "$OUT.prev" "$OUT"; fi
docker compose -f "$BASE/compose.yml" restart sing-box
echo "rollback done, MANUAL INVESTIGATION NEEDED"
exit 1
