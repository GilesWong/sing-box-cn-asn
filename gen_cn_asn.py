#!/usr/bin/env python3
"""Generate a sing-box source-format rule-set containing every prefix
announced by routed CN ASNs.

Data pipeline:
  1. ASN list:  RIPEstat country-asns (lod=1), fallback APNIC delegated file
  2. Prefixes:  RIPEstat announced-prefixes per ASN, fallback bgpview.io
  3. Validate against previous output, then atomically replace it

Exit codes: 0 ok, 1 validation gate rejected, 2 fatal error
"""

import argparse
import concurrent.futures
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request

RIPESTAT = "https://stat.ripe.net/data"
BGPVIEW = "https://api.bgpview.io"
APNIC_DELEGATED = "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest"
UA = "cn-asn-ruleset-generator/1.0"

print_lock = threading.Lock()
rate_lock = threading.Lock()
min_interval = 0.12  # global pace ~8 req/s across all workers
_last_req = [0.0]


def log(msg):
    with print_lock:
        print(time.strftime("[%H:%M:%S] "), msg, sep="", flush=True)


def pace():
    with rate_lock:
        now = time.monotonic()
        wait = _last_req[0] + min_interval - now
        if wait > 0:
            time.sleep(wait)
        _last_req[0] = time.monotonic()


def http_json(url, timeout=30, retries=3):
    last_err = None
    for attempt in range(retries):
        pace()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 429:
                    raise urllib.error.HTTPError(url, 429, "rate limited", resp.headers, None)
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:
                retry_after = e.headers.get("Retry-After") if e.headers else None
                delay = float(retry_after) if retry_after and retry_after.isdigit() else 2 ** (attempt + 1)
                time.sleep(min(delay, 15))
                continue
            if e.code >= 500:
                time.sleep(2 ** (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ConnectionError) as e:
            last_err = e
            time.sleep(2 ** (attempt + 1))
    raise last_err if last_err else RuntimeError(url)


def fetch_asn_list_ripestat():
    d = http_json(f"{RIPESTAT}/country-asns/data.json?resource=CN&lod=1")["data"]
    countries = d["countries"]
    if not countries:
        raise RuntimeError("country-asns returned no countries")
    routed = countries[0].get("routed", "") or ""
    asns = set(int(x) for x in re.findall(r"AsnSingle\((\d+)\)", routed))
    for a, b in re.findall(r"AsnRange\((\d+),\s*(\d+)\)", routed):
        asns.update(range(int(a), int(b) + 1))
    if not asns:
        raise RuntimeError("no ASNs parsed from RIPEstat routed field")
    return asns, "ripestat-country-asns"


def fetch_asn_list_apnic():
    req = urllib.request.Request(APNIC_DELEGATED, headers={"User-Agent": UA})
    pace()
    with urllib.request.urlopen(req, timeout=60) as resp:
        text = resp.read().decode("utf-8", "replace")
    asns = set()
    for line in text.splitlines():
        if not line or line.startswith(("#", "2|", "version")):
            continue
        parts = line.split("|")
        if len(parts) >= 4 and parts[1] == "CN" and parts[2] == "asn":
            asns.add(int(parts[3]))
    if not asns:
        raise RuntimeError("no CN ASNs in APNIC delegated file")
    return asns, "apnic-delegated"


def prefixes_ripestat(asn):
    d = http_json(f"{RIPESTAT}/announced-prefixes/data.json?resource=AS{asn}")["data"]
    return [p["prefix"] for p in d.get("prefixes", [])]


def prefixes_bgpview(asn):
    d = http_json(f"{BGPVIEW}/asn/{asn}/prefixes")
    if d.get("status") != "ok":
        raise RuntimeError(f"bgpview status={d.get('status')}")
    data = d.get("data") or {}
    out = [p["prefix"] for p in data.get("ipv4_prefixes", [])]
    out += [p["prefix"] for p in data.get("ipv6_prefixes", [])]
    return out


def fetch_prefixes_for_asn(asn):
    try:
        return asn, prefixes_ripestat(asn), "ripestat"
    except Exception as e1:
        try:
            return asn, prefixes_bgpview(asn), "bgpview"
        except Exception as e2:
            return asn, None, f"both failed: {e1} / {e2}"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", default="cn-asn.json", help="final rule-set path")
    ap.add_argument("--min-ratio", type=float, default=0.8,
                    help="new prefix count must be >= ratio * old count")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0, help="debug: only first N ASNs")
    ap.add_argument("--extra", default="",
                    help="file with supplemental ASNs (one per line, '#' comments)")
    ap.add_argument("--max-fail-pct", type=float, default=5.0,
                    help="abort if more than this %% of ASNs fail on all sources")
    args = ap.parse_args()

    # --- 1. ASN list ---------------------------------------------------
    try:
        asns, src = fetch_asn_list_ripestat()
    except Exception as e:
        log(f"RIPEstat country-asns failed ({e}), falling back to APNIC")
        asns, src = fetch_asn_list_apnic()
    if args.extra:
        extra = []
        with open(args.extra) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line.isdigit():
                    extra.append(int(line))
        asns.update(extra)
        log(f"extra ASNs from {args.extra}: {len(extra)}")
    asn_list = sorted(asns)
    if args.limit:
        asn_list = asn_list[: args.limit]
    log(f"ASN source: {src}, routed CN ASNs: {len(asn_list)}")
    if not asn_list:
        log("FATAL: empty ASN list")
        return 2

    # --- 2. prefixes ----------------------------------------------------
    v4, v6 = set(), set()
    failed = []
    done = 0
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(fetch_prefixes_for_asn, a) for a in asn_list]
        for fut in concurrent.futures.as_completed(futs):
            asn, prefixes, note = fut.result()
            done += 1
            if prefixes is None:
                failed.append((asn, note))
                if done % 200 == 0 or len(failed) <= 3:
                    log(f"progress {done}/{len(asn_list)} failed={len(failed)} latest_fail AS{asn}: {note[:120]}")
            else:
                for p in prefixes:
                    (v6 if ":" in p else v4).add(p)
            if done % 500 == 0:
                log(f"progress {done}/{len(asn_list)} v4={len(v4)} v6={len(v6)} failed={len(failed)} "
                    f"({time.monotonic()-start:.0f}s)")
    log(f"fetched in {time.monotonic()-start:.0f}s: v4={len(v4)} v6={len(v6)} "
        f"unique_total={len(v4)+len(v6)} failed_asns={len(failed)}")

    # --- 3. quality gates ------------------------------------------------
    fail_pct = 100.0 * len(failed) / len(asn_list)
    if fail_pct > args.max_fail_pct:
        log(f"FATAL: {fail_pct:.1f}% of ASNs failed (threshold {args.max_fail_pct}%), aborting, "
            f"existing output untouched")
        return 1
    if len(v4) < 1000 or len(v6) < 50:
        log(f"FATAL: implausibly small result (v4={len(v4)}, v6={len(v6)}), aborting")
        return 1
    old_count = 0
    if os.path.exists(args.output):
        try:
            with open(args.output) as f:
                old = json.load(f)
            old_count = sum(len(r.get("ip_cidr", [])) for r in old.get("rules", []))
        except Exception as e:
            log(f"warning: cannot read old output for comparison: {e}")
        new_count = len(v4) + len(v6)
        if old_count and new_count < old_count * args.min_ratio:
            log(f"FATAL: new count {new_count} < {args.min_ratio:.0%} of old {old_count}, "
                f"aborting, existing output untouched")
            return 1

    # --- 4. atomic write --------------------------------------------------
    ruleset = {
        "version": 1,
        "rules": [{"ip_cidr": sorted(v4, key=lambda s: tuple(
                       int(x) if x.isdigit() else 0 for x in s.split("/")[0].split("."))) +
                   sorted(v6)}],
    }
    tmp = args.output + ".new"
    with open(tmp, "w") as f:
        json.dump(ruleset, f, separators=(",", ":"))
    json.load(open(tmp))  # re-parse what we actually wrote
    os.replace(tmp, args.output)
    log(f"OK: wrote {args.output} ({os.path.getsize(args.output)} bytes, "
        f"v4={len(v4)} v6={len(v6)}, old_count={old_count})")
    if failed:
        log(f"note: {len(failed)} ASNs had no usable data and are skipped: "
            f"{[a for a, _ in failed[:10]]}{'...' if len(failed) > 10 else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
