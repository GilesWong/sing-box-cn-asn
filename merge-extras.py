import json, os, sys, ipaddress
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_cn_asn import fetch_prefixes_for_asn

out_path = sys.argv[1]
extras = []
for line in open(sys.argv[2]):
    line = line.split("#", 1)[0].strip()
    if line.isdigit():
        extras.append(int(line))
print("extra ASNs:", extras)

with open(out_path) as f:
    ruleset = json.load(f)
pfx = set(ruleset["rules"][0]["ip_cidr"])
before = len(pfx)

for asn in extras:
    asn, prefixes, note = fetch_prefixes_for_asn(asn)
    if prefixes is None:
        print(f"AS{asn}: FAILED {note}")
        continue
    added = 0
    for p in prefixes:
        if p not in pfx:
            pfx.add(p)
            added += 1
    print(f"AS{asn}: +{added} (total {len(prefixes)} announced)")

after = len(pfx)
print(f"total: {before} -> {after}")
assert after >= before, "merge must never remove prefixes"

v4 = sorted((p for p in pfx if ":" not in p),
            key=lambda s: tuple(int(x) if x.isdigit() else 0 for x in s.split("/")[0].split(".")))
v6 = sorted(p for p in pfx if ":" in p)
new = {"version": 1, "rules": [{"ip_cidr": v4 + v6}]}
tmp = out_path + ".new"
with open(tmp, "w") as f:
    json.dump(new, f, separators=(",", ":"))
json.load(open(tmp))
os.replace(tmp, out_path)
print(f"OK: {out_path} now {os.path.getsize(out_path)} bytes, {after} prefixes")
