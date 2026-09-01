import json, urllib.request, time

CANDIDATES = {
    # tencent
    139341: "tencent", 137876: "tencent", 135341: "tencent", 133478: "tencent",
    # alibaba
    137973: "alibaba", 58807: "alibaba", 145591: "alibaba", 135377: "alibaba",
    # bytedance / tiktok
    396986: "bytedance", 139190: "bytedance", 138954: "bytedance",
    # huawei
    136188: "huawei", 135373: "huawei", 138544: "huawei",
    # baidu / xiaomi / netease / jd / kuaishou / cmi
    138353: "baidu", 138448: "xiaomi", 45062: "netease", 134108: "jd",
    138430: "kuaishou", 58453: "cmi", 58715: "ctg",
}

def whois_name(asn):
    url = f"https://stat.ripe.net/data/whois/data.json?resource=AS{asn}"
    req = urllib.request.Request(url, headers={"User-Agent": "probe"})
    try:
        d = json.loads(urllib.request.urlopen(req, timeout=30).read())["data"]
    except Exception as e:
        return f"ERR {e}"
    texts = []
    for rec in d.get("records", []):
        for r in rec:
            texts.append(r.get("value", ""))
    blob = " | ".join(texts)[:400]
    return blob

for asn, label in sorted(CANDIDATES.items()):
    blob = whois_name(asn)
    low = blob.lower()
    hit = label in low or label.split()[0] in low
    print(f"AS{asn:<7} [{label}] match={hit} :: {blob[:150]}")
    time.sleep(0.3)
