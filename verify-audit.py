#!/usr/bin/env python3
"""Verify audit.json and apply-audit-route.py without network access."""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
AUDIT_PATH = ROOT / "audit.json"
APPLY_AUDIT = ROOT / "apply-audit-route.py"
APPLY_CN_ASN = ROOT / "apply-cn-asn-route.py"

FORBIDDEN = [
    "onedrive",
    "speedtest",
    "speed.io",
    "fast.com",
    "ipaddress",
    "whatismyip",
    "ipip",
    "iplocation",
    "myip",
    "whatismybrowser",
    "ip138",
]

POSITIVE = [
    "xunlei.com",
    "m.weibo.com",
    "icbc.com.cn",
    "gov.cn",
    "www.gov.cn",
    "www.gov.com",
    "cctv.com.cn",
    "pincong.rocks",
    "mycard.com.tw",
    "gash.com.tw",
    "antpool.com",
    "sparkpool.com",
    "2miners.com",
    "miaozhen.com",
    "talkingdata.com",
    "umeng.com",
    "adsafe.com",
    "nytimes.com",
    "theepochtimes.com",
    "110.qq.com",
    "talk.news.pts.org",
    "efcc.org",
    "cn.rfi.fr",
    "truthmoviegroup.wixsite.com",
    "go.kr",
    "12377.cn",
    "jubao.org",
    "metatrader5.com",
    "sinaimg.cn",
    "autonavi.com",
    "pinduoduo.com",
    "kuaishou.com",
    "zhihu.com",
    "taobao.com",
    "esu.wiki",
]

NEGATIVE = [
    "onedrive.com",
    "onedrive.live.com",
    "speedtest.net",
    "fast.com",
    "speed.io",
    "whatismyip.com",
    "ip138.com",
    "ipip.net",
    "whatismybrowser.com",
    "google.com",
    "github.com",
    "example.com",
    "apple.com",
    "microsoft.com",
    "cloudflare.com",
    "notxunlei.com",
    "myweibo.com",
    "thunderbird.mozilla.org",
    "bankofamerica.com",
    "mybank.com",
    "planned.com",
    "notgov.com",
]

PRIVATE_CIDRS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
]

PORT_VALUES = [107, 194, 445, 465, 587, 992, 3389, 6679, 6697, 7000]
PORT_RANGES = ["22:25", "6665:6669", "6881:6999"]


def require(condition, message):
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def load_ruleset():
    try:
        data = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(f"FAIL: cannot load {AUDIT_PATH}: {e}")

    require(isinstance(data, dict), "audit.json must be a JSON object")
    require(data.get("version") == 1, "audit.json version must be 1")
    rules = data.get("rules")
    require(isinstance(rules, list) and rules, "audit.json rules must be a non-empty array")

    suffixes = []
    regexes = []
    for index, rule in enumerate(rules):
        require(isinstance(rule, dict), f"rules[{index}] must be an object")
        require(
            set(rule) <= {"domain_suffix", "domain_regex"},
            f"rules[{index}] has unsupported fields: {sorted(set(rule) - {'domain_suffix', 'domain_regex'})}",
        )
        for value in rule.get("domain_suffix", []):
            require(isinstance(value, str) and value, f"rules[{index}] has invalid domain_suffix")
            require(not value.startswith("."), f"domain_suffix must not start with a dot: {value}")
            require(value == value.lower(), f"domain_suffix must be lowercase: {value}")
            suffixes.append(value)
        for value in rule.get("domain_regex", []):
            require(isinstance(value, str) and value, f"rules[{index}] has invalid domain_regex")
            require(value == value.lower(), f"domain_regex must be lowercase: {value}")
            try:
                re.compile(value)
            except re.error as e:
                raise SystemExit(f"FAIL: invalid regex {value!r}: {e}")
            regexes.append(value)

    require(suffixes, "audit.json must contain domain_suffix entries")
    require(regexes, "audit.json must contain domain_regex entries")
    require(len(suffixes) == len(set(suffixes)), "duplicate domain_suffix entries")
    require(len(regexes) == len(set(regexes)), "duplicate domain_regex entries")

    for value in suffixes + regexes:
        require("\u00ad" not in value, "soft hyphen found in audit rules")
        require(not value.startswith("regexp:"), "regexp: prefix found in audit rules")
        for term in FORBIDDEN:
            require(term not in value, f"excluded term {term!r} found in {value!r}")

    return suffixes, [re.compile(value) for value in regexes], data


def matches(domain, suffixes, regexes):
    domain = domain.lower().rstrip(".")
    return any(domain == suffix or domain.endswith("." + suffix) for suffix in suffixes) or any(
        regex.search(domain) for regex in regexes
    )


def base_config():
    return {
        "route": {
            "rules": [
                {
                    "rule_set": ["geosite-google"],
                    "action": "route",
                    "outbound": "direct",
                },
                {"action": "resolve"},
                {"rule_set": ["asn-cn"], "action": "reject"},
            ],
            "rule_set": [
                {
                    "tag": "geosite-google",
                    "type": "local",
                    "format": "source",
                    "path": "/tmp/geosite-google.json",
                }
            ],
        }
    }


def run_script(script, config, extra_args):
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        config_path = tmp_path / "config.json"
        output_path = tmp_path / "config.out.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        command = [
            sys.executable,
            str(script),
            "--config",
            str(config_path),
            "--output",
            str(output_path),
            *extra_args,
        ]
        result = subprocess.run(command, text=True, capture_output=True)
        require(
            result.returncode == 0,
            f"{script.name} failed:\n{result.stderr.strip()}\n{result.stdout.strip()}",
        )
        return json.loads(output_path.read_text(encoding="utf-8"))


def run_audit(config, inbound=None, before_first_rule_set=False):
    args = ["--ruleset", str(AUDIT_PATH)]
    if before_first_rule_set:
        args.append("--before-first-rule-set")
    if inbound:
        for tag in inbound:
            args.extend(["--inbound", tag])
    return run_script(APPLY_AUDIT, config, args)


def run_cn_asn(config, inbound=None):
    args = [
        "--ruleset",
        "/tmp/cn-asn.json",
        "--local-ip",
        "203.0.113.10",
    ]
    if inbound:
        for tag in inbound:
            args.extend(["--inbound", tag])
    return run_script(APPLY_CN_ASN, config, args)


def find_rule(rules, predicate, description):
    for index, rule in enumerate(rules):
        if isinstance(rule, dict) and predicate(rule):
            return index, rule
    raise SystemExit(f"FAIL: missing {description}")


def is_reject(rule):
    return rule.get("action") == "reject"


def verify_ruleset_and_matching():
    suffixes, regexes, _ = load_ruleset()
    for domain in POSITIVE:
        require(matches(domain, suffixes, regexes), f"expected match: {domain}")
    for domain in NEGATIVE:
        require(not matches(domain, suffixes, regexes), f"unexpected match: {domain}")


def verify_patch_defaults():
    patched = run_audit(base_config())
    rules = patched["route"]["rules"]
    rule_sets = patched["route"]["rule_set"]

    sniff_index, sniff = find_rule(rules, lambda rule: rule.get("action") == "sniff", "sniff rule")
    geosite_index, _ = find_rule(
        rules,
        lambda rule: "geosite-google" in as_list(rule.get("rule_set")),
        "geosite rule",
    )
    private_index, private = find_rule(
        rules,
        lambda rule: is_reject(rule)
        and set(as_list(rule.get("ip_cidr"))) == set(PRIVATE_CIDRS),
        "private IP reject rule",
    )
    port_index, port = find_rule(
        rules,
        lambda rule: is_reject(rule)
        and ("port" in rule or "port_range" in rule),
        "port reject rule",
    )
    bt_index, bt = find_rule(
        rules,
        lambda rule: is_reject(rule)
        and set(as_list(rule.get("protocol"))) == {"bittorrent"},
        "BitTorrent reject rule",
    )
    audit_index, audit = find_rule(
        rules,
        lambda rule: is_reject(rule) and "audit" in as_list(rule.get("rule_set")),
        "audit reject rule",
    )
    resolve_index, _ = find_rule(
        rules, lambda rule: rule.get("action") == "resolve", "resolve rule"
    )
    asn_index, _ = find_rule(
        rules,
        lambda rule: "asn-cn" in as_list(rule.get("rule_set")),
        "asn-cn reject rule",
    )

    require(
        sniff_index
        < geosite_index
        < private_index
        < port_index
        < bt_index
        < audit_index
        < resolve_index
        < asn_index,
        "audit rules are not in the expected order",
    )
    require("sniffer" not in sniff, "new sniff rule must use all default sniffers")
    require("inbound" not in sniff, "default sniff rule must apply to all inbounds")
    require(
        set(private["ip_cidr"]) == set(PRIVATE_CIDRS),
        "private CIDR list mismatch",
    )
    require(set(port.get("port", [])) == set(PORT_VALUES), "port list mismatch")
    require(set(port.get("port_range", [])) == set(PORT_RANGES), "port range mismatch")
    require(
        "10000:65535" not in port.get("port_range", []),
        "full high-port range must not be blocked",
    )
    require(set(bt["protocol"]) == {"bittorrent"}, "BitTorrent protocol mismatch")
    require(set(audit["rule_set"]) == {"audit"}, "audit rule_set mismatch")
    require(
        len([entry for entry in rule_sets if entry.get("tag") == "audit"]) == 1,
        "audit rule_set must be present exactly once",
    )
    audit_entry = next(entry for entry in rule_sets if entry.get("tag") == "audit")
    require(audit_entry.get("type") == "local", "audit rule_set must be local")
    require(audit_entry.get("format") == "source", "audit rule_set must be source format")
    require(audit_entry.get("path") == str(AUDIT_PATH), "audit rule_set path mismatch")

    second = run_audit(patched)
    require(second == patched, "audit patch is not idempotent")


def verify_scope():
    patched = run_audit(base_config(), inbound=["snell-share"])
    rules = patched["route"]["rules"]
    managed = [
        rule
        for rule in rules
        if isinstance(rule, dict)
        and (
            rule.get("action") == "sniff"
            or (
                is_reject(rule)
                and (
                    "ip_cidr" in rule
                    or "port" in rule
                    or "port_range" in rule
                    or "protocol" in rule
                    or "audit" in as_list(rule.get("rule_set"))
                )
            )
        )
    ]
    require(len(managed) == 5, f"expected 5 scoped rules, got {len(managed)}")
    for rule in managed:
        require(
            as_list(rule.get("inbound")) == ["snell-share"],
            f"rule is not scoped correctly: {rule}",
        )


def verify_existing_sniff():
    config = base_config()
    config["route"]["rules"].insert(
        0, {"action": "sniff", "sniffer": ["http", "tls"]}
    )
    patched = run_audit(config)
    sniffs = [
        rule
        for rule in patched["route"]["rules"]
        if isinstance(rule, dict) and rule.get("action") == "sniff"
    ]
    require(len(sniffs) == 1, "existing sniff rule was duplicated")
    require(
        sniffs[0].get("sniffer") == ["http", "tls", "bittorrent"],
        "bittorrent was not appended to existing sniffer list",
    )

    config = base_config()
    config["route"]["rules"].insert(0, {"action": "sniff"})
    patched = run_audit(config)
    sniffs = [
        rule
        for rule in patched["route"]["rules"]
        if isinstance(rule, dict) and rule.get("action") == "sniff"
    ]
    require(len(sniffs) == 1, "default sniff rule was duplicated")
    require("sniffer" not in sniffs[0], "default sniff rule was modified")


def verify_scoped_sniff():
    config = base_config()
    config["route"]["rules"].insert(
        0,
        {
            "inbound": ["snell-private"],
            "action": "sniff",
            "sniffer": ["http", "tls"],
        },
    )
    patched = run_audit(config, inbound=["snell-share"])
    sniffs = [
        rule
        for rule in patched["route"]["rules"]
        if isinstance(rule, dict) and rule.get("action") == "sniff"
    ]
    require(len(sniffs) == 2, "expected a separate sniff rule for the target inbound")
    private_sniff = next(rule for rule in sniffs if "snell-private" in as_list(rule.get("inbound")))
    share_sniff = next(rule for rule in sniffs if "snell-share" in as_list(rule.get("inbound")))
    require(
        private_sniff.get("sniffer") == ["http", "tls"],
        "unrelated sniff rule was modified",
    )
    require("sniffer" not in share_sniff, "target sniff rule must use defaults")


def verify_before_first_rule_set():
    config = base_config()
    config["route"]["rules"].insert(
        0,
        {
            "ip_cidr": ["203.0.113.10/32"],
            "action": "route",
            "outbound": "direct",
        },
    )
    patched = run_audit(
        config,
        inbound=["snell-share"],
        before_first_rule_set=True,
    )
    rules = patched["route"]["rules"]

    local_index, _ = find_rule(
        rules,
        lambda rule: rule.get("action") == "route"
        and "203.0.113.10/32" in as_list(rule.get("ip_cidr")),
        "local-IP direct rule",
    )
    private_index, _ = find_rule(
        rules,
        lambda rule: is_reject(rule)
        and set(as_list(rule.get("ip_cidr"))) == set(PRIVATE_CIDRS),
        "private IP reject rule",
    )
    port_index, _ = find_rule(
        rules,
        lambda rule: is_reject(rule)
        and ("port" in rule or "port_range" in rule),
        "port reject rule",
    )
    bt_index, _ = find_rule(
        rules,
        lambda rule: is_reject(rule)
        and set(as_list(rule.get("protocol"))) == {"bittorrent"},
        "BitTorrent reject rule",
    )
    audit_index, _ = find_rule(
        rules,
        lambda rule: is_reject(rule) and "audit" in as_list(rule.get("rule_set")),
        "audit reject rule",
    )
    geosite_index, _ = find_rule(
        rules,
        lambda rule: "geosite-google" in as_list(rule.get("rule_set")),
        "geosite rule",
    )
    resolve_index, _ = find_rule(
        rules, lambda rule: rule.get("action") == "resolve", "resolve rule"
    )
    asn_index, _ = find_rule(
        rules,
        lambda rule: "asn-cn" in as_list(rule.get("rule_set")),
        "asn-cn reject rule",
    )

    require(
        local_index
        < private_index
        < port_index
        < bt_index
        < audit_index
        < geosite_index
        < resolve_index
        < asn_index,
        "--before-first-rule-set did not place audit before the first rule_set",
    )

    second = run_audit(
        patched,
        inbound=["snell-share"],
        before_first_rule_set=True,
    )
    require(second == patched, "--before-first-rule-set patch is not idempotent")


def verify_patch_order_with_cn_asn():
    cn_first = run_cn_asn(base_config())
    audit_second = run_audit(cn_first)
    rules = audit_second["route"]["rules"]
    audit_index, _ = find_rule(
        rules,
        lambda rule: is_reject(rule) and "audit" in as_list(rule.get("rule_set")),
        "audit reject rule",
    )
    local_index, _ = find_rule(
        rules,
        lambda rule: rule.get("action") == "route"
        and "203.0.113.10/32" in as_list(rule.get("ip_cidr")),
        "CN local-IP route rule",
    )
    resolve_index, _ = find_rule(
        rules, lambda rule: rule.get("action") == "resolve", "resolve rule"
    )
    asn_index, _ = find_rule(
        rules,
        lambda rule: "asn-cn" in as_list(rule.get("rule_set")),
        "asn-cn reject rule",
    )
    require(local_index < audit_index < resolve_index < asn_index, "CN-first order is wrong")

    audit_first = run_audit(base_config())
    cn_second = run_cn_asn(audit_first)
    rules = cn_second["route"]["rules"]
    audit_index, _ = find_rule(
        rules,
        lambda rule: is_reject(rule) and "audit" in as_list(rule.get("rule_set")),
        "audit reject rule",
    )
    local_index, _ = find_rule(
        rules,
        lambda rule: rule.get("action") == "route"
        and "203.0.113.10/32" in as_list(rule.get("ip_cidr")),
        "CN local-IP route rule",
    )
    resolve_index, _ = find_rule(
        rules, lambda rule: rule.get("action") == "resolve", "resolve rule"
    )
    asn_index, _ = find_rule(
        rules,
        lambda rule: "asn-cn" in as_list(rule.get("rule_set")),
        "asn-cn reject rule",
    )
    require(audit_index < local_index < resolve_index < asn_index, "audit-first order is wrong")


def main():
    verify_ruleset_and_matching()
    verify_patch_defaults()
    verify_scope()
    verify_existing_sniff()
    verify_scoped_sniff()
    verify_before_first_rule_set()
    verify_patch_order_with_cn_asn()
    print("OK: audit.json and apply-audit-route.py verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
