#!/usr/bin/env python3
"""Add the audit ruleset and its route rules to a sing-box config.

The operation is idempotent: rules created by this script are replaced
rather than duplicated. If no --inbound is supplied, the rules apply to
every inbound.
"""

import argparse
import json
import sys

AUDIT_TAG = "audit"

PRIVATE_CIDRS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
]

PORT_VALUES = [
    107,
    194,
    445,
    465,
    587,
    992,
    3389,
    6679,
    6697,
    7000,
]

PORT_RANGES = [
    "22:25",
    "6665:6669",
    "6881:6999",
]


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def same_set(left, right):
    return set(as_list(left)) == set(right)


def is_resolve(rule):
    return isinstance(rule, dict) and rule.get("action") == "resolve"


def is_managed_rule(rule):
    if not isinstance(rule, dict) or rule.get("action") != "reject":
        return False

    keys = set(rule)
    if "rule_set" in keys and AUDIT_TAG in as_list(rule.get("rule_set")):
        return keys <= {"inbound", "action", "rule_set"}
    if "protocol" in keys and same_set(rule.get("protocol"), ["bittorrent"]):
        return keys <= {"inbound", "action", "protocol"}
    if "ip_cidr" in keys and same_set(rule.get("ip_cidr"), PRIVATE_CIDRS):
        return keys <= {"inbound", "action", "ip_cidr"}
    if "port" in keys or "port_range" in keys:
        if not keys <= {"inbound", "action", "port", "port_range"}:
            return False
        if "port" in keys and not same_set(rule.get("port"), PORT_VALUES):
            return False
        if "port_range" in keys and not same_set(rule.get("port_range"), PORT_RANGES):
            return False
        return True
    return False


def find_insert_index(rules, before_first_rule_set=False):
    if before_first_rule_set:
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            if as_list(rule.get("rule_set")):
                return index
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        if is_resolve(rule):
            return index
        if "asn-cn" in as_list(rule.get("rule_set")):
            return index
    return len(rules)


def ensure_bittorrent(rule):
    sniffer = rule.get("sniffer")
    if sniffer is None:
        return
    if isinstance(sniffer, str):
        sniffer = [sniffer]
    if not isinstance(sniffer, list) or not sniffer:
        return
    if any(str(name).lower() == "bittorrent" for name in sniffer):
        return
    sniffer.append("bittorrent")
    rule["sniffer"] = sniffer


def ensure_sniff(rules, targets, insert_at):
    covered = set()
    covered_all = False

    for rule in rules[:insert_at]:
        if not isinstance(rule, dict) or rule.get("action") != "sniff":
            continue
        scope = as_list(rule.get("inbound"))
        if not targets:
            if not scope:
                ensure_bittorrent(rule)
                covered_all = True
            continue
        applies = set(targets) if not scope else set(targets) & set(scope)
        if applies:
            ensure_bittorrent(rule)
            covered.update(applies)

    if targets:
        missing = [tag for tag in targets if tag not in covered]
        if not missing:
            return False
        new_rule = {"inbound": missing, "action": "sniff"}
    else:
        if covered_all:
            return False
        new_rule = {"action": "sniff"}

    rules.insert(0, new_rule)
    return True


def load_json(path, description):
    try:
        with open(path, encoding="utf-8") as f:
            value = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(f"cannot load {description} {path}: {e}")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="source sing-box config")
    parser.add_argument("--ruleset", required=True, help="absolute audit ruleset path")
    parser.add_argument("--output", required=True, help="patched config path")
    parser.add_argument(
        "--inbound",
        action="append",
        default=[],
        help="inbound tag to scope the rules to; omit for all inbounds",
    )
    parser.add_argument(
        "--before-first-rule-set",
        action="store_true",
        help=(
            "insert the audit group before the first rule that references a "
            "rule_set, after earlier local-IP/direct exceptions"
        ),
    )
    args = parser.parse_args()

    targets = list(dict.fromkeys(args.inbound))

    ruleset = load_json(args.ruleset, "ruleset")
    if (
        not isinstance(ruleset, dict)
        or not isinstance(ruleset.get("rules"), list)
        or not ruleset["rules"]
    ):
        raise SystemExit("ruleset must be a JSON object with a non-empty rules array")

    config = load_json(args.config, "config")
    if not isinstance(config, dict):
        raise SystemExit("config must be a JSON object")

    route = config.setdefault("route", {})
    if not isinstance(route, dict):
        raise SystemExit("route must be a JSON object")
    rules = route.setdefault("rules", [])
    rule_sets = route.setdefault("rule_set", [])
    if not isinstance(rules, list) or not isinstance(rule_sets, list):
        raise SystemExit("route.rules and route.rule_set must be arrays")

    rules[:] = [rule for rule in rules if not is_managed_rule(rule)]
    rule_sets[:] = [
        entry
        for entry in rule_sets
        if not (
            isinstance(entry, dict) and AUDIT_TAG in as_list(entry.get("tag"))
        )
    ]

    insert_at = find_insert_index(rules, args.before_first_rule_set)
    sniff_added = ensure_sniff(rules, targets, insert_at)
    insert_at = find_insert_index(rules, args.before_first_rule_set)

    new_rules = []
    for payload in (
        {"ip_cidr": PRIVATE_CIDRS, "action": "reject"},
        {"port": PORT_VALUES, "port_range": PORT_RANGES, "action": "reject"},
        {"protocol": ["bittorrent"], "action": "reject"},
        {"rule_set": [AUDIT_TAG], "action": "reject"},
    ):
        rule = {}
        if targets:
            rule["inbound"] = targets
        rule.update(payload)
        new_rules.append(rule)
    rules[insert_at:insert_at] = new_rules

    rule_sets.append(
        {
            "tag": AUDIT_TAG,
            "type": "local",
            "format": "source",
            "path": args.ruleset,
        }
    )

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")

    print(
        f"wrote {args.output}: inserted {len(new_rules)} rules at index {insert_at}"
    )
    print("scope:", "all inbounds" if not targets else targets)
    print(
        "insert:",
        "before first rule_set"
        if args.before_first_rule_set
        else "before resolve/asn-cn",
    )
    print(
        "sniff:",
        "inserted default sniff rule" if sniff_added else "reused or updated existing rule",
    )
    print("blocked ports:", json.dumps(PORT_VALUES + PORT_RANGES))
    print("blocked private CIDRs:", json.dumps(PRIVATE_CIDRS))
    print("rule_set:", json.dumps(rule_sets[-1]))
    for rule in new_rules:
        print("rule:", json.dumps(rule))
    return 0


if __name__ == "__main__":
    sys.exit(main())
