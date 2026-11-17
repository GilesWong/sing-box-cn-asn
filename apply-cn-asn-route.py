#!/usr/bin/env python3
"""Add the CN-ASN ruleset and route rules to a sing-box config.

The operation is idempotent: existing asn-cn entries and the local-IP
bypass created by this script are replaced rather than duplicated. If no
--inbound is supplied, the rules apply to every inbound.
"""

import argparse
import ipaddress
import json
import sys


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def same_inbounds(rule, inbounds):
    return as_list(rule.get("inbound")) == inbounds


def is_simple_resolve(rule):
    allowed = {"inbound", "action", "server", "strategy", "disable_cache"}
    return rule.get("action") == "resolve" and set(rule) <= allowed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="source sing-box config")
    parser.add_argument("--ruleset", required=True, help="absolute ruleset path")
    parser.add_argument("--local-ip", required=True, help="server IPv4 or CIDR")
    parser.add_argument("--inbound", action="append", default=[],
                        help="inbound tag to scope the rules to; omit for all inbounds")
    parser.add_argument("--output", required=True, help="patched config path")
    args = parser.parse_args()

    inbounds = list(dict.fromkeys(args.inbound))

    local_interface = ipaddress.ip_interface(args.local_ip)
    if local_interface.version != 4:
        raise SystemExit("--local-ip must be IPv4")
    local_cidr = str(local_interface.network)

    with open(args.config, encoding="utf-8") as f:
        config = json.load(f)

    route = config.setdefault("route", {})
    rules = route.setdefault("rules", [])
    rule_sets = route.setdefault("rule_set", [])

    rules[:] = [
        rule
        for rule in rules
        if not (
            "asn-cn" in as_list(rule.get("rule_set"))
            or (
                is_simple_resolve(rule)
                and (
                    not inbounds
                    or not rule.get("inbound")
                    or same_inbounds(rule, inbounds)
                )
            )
            or (
                rule.get("action") == "route"
                and rule.get("outbound") == "direct"
                and local_cidr in as_list(rule.get("ip_cidr"))
            )
        )
    ]
    rule_sets[:] = [entry for entry in rule_sets if entry.get("tag") != "asn-cn"]
    rule_sets.append({
        "tag": "asn-cn",
        "type": "local",
        "format": "source",
        "path": args.ruleset,
    })

    insert_at = 0
    for index, rule in enumerate(rules):
        if as_list(rule.get("rule_set")):
            insert_at = index + 1

    new_rules = []
    for rule in (
        {
            "ip_cidr": [local_cidr],
            "action": "route",
            "outbound": "direct",
        },
        {
            "action": "resolve",
        },
        {
            "rule_set": ["asn-cn"],
            "action": "reject",
        },
    ):
        if inbounds:
            rule = {"inbound": inbounds, **rule}
        new_rules.append(rule)
    rules[insert_at:insert_at] = new_rules

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.write("\n")

    print(f"wrote {args.output}: inserted {len(new_rules)} rules at index {insert_at}")
    print("scope:", "all inbounds" if not inbounds else inbounds)
    print("rule_set:", json.dumps(rule_sets[-1]))
    for rule in new_rules:
        print("rule:", json.dumps(rule))
    return 0


if __name__ == "__main__":
    sys.exit(main())
