# sing-box CN ASN rules

This repository builds a sing-box source-format rule set containing the IPv4 and
IPv6 prefixes announced by ASNs registered in China. The rule set is published
as a rolling GitHub release and can be consumed either as a local file or as a
remote `rule_set` URL.

The repository also contains:

- an idempotent script that patches an existing sing-box configuration with the
  CN ASN rule set and the server's own-IP direct exception;
- a static domain audit rule set and an idempotent script that applies it;
- an offline verifier for the audit rules and both patch scripts;
- a systemd updater and a Docker updater that download, validate, install, and
  roll back the published rule set.

## Contents

| Path | Purpose |
| --- | --- |
| `gen_cn_asn.py` | Builds `cn-asn.json` from RIPEstat, with APNIC and bgpview fallbacks. |
| `merge-extras.py` | Adds a supplemental ASN list to an already generated rule set. |
| `cn-asn-extra.txt` | Optional list of ASNs registered outside China but operated by CN companies. |
| `apply-cn-asn-route.py` | Patches a sing-box config with the CN ASN rule set, a resolve rule, and an own-IP direct exception. |
| `apply-audit-route.py` | Patches a sing-box config with private-IP, high-risk-port, BitTorrent, and audit-domain rejects. |
| `audit.json` | Static source-format domain audit rule set. |
| `verify-audit.py` | Offline verifier for `audit.json` and both patch scripts. |
| `update-cn-asn-native.sh` | systemd updater for the native sing-box deployment. |
| `update-cn-asn-native.service`, `.timer` | systemd unit and daily timer for the native updater. |
| `update-cn-asn.sh`, `.service`, `.timer` | Docker/Compose updater and units. |
| `compose.yml` | Example Compose deployment for sing-box. |
| `.github/workflows/update.yml` | Daily build, validation, and rolling-release publication. |

## Requirements

- Python 3.9 or newer.
- A sing-box release that supports source-format rule sets and route-rule
  actions (`action: resolve`, `action: reject`); sing-box 1.11 or newer is
  recommended.
- Network access to `stat.ripe.net`, `api.bgpview.io`, and
  `ftp.apnic.net` when generating the rule set.
- `curl`, `sha256sum`, `sing-box`, and either systemd or Docker on the server
  that consumes the rule set.

## Generate the rule set

```sh
python3 gen_cn_asn.py \
  --output cn-asn.json \
  --extra cn-asn-extra.txt \
  --min-ratio 0.8 \
  --concurrency 8
```

The generator:

1. Reads the routed ASN list for CN from RIPEstat `country-asns`, falling back
   to the APNIC delegated file.
2. Fetches every announced prefix for each ASN from RIPEstat, falling back to
   bgpview per ASN.
3. Applies quality gates and writes the result atomically.

Exit codes: `0` success, `1` a validation gate rejected the result, `2` a fatal
error. A rejected run leaves the previous output untouched.

The output is a source-format rule set:

```json
{
  "version": 1,
  "rules": [
    { "ip_cidr": ["203.0.113.0/24", "2001:db8::/32"] }
  ]
}
```

`203.0.113.0/24` and `2001:db8::/32` above are documentation examples only.

Useful flags:

- `--extra <file>`: merge supplemental ASNs (one per line, `#` comments).
- `--min-ratio 0.8`: refuse a result smaller than 80% of the previous output.
- `--max-fail-pct 5`: abort when more than 5% of ASNs fail on all sources.
- `--concurrency N`: number of parallel prefix fetch workers.
- `--limit N`: debug only, process the first N ASNs.

## Automated build and release

`.github/workflows/update.yml` runs daily and on manual dispatch. It generates
the rule set, compares it with the currently published asset, and uploads both
`cn-asn.json` and `cn-asn.json.sha256` to a rolling release tagged `latest`.

Stable asset URLs:

```text
https://github.com/<OWNER>/<REPO>/releases/latest/download/cn-asn.json
https://github.com/<OWNER>/<REPO>/releases/latest/download/cn-asn.json.sha256
```

If you fork the repository, update the repository name used by the updater
(`GITHUB_REPO`) or set it through the environment.

The client-side checksum verifies transport integrity. It does not prove that
the release was produced by a trusted workflow; pin a digest or add a signature
if you need authenticity guarantees.

## Use the rule set in sing-box

### Local file

Install the rule set at a path readable by the sing-box service and reference
it from `route.rule_set`:

```json
{
  "tag": "cn-asn",
  "type": "local",
  "format": "source",
  "path": "/etc/sing-box/rulesets/cn-asn.json"
}
```

### Remote URL

Alternatively, let sing-box download and refresh the published asset:

```json
{
  "tag": "cn-asn",
  "type": "remote",
  "format": "source",
  "url": "https://github.com/<OWNER>/<REPO>/releases/latest/download/cn-asn.json",
  "update_interval": "24h"
}
```

Remote mode stores the downloaded rule set in sing-box's data directory, so
that directory must be persistent if you want the cache to survive restarts.

### Route order

A typical route section looks like this. The addresses and inbound tags are
placeholders:

```json
{
  "route": {
    "rules": [
      {
        "ip_cidr": ["198.51.100.10/32"],
        "action": "route",
        "outbound": "direct"
      },
      {
        "inbound": ["example-inbound"],
        "ip_cidr": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10", "::1/128"],
        "action": "reject"
      },
      {
        "inbound": ["example-inbound"],
        "port": [445, 3389],
        "action": "reject"
      },
      {
        "inbound": ["example-inbound"],
        "protocol": ["bittorrent"],
        "action": "reject"
      },
      {
        "inbound": ["example-inbound"],
        "rule_set": ["audit"],
        "action": "reject"
      },
      {
        "action": "resolve"
      },
      {
        "rule_set": ["cn-asn"],
        "action": "reject"
      }
    ],
    "final": "direct"
  }
}
```

Ordering rules:

- The own-IP and management-host direct exceptions must appear before any
  reject rule that could match them.
- `action: resolve` must appear before the IP-based `cn-asn` reject if clients
  may send domain names. For IP-literal destinations, the address rule matches
  without resolution.
- Put the audit rejects before `resolve` and before the CN ASN reject.

## Patch an existing configuration

Both patch scripts are idempotent: they remove only the rules they created and
then re-insert them. They never edit the live configuration in place; write to
a new file, validate it, and install it atomically.

### CN ASN rules

```sh
cp -a <CONFIG> <CONFIG>.bak-$(date +%Y%m%d-%H%M%S)

python3 apply-cn-asn-route.py \
  --config <CONFIG> \
  --output <CONFIG>.new \
  --ruleset <ABSOLUTE_RULESET_PATH> \
  --local-ip <SERVER_IPV4>

sing-box check -c <CONFIG>.new
mv <CONFIG>.new <CONFIG>
systemctl restart <SING_BOX_SERVICE>
```

The script inserts:

1. a direct route for `<SERVER_IPV4>/32`;
2. an `action: resolve` rule;
3. a reject rule for the `cn-asn` rule set.

Omit `--inbound` to apply the rules to every inbound. Pass one or more
`--inbound <TAG>` options to scope them.

If you need additional management hosts to bypass the CN reject, add a separate
direct rule before the reject. Do not merge those addresses into the rule the
script creates: the next run of the script replaces that rule and keeps only
`--local-ip`.

### Audit rules

Install the audit rule set and patch the configuration:

```sh
install -d -m 0750 /etc/sing-box/rulesets
install -m 0640 audit.json /etc/sing-box/rulesets/audit.json

python3 apply-audit-route.py \
  --config <CONFIG> \
  --output <CONFIG>.new \
  --ruleset /etc/sing-box/rulesets/audit.json \
  --inbound <INBOUND_TAG>

sing-box check -c <CONFIG>.new
mv <CONFIG>.new <CONFIG>
systemctl restart <SING_BOX_SERVICE>
```

The patch inserts, in order:

1. a private-address reject;
2. a high-risk-port reject;
3. a BitTorrent protocol reject;
4. a reject for the `audit` rule set.

It places them before the first `resolve` or `cn-asn` rule, and adds or updates
a `sniff` rule so that BitTorrent detection works. Run the audit patch after
the CN patch so the own-IP direct rule remains ahead of the audit rejects.

By default the audit group stays after earlier geosite/WARP rules. Use
`--before-first-rule-set` when the audit rules must take precedence over an
existing `rule_set` direct route.

Review the audit categories before deploying. The list is intentionally broad
and includes banking, security software, mining pools, and political/news
domains that can block legitimate traffic.

## Update a server

### systemd updater

```sh
install -m 0755 update-cn-asn-native.sh /usr/local/sbin/update-cn-asn-native.sh
install -m 0644 update-cn-asn-native.service /etc/systemd/system/
install -m 0644 update-cn-asn-native.timer /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now update-cn-asn-native.timer
```

The updater:

1. downloads the latest `cn-asn.json` and its checksum;
2. verifies the checksum;
3. stages the file and runs `sing-box check` as the service user;
4. installs the file atomically;
5. restarts the service, checks the listening ports, and scans the journal for
   fatal errors;
6. restores the previous rule set if any step fails.

Test without changing the live rule set:

```sh
DRY_RUN=1 /usr/local/sbin/update-cn-asn-native.sh
```

Environment overrides: `GITHUB_REPO`, `BASE`, `SINGBOX_SERVICE`,
`HEALTH_PORTS`, `LOCK`, `DRY_RUN`.

The timer runs daily. Adjust `OnCalendar` to match when the publishing workflow
usually finishes, or trigger the updater from the release pipeline instead.

### Docker updater

`update-cn-asn.sh` performs the same download and checksum steps for a Compose
deployment, then restarts the container and verifies its health port. Set
`GITHUB_REPO`, `BASE`, `SINGBOX_CONTAINER`, and `HEALTH_PORT` as needed.

The directory the updater writes to must be mounted into the container,
otherwise the container keeps serving the old rule set. Alternatively, use the
remote `rule_set` URL and let sing-box refresh it directly.

## Verify

Run the offline verifier after editing `audit.json` or either patch script:

```sh
python3 verify-audit.py
```

It checks the rule-set structure, regex compilation, expected and unexpected
domain matches, the excluded categories, the high-port exclusion, inbound
scoping, sniff handling, idempotency, and both patch orderings. It requires no
network access.

## Data semantics and limitations

- **Selection is by ASN registration country, not by prefix location.** The set
  contains every globally announced prefix of an ASN registered in China, plus
  the optional extras. A CN-registered ASN can announce address space outside
  China, so some foreign-hosted services may be included. If a host you must
  reach falls inside the set, add an explicit direct rule before the reject.
- **The rule set is IP-based.** A CN domain served from a non-CN CDN address
  will not match. This is a limitation of ASN/IP rules, not a bug.
- **The audit list is a snapshot, not a feed.** Review and update it manually
  when the source policy changes.
- **Deliberate audit exclusions:** OneDrive, speedtest/fast/speed.io, IP-lookup
  domains, and the full `10000-65535` port range.
- **Payload-only rules cannot be expressed as sing-box domain rules.** The
  `peer_id`, `info_hash`, `magnet`, `ed2k`, and SMTP-header rules from the
  source policy are omitted. BitTorrent is handled by protocol sniffing, and
  SMTP is handled by port blocks.

## Security notes

- Never commit a server configuration, credential, or private key. The
  repository's `.gitignore` excludes `config.json`, generated rule sets, logs,
  caches, and local probe files.
- Keep live configurations outside the repository checkout, owned by root and
  readable only by the service account.
- The published checksum protects against transport corruption only. If you
  need authenticity, pin a known digest or verify a signature.
- Review the audit rule set before applying it to a shared or production proxy.
  Several categories can block legitimate services.

## License

No license file is included. Add one before redistributing or reusing this
repository outside its intended deployment.
