# hexward-wazuh

Wazuh decoder and rules for [Hexward Labs](https://hexwardlabs.com) security
tools. Every finding RuleHawk, Loglight, CertLight, Decoy, DmarcWatch,
Patchlight, TenantWatch or Attack Surface Monitor opens or resolves becomes a
Wazuh alert, at a level that matches its severity.

The products emit the [Hexward Finding Schema](https://github.com/nizartuanku/hexward-core/blob/main/SCHEMA.md)
(`hexward.finding/1`), so one rule set covers all of them. Free in every
edition of every Hexward product.

## What you get

| Finding | Wazuh rule | Level |
| --- | --- | --- |
| critical, opened | 100510 | 12 |
| high, opened | 100511 | 10 |
| medium, opened | 100512 | 7 |
| low, opened | 100513 | 4 |
| info, opened | 100514 | 3 |
| any severity, resolved | 100520 | 3 (closes the story, never pages) |
| snapshot (bulk export) | 100530 | 3 |

Alert descriptions read like `Hexward rulehawk: high - Deny rule 3 never
applies — shadowed by allow rule 2 on hq-asa`. All HFS fields are decoded with
their own names (`finding.check`, `finding.target`, `finding.fingerprint`,
`product`, `src_ip`, …), so you can filter and correlate on them. Groups:
`hexward`, `posture`, plus `hexward_open`/`hexward_<severity>`,
`hexward_resolved` or `hexward_snapshot`.

## Install (manager)

```sh
cp decoders/hexward_decoders.xml /var/ossec/etc/decoders/
cp rules/hexward_rules.xml       /var/ossec/etc/rules/
chown wazuh:wazuh /var/ossec/etc/decoders/hexward_decoders.xml /var/ossec/etc/rules/hexward_rules.xml
/var/ossec/bin/wazuh-control restart
./test/run-logtest.sh            # optional: every line should hit a 1005xx rule
```

Then pick how findings reach Wazuh.

### Path A — file + Wazuh agent (recommended)

On the host that runs the Hexward product, start it with

```sh
rulehawk -export-file /var/log/hexward/rulehawk.ndjson
```

and add [`config/agent-localfile.conf`](config/agent-localfile.conf) to the
agent. The agent already encrypts and buffers everything it sends to the
manager, so nothing extra is needed for transport security.

### Path B — syslog straight to the manager

When the product host has no agent:

```sh
rulehawk -syslog wazuh.example:5514 -syslog-format json -syslog-network tcp
```

and add [`config/manager-syslog.conf`](config/manager-syslog.conf) to the
manager, with your product hosts in `allowed-ips`. Both syslog headers work:
RFC 5424 (the products' default) and RFC 3164 (`-syslog-rfc 3164`).

## Good to know

- **Load current state once.** Live export only carries changes. To give
  Wazuh the findings that already exist, append a snapshot to the watched
  file: `curl -s http://127.0.0.1:8426/api/findings/export?format=hfs >> /var/log/hexward/rulehawk.ndjson`
  (use your product's port). Wazuh reads lines added to a file it already
  watches; lines written before it found the file are not read, so let Wazuh
  pick the file up first.
- **Transport security.** Wazuh's syslog listener has no TLS. Use path A
  when findings cross an untrusted network. TCP is recommended over UDP for
  path B, because UDP can drop events under load.
- **Evidence.** Evidence is redacted by the product before it is sent
  (secret-like keys dropped). Start the product with `-export-evidence none`
  to send none at all; `src_ip` is still populated.

## Tested

Wazuh manager 4.14.9 (Docker), October 2026:

- `wazuh-logtest`: all [test vectors](test) and both syslog headers hit the
  expected rule and level.
- Path A end to end: RuleHawk 0.1.3 writing NDJSON, read by the Wazuh
  logcollector, alerts 100511/100512/100513 with the expected levels.
- Path B end to end: RuleHawk 0.1.3 on a second host sending TCP syslog
  (RFC 5424) to the manager, all 10 findings decoded by `hexward` and alerted.

## License

Apache-2.0. © Nizar Tuanku — Cybersecurity.
