#!/bin/sh
# Feeds the HFS test vectors through wazuh-logtest on a manager that has
# hexward_decoders.xml and hexward_rules.xml installed, and prints the rule
# that fired for each line. Usage (container): ./run-logtest.sh <container>
# Usage (host):      ./run-logtest.sh
set -eu
here=$(dirname "$0")
lines=$(mktemp)
for f in opened_with_ip resolved snapshot_group minimal_no_evidence; do
  cat "$here/$f.json" >>"$lines"
done
# Syslog path: RFC 3164 and RFC 5424 headers, as products send them.
printf 'Oct 28 09:12:44 fw-audit-01 hexward[4242]: %s\n' "$(cat "$here/opened_with_ip.json")" >>"$lines"
printf '1 2026-10-28T09:12:44.000Z fw-audit-01 hexward 4242 finding - %s\n' "$(cat "$here/opened_with_ip.json")" >>"$lines"
if [ $# -ge 1 ]; then run="docker exec -i $1 /var/ossec/bin/wazuh-logtest"; else run=/var/ossec/bin/wazuh-logtest; fi
$run <"$lines" 2>&1 | grep -E "^\s+(name|id|level): " | grep -v 'finding\.' | tr -d "\t'" | paste - - -
rm -f "$lines"
