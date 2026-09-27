#!/usr/bin/env bash
# Splunkbase checks (splunk-appinspect, precert mode) on the package built by dev/package.sh.
# Fails on failure/error only: splunk-appinspect itself exits 0 whatever it finds. Needs: pip install splunk-appinspect
set -euo pipefail
cd "$(dirname "$0")/.."
pkg=$(dev/package.sh)
splunk-appinspect inspect "$pkg" --mode precert --data-format json --output-file dist/appinspect.json >/dev/null
python3 - <<'PY'
import json, sys
r = json.load(open('dist/appinspect.json'))['reports'][0]
bad = 0
for g in r['groups']:
    for c in g['checks']:
        if c['result'] in ('failure', 'error', 'future_failure', 'warning'):
            print(f"{c['result'].upper():15} {c['name']}")
            for m in c['messages'][:2]:
                print(f"{'':16}{m['message'][:200]}")
            bad += c['result'] in ('failure', 'error')
print(r['summary'])
sys.exit(1 if bad else 0)
PY
