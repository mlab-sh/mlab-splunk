#!/usr/bin/env bash
# The app inside a running Splunk container, no network needed: btool, unit tests on Splunk's own
# Pythons, | mlab, and mlab_ir posting to a fake ir.mlab.sh inside the container.
# CONTAINER (default: the dev stack's), SPLUNK_URL (default https://localhost:8089), SPLUNK_PASSWORD.
set -uo pipefail
cd "$(dirname "$0")/.."

C=${CONTAINER:-mlab-splunk-splunk-1}
URL=${SPLUNK_URL:-https://localhost:8089}
AUTH=admin:${SPLUNK_PASSWORD:-changeme123}
fails=0
ok() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
ko() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fails=$((fails+1)); }
sx() { docker exec -u splunk -e PYTHONDONTWRITEBYTECODE=1 "$C" "$@"; }  # no __pycache__ in the mounted app
# job <spl>: run a blocking search, print its sid
job() { curl -sk -u "$AUTH" "$URL/services/search/jobs" -d exec_mode=blocking -d output_mode=json --data-urlencode "search=$1" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["sid"])'; }
results() { curl -sk -u "$AUTH" "$URL/services/search/jobs/$1/results?output_mode=json&count=0"; }
searchlog() { sx cat "/opt/splunk/var/run/splunk/dispatch/$1/search.log"; }

# Splunk < 10.2 does not know python.required (it keeps using python.version / python3): expected there
out=$(sx /opt/splunk/bin/splunk btool check --app=mlab 2>&1 | grep -v 'python.required (value: 3.13)')
[ -z "$out" ] && ok "btool check clean" || { ko "btool check"; sed 's/^/    /' <<<"$out"; }

docker exec -u root "$C" sh -c 'rm -rf /tmp/mlab-t /tmp/mlab-ir.jsonl && mkdir -p /tmp/mlab-t && ln -s /opt/splunk/etc/apps/mlab /tmp/mlab-t/mlab'
docker cp -q tests "$C:/tmp/mlab-t/tests"
for py in python3.9 python3.13; do
  sx test -x "/opt/splunk/bin/$py" || continue
  if o=$(sx sh -c "cd /tmp/mlab-t && /opt/splunk/bin/splunk cmd $py -m unittest discover -s tests 2>&1"); then
    ok "unit tests on Splunk's $py ($(grep -oE 'Ran [0-9]+ tests' <<<"$o"))"
  else ko "unit tests on Splunk's $py"; tail -15 <<<"$o" | sed 's/^/    /'; fi
done

sid=$(job '| makeresults | eval src="10.0.0.1" | mlab type=ip | eval ran="yes"')
r=$(results "$sid")
grep -q '"ran":"yes"' <<<"$r" && ! grep -q '"mlab_type":"' <<<"$r" && ok "| mlab runs (private IP left alone, no network)" \
  || { ko "| mlab: ${r:0:300}"; searchlog "$sid" | grep -iE 'error|mlab' | tail -5 | sed 's/^/    /'; }
py=$(sx grep -ohE 'python3\.[0-9]+' "/opt/splunk/var/run/splunk/dispatch/$sid/search.log" | sort -u | tr '\n' ' ')
echo "    (search.log mentions: ${py:-no python version})"

# mlab_ir -> fake ir.mlab.sh on 127.0.0.1:18080 inside the container, recording each POST
docker exec -u root "$C" pkill -f 18080  # a leftover from an interrupted run would hold the port
docker exec -d -u splunk "$C" /opt/splunk/bin/splunk cmd python3 -c '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(s):
        b = s.rfile.read(int(s.headers["Content-Length"]))
        open("/tmp/mlab-ir.jsonl", "ab").write(s.headers["Authorization"].encode() + b" " + b + b"\n")
        s.send_response(200); s.end_headers(); s.wfile.write(b"{\"status\":\"created\",\"uuid\":\"fake\"}")
    def log_message(s, *a): pass
http.server.HTTPServer(("127.0.0.1", 18080), H).serve_forever()'
# keep a real token if there is one (dev stack); the fake server accepts anything
curl -sk -u "$AUTH" -o /dev/null "$URL/servicesNS/nobody/mlab/storage/passwords" -d realm=mlab -d name=ir_token -d password=mlab_app_ci
sleep 2
sid=$(job '| makeresults | eval file_hash="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", dest="web01", title="ci" | sendalert mlab_ir param.base_url="http://127.0.0.1:18080" param.severity=low')
sent=$(sx cat /tmp/mlab-ir.jsonl 2>/dev/null)
if grep -q '"title": "ci"' <<<"$sent" && grep -q '"severity": "low"' <<<"$sent" && grep -q 275a021b <<<"$sent" && grep -q '^token mlab_app_' <<<"$sent"; then
  ok "mlab_ir posted to ir with its token from storage/passwords"
else
  ko "mlab_ir: got '${sent:0:300}'"; searchlog "$sid" | grep -i 'mlab_ir\|sendmodalert' | tail -5 | sed 's/^/    /'
fi
docker exec -u root "$C" pkill -f 18080; docker exec -u root "$C" rm -rf /tmp/mlab-t /tmp/mlab-ir.jsonl

exit "$fails"
