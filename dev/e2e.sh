#!/usr/bin/env bash
# End-to-end checks against the running dev stack (dev/setup.sh first).
# Chain under test: HEC event -> saved search -> | mlab (mlab.sh) -> alert -> mlab_ir -> ir.mlab.sh
set -uo pipefail
cd "$(dirname "$0")/.."

IR=http://localhost:8080
SPLUNK=https://localhost:8089
HEC=https://localhost:8088/services/collector/event
HEC_TOKEN=6d6c6162-0000-4000-8000-000000000001
AUTH=admin:changeme123
GEN=dev/.generated
EICAR_SHA=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
fails=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
ko()   { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fails=$((fails+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$*"; }
step() { printf '\n\033[1m[%s]\033[0m\n' "$*"; }
sp()   { curl -sk -u "$AUTH" "$@"; }
# search <spl>: results as JSON lines
search() { sp "$SPLUNK/services/search/v2/jobs/export" -d output_mode=json --data-urlencode "search=$1"; }
# wait_for <seconds> <command...>: retry every 3s until the command succeeds
wait_for() { local end=$((SECONDS+$1)); shift; until "$@"; do [ $SECONDS -ge $end ] && return 1; sleep 3; done; }
jf() { python3 -c 'import json,sys
for l in sys.stdin:
    r = json.loads(l).get("result")
    if r: print(r.get(sys.argv[1], "")); break' "$1"; }
hec() { curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Splunk $HEC_TOKEN" "$HEC" -d "{\"sourcetype\":\"_json\",\"event\":$1}"; }
ss() { printf '%s' "$1" | python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read(), safe=""))'; }
# fire <saved search>: enable it with the mlab_ir action and run it now over the last hour.
# Put back to disabled on exit: disabling it before the alert is post-processed makes Splunk drop it ("alert is invalid").
fired=()
ss_url() { echo "$SPLUNK/servicesNS/nobody/mlab/saved/searches/$(ss "$1")"; }
fire() {
  sp -o /dev/null "$(ss_url "$1")" -d disabled=0 -d actions=mlab_ir
  sp -o /dev/null "$(ss_url "$1")/dispatch" -d trigger_actions=1 -d dispatch.earliest_time=-1h -d dispatch.latest_time=now
  fired+=("$1")
}
restore() { for s in "${fired[@]+"${fired[@]}"}"; do sp -o /dev/null "$(ss_url "$s")" -d disabled=1 -d actions=; done; }
trap restore EXIT
# mlab_ir logs "<search> -> created|duplicate <ir uuid>" on stderr, which lands in splunkd.log
ir_lines() { docker compose exec -T -u splunk splunk grep -h "mlab_ir: $1 -> " /opt/splunk/var/log/splunk/splunkd.log 2>/dev/null; }
irlogin() { curl -s -c "$GEN/ir_cookies" -o /dev/null -H 'Content-Type: application/json' \
  -d '{"email":"admin@localhost","password":"adminadmin"}' "$IR/api/v1/auth/login"; }

free_gb=$(df -g . | awk 'NR==2 {print $4}')
[ "$free_gb" -ge 5 ] || { echo "only ${free_gb} GB free on disk (< 5 GB), stop the stack first: docker compose stop"; exit 1; }

step "1. Unit tests"
if out=$(python3 -m unittest discover -s tests 2>&1); then ok "$(tail -1 <<<"$out") ($(grep -oE 'Ran [0-9]+ tests' <<<"$out"))"
else ko "unit tests"; tail -20 <<<"$out" | sed 's/^/    /'; fi

step "2. Services and app"
curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/ | grep -qE '200|303' && ok "Splunk web http://localhost:8000" || ko "Splunk web"
curl -s -o /dev/null -w '%{http_code}' "$IR/" | grep -qE '^[23]' && ok "ir.mlab.sh $IR" || ko "ir.mlab.sh"
sp "$SPLUNK/services/apps/local/mlab?output_mode=json" | grep -q '"version": *"[0-9]' && ok "app mlab installed" || ko "app mlab not installed"
out=$(docker compose exec -T splunk sudo -u splunk /opt/splunk/bin/splunk btool check --app=mlab 2>&1)
[ -z "$out" ] && ok "btool check clean" || { ko "btool check"; sed 's/^/    /' <<<"$out"; }

step "3. | mlab against mlab.sh"
r=$(search "| makeresults | eval file_hash=\"$(tr a-f A-F <<<$EICAR_SHA)\" | mlab type=hash")
[ "$(jf mlab_verdict <<<"$r")" = known_malicious ] && ok "hash: EICAR -> known_malicious ($(jf mlab_file_name <<<"$r"))" || ko "hash: ${r:0:300}"
r=$(search '| makeresults | eval cve="CVE-2021-44228" | mlab type=cve')
[ "$(jf mlab_in_kev <<<"$r")" = true ] && ok "cve: Log4Shell in_kev=true cvss=$(jf mlab_cvss_score <<<"$r") epss=$(jf mlab_epss_score <<<"$r")" || ko "cve: ${r:0:300}"
r=$(search '| makeresults | eval url="http://bit.ly/invoice.exe" | mlab type=url')
[ "$(jf mlab_type <<<"$r")" = url ] && ok "url: findings=$(jf mlab_findings <<<"$r" | tr '\n' ' ')" || ko "url: ${r:0:300}"
r=$(search '| makeresults | eval src="10.0.0.5" | mlab type=ip')
[ -z "$(jf mlab_type <<<"$r")" ] && ok "ip: private 10.0.0.5 not sent" || ko "ip: private IP was looked up"
r=$(search '| makeresults | eval src="185.220.101.1" | mlab type=ip')
if [ "$(jf mlab_tor <<<"$r")" = true ]; then ok "ip: 185.220.101.1 tor=true country=$(jf mlab_country_code <<<"$r")"
elif grep -q 'quota' <<<"$r"; then skip "ip: mlab.sh IP quota reached (anonymous: 5/day)"
else ko "ip: ${r:0:300}"; fi

step "4. Full chain: EICAR seen on web01 -> 'mlab - Known malicious file' -> ir.mlab.sh"
ev='{"file_hash":"'$EICAR_SHA'","file_path":"/tmp/eicar.com","dest":"web01"}'  # bash 3.2: no nested quotes in $()
[ "$(hec "$ev")" = 200 ] && ok "event sent over HEC" || ko "HEC refused the event"
indexed() { [ -n "$(search "search index=main file_hash=$EICAR_SHA earliest=-1h | head 1" | jf file_hash)" ]; }
wait_for 60 indexed && ok "event indexed" || ko "event not searchable"
before=$(ir_lines 'mlab - Known malicious file' | wc -l)
fire 'mlab - Known malicious file'
new_line() { [ "$(ir_lines "$1" | wc -l)" -gt "$2" ]; }
if wait_for 60 new_line 'mlab - Known malicious file' "$before"; then
  read -r status1 uuid <<<"$(ir_lines 'mlab - Known malicious file' | tail -1 | awk '{print $(NF-1), $NF}')"
  ok "mlab_ir sent it: $status1 (uuid $uuid)"
  irlogin
  a=$(curl -s -b "$GEN/ir_cookies" "$IR/api/v1/alerts/$uuid")
  grep -q '"severity": *"high"' <<<"$a" && ok "ir alert severity high" || ko "severity: ${a:0:300}"
  grep -q 'Known malicious file' <<<"$a" && ok "ir alert title from the saved search" || ko "title: ${a:0:300}"
  obs=$(curl -s -b "$GEN/ir_cookies" "$IR/api/v1/observables/by-alert/$uuid")
  grep -q "$EICAR_SHA" <<<"$obs" && ok "observable: EICAR sha256" || ko "no hash observable"
  grep -q '/tmp/eicar.com' <<<"$obs" && ok "observable: file path" || ko "no filename observable"
  grep -q '"web01"' <<<"$obs" && ok "observable: hostname web01" || ko "no hostname observable"
else
  ko "mlab_ir did not run (splunkd.log: grep sendmodalert)"
  docker compose exec -T -u splunk splunk grep -h 'mlab_ir' /opt/splunk/var/log/splunk/splunkd.log | tail -5 | cut -c1-300 | sed 's/^/    /'
fi

step "5. Dedup: same malware on same host collapses in ir.mlab.sh"
before=$(ir_lines 'mlab - Known malicious file' | wc -l)
fire 'mlab - Known malicious file'
wait_for 60 new_line 'mlab - Known malicious file' "$before"
read -r status2 uuid2 <<<"$(ir_lines 'mlab - Known malicious file' | tail -1 | awk '{print $(NF-1), $NF}')"
[ "$status2" = duplicate ] && [ "$uuid2" = "${uuid:-x}" ] && ok "ir answered duplicate, same alert $uuid2" \
  || ko "expected duplicate of ${uuid:-?}, got '$status2 $uuid2'"

step "6. Known exploited CVE -> critical in ir.mlab.sh"
hec '{"cve":"CVE-2021-44228","dest":"web01","signature":"log4j 2.14.1"}' >/dev/null
cve_indexed() { [ -n "$(search 'search index=main cve=CVE-2021-44228 earliest=-1h | head 1' | jf cve)" ]; }
wait_for 60 cve_indexed || ko "CVE event not searchable"
before=$(ir_lines 'mlab - Known exploited CVE' | wc -l)
fire 'mlab - Known exploited CVE'
if wait_for 60 new_line 'mlab - Known exploited CVE' "$before"; then
  read -r st cu <<<"$(ir_lines 'mlab - Known exploited CVE' | tail -1 | awk '{print $(NF-1), $NF}')"
  irlogin
  a=$(curl -s -b "$GEN/ir_cookies" "$IR/api/v1/alerts/$cu")
  obs=$(curl -s -b "$GEN/ir_cookies" "$IR/api/v1/observables/by-alert/$cu")
  grep -q '"severity": *"critical"' <<<"$a" && grep -q 'CVE-2021-44228' <<<"$obs" \
    && ok "ir alert $cu ($st): critical, observable CVE-2021-44228" || ko "KEV alert: ${a:0:200}"
else
  ko "mlab_ir did not run for the CVE search"
fi

step "7. mlab_ir log (last lines)"
docker compose exec -T -u splunk splunk grep -h 'mlab_ir' /opt/splunk/var/log/splunk/splunkd.log | tail -4 | cut -c1-220 | sed 's/^/  /'

echo
[ "$fails" -eq 0 ] && printf '\033[32mAll checks passed.\033[0m\n' || printf '\033[31m%d check(s) failed.\033[0m\n' "$fails"
exit "$fails"
