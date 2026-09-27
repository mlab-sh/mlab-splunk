#!/usr/bin/env python
# Custom alert action (and ES adaptive response): one ir.mlab.sh alert per search result,
# via POST <base_url>/api/v1/ingest/alert. The app token is storage/passwords realm=mlab name=ir_token.

import csv
import gzip
import ipaddress
import itertools
import json
import os
import sys
import urllib.request

import mlabsh

SEVERITIES = ('info', 'low', 'medium', 'high', 'critical')
MAX_RESULTS = 100  # ponytail: first 100 results per trigger; raise it or batch if searches return more
MLAB_TYPES = {'hash': 'hash', 'url': 'url', 'cve': 'cve'}  # ip: type auto-detected by ir


def log(level, msg):
    print(f'{level} mlab_ir: {msg}', file=sys.stderr)  # sendmodalert copies stderr into splunkd.log


def rows(results_file):
    csv.field_size_limit(10 * 1024 * 1024)  # _raw can be big
    with gzip.open(results_file, 'rt', newline='') as f:
        for r in csv.DictReader(f):
            # a multivalue field is newline-joined, with its $a$;$b$ form in __mv_<field>
            yield {k: v.split('\n') if r.get(f'__mv_{k}') else v
                   for k, v in r.items() if v and not k.startswith('__mv_')}


def values(row, *names):
    out = []
    for n in names:
        v = row.get(n)
        out += v if isinstance(v, list) else [v] if v else []
    return out


def first(row, *names):
    return next(iter(values(row, *names)), None)


def observables(row):
    out = []
    for v in values(row, 'src', 'src_ip', 'dest', 'dest_ip', 'dvc'):
        try:
            ipaddress.ip_address(v)
            out.append({'value': v})  # ipv4/ipv6 auto-detected by ir
        except ValueError:
            out.append({'value': v, 'type': 'hostname'})
    out += [{'value': v.lower(), 'type': 'hash'} for v in values(row, 'file_hash', 'sha256', 'md5')]
    mlab_type, mlab_value = first(row, 'mlab_type'), first(row, 'mlab_value')
    if mlab_type and mlab_value:
        out.append({'value': mlab_value, 'type': MLAB_TYPES[mlab_type]} if mlab_type in MLAB_TYPES
                   else {'value': mlab_value})
    for names, t in ((('url',), 'url'), (('cve',), 'cve'), (('file_path', 'file_name'), 'filename'),
                     (('host',), 'hostname')):
        out += [{'value': v, 'type': t} for v in values(row, *names)]
    seen, uniq = set(), []
    for o in out:
        if o['value'] not in seen:
            seen.add(o['value'])
            uniq.append(o)
    return uniq[:100]  # ir.mlab.sh caps observables per alert at 100


def payload(row, search_name, severity='medium'):
    # ES notables carry severity/urgency, rule_name and event_id; plain searches may set severity/title
    sev = next((s for s in (first(row, 'severity'), first(row, 'urgency')) if s in SEVERITIES), severity)
    context = [f'Search: {search_name}']
    context += [f'{k}: {", ".join(v) if isinstance(v, list) else v}' for k, v in row.items() if not k.startswith('_')]
    if row.get('_raw'):
        context += ['', row['_raw']]
    p = {
        'title': first(row, 'title', 'rule_name') or search_name,
        'severity': sev,
        'source': 'splunk',
        'external_id': first(row, 'event_id'),
        # same search + host (+ same mlab indicator) collapses into one ir alert
        'dedup_key': ':'.join(x for x in ('splunk', search_name, first(row, 'dest', 'host'),
                                          first(row, 'mlab_value')) if x),
        'description': '\n'.join(context),
        'tags': [search_name] + values(row, 'mitre_technique_id'),
        'observables': observables(row),
    }
    return {k: v for k, v in p.items() if v is not None}


def post(base, token, body):
    req = urllib.request.Request(base.rstrip('/') + '/api/v1/ingest/alert',
                                 data=json.dumps(body).encode(), method='POST',
                                 headers={'Content-Type': 'application/json', 'User-Agent': mlabsh.USER_AGENT,
                                          'Authorization': f'token {token}'})
    with urllib.request.urlopen(req, timeout=20, context=mlabsh.TLS) as r:
        res = json.load(r)
    # ir.mlab.sh rate limiting answers 200 with {"status":"error"}
    if res.get('status') == 'error':
        raise RuntimeError(res.get('error'))
    return res


def run(p, token=None):
    cfg = p.get('configuration') or {}
    base = cfg.get('base_url')
    if not base:
        raise ValueError('base_url (ir.mlab.sh URL) is not set')
    token = token or mlabsh.secret(p['server_uri'], p['session_key'], 'ir_token')
    if not token:
        raise ValueError('no ir.mlab.sh app token: storage/passwords realm=mlab name=ir_token')
    severity = cfg.get('severity') if cfg.get('severity') in SEVERITIES else 'medium'
    name = p.get('search_name') or 'Splunk alert'
    results = rows(p['results_file']) if os.path.isfile(p.get('results_file') or '') else [p.get('result') or {}]
    failed = 0
    for row in itertools.islice(results, MAX_RESULTS):
        try:
            res = post(base, token, payload(row, name, severity))
            log('INFO', f'{name} -> {res.get("status")} {res.get("uuid")}')
        except Exception as e:  # keep sending the other results
            log('ERROR', f'{name}: {e}')
            failed += 1
    return 2 if failed else 0


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] != '--execute':
        log('FATAL', 'unsupported execution mode (expected --execute)')
        sys.exit(1)
    try:
        sys.exit(run(json.load(sys.stdin)))
    except Exception as e:
        log('ERROR', str(e))
        sys.exit(2)
