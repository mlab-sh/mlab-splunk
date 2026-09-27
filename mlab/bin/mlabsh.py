# mlab.sh lookups shared by the `mlab` search command and the `mlab_ir` alert action.
# Stdlib only, except secret() which uses the vendored splunklib.

import ipaddress
import json
import os
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))

BASE = 'https://mlab.sh/api/v1'
VULN = 'https://vuln.mlab.sh/api/v1'
TTL = 24 * 3600          # a verdict is reused for a day
QUOTA_BACKOFF = 3600     # after "limit reached", stop asking that kind for an hour
REALM = 'mlab'           # storage/passwords realm: api_key (mlab.sh), ir_token (ir.mlab.sh)
USER_AGENT = 'mlab-splunk'

# Field looked up by default, and the response keys kept (as mlab_<key>) for each kind.
FIELDS = {'hash': 'file_hash', 'url': 'url', 'ip': 'src', 'cve': 'cve'}
KEEP = {
    'hash': ('verdict', 'known_malicious', 'family', 'file_name', 'product', 'trust',
             'sources_hit', 'sources_answered', 'summary'),
    'url': ('host', 'findings', 'severities'),
    'cve': ('cvss_score', 'cvss_severity', 'epss_score', 'epss_percentile', 'in_kev', 'kev_date_added',
            'in_eu_kev', 'risk_score'),
    'ip': ('country_code', 'as', 'org', 'proxy', 'hosting', 'tor'),
}

try:  # some Splunk builds have no usable system CA store
    import certifi
    TLS = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    TLS = ssl.create_default_context()


def cache_path():
    return os.path.join(os.environ.get('SPLUNK_HOME', '/opt/splunk'), 'var', 'run', 'splunk', 'mlab-cache.db')


class Cache:
    def __init__(self, path):
        try:
            self.db = sqlite3.connect(path, timeout=10)
            self.db.execute('CREATE TABLE IF NOT EXISTS c (k TEXT PRIMARY KEY, v TEXT, exp REAL)')
        except sqlite3.Error:  # no persistent cache is better than no enrichment
            self.db = sqlite3.connect(':memory:')
            self.db.execute('CREATE TABLE c (k TEXT PRIMARY KEY, v TEXT, exp REAL)')

    def get(self, k):
        row = self.db.execute('SELECT v FROM c WHERE k=? AND exp>?', (k, time.time())).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, k, v, ttl=TTL):
        self.db.execute('REPLACE INTO c VALUES (?,?,?)', (k, json.dumps(v), time.time() + ttl))
        self.db.commit()

    def close(self):
        self.db.close()


class QuotaReached(Exception):
    pass


def call(url, key=None):
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    if key:
        req.add_header('Authorization', f'token {key}')
    try:
        with urllib.request.urlopen(req, timeout=20, context=TLS) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        with e:
            body = e.read().decode(errors='replace')
        # mlab.sh answers quota exhaustion with a 400 "... limit reached", not a 429
        if e.code in (400, 429) and 'limit' in body.lower():
            raise QuotaReached(body)
        raise


def lookup(kind, value, key, base=BASE):
    q = urllib.parse.quote(value, safe='')
    if kind == 'hash':
        r = call(f'{base}/scan/hash?hash={q}', key)
    elif kind == 'url':
        r = call(f'{base}/scan/url?url={q}', key)
        findings = r.get('findings') or []
        r = {'host': r.get('host'), 'findings': [f.get('title') for f in findings],
             'severities': sorted({f.get('severity') for f in findings if f.get('severity')})}
    elif kind == 'cve':
        r = call(f'{VULN}/cve/{q}')  # public API: the key is not sent
    elif kind == 'ip':
        r = call(f'{base}/scan/ip?ip={q}', key)
        if isinstance(r.get('tor'), dict):
            r['tor'] = bool(r['tor'].get('is_tor'))
    else:
        raise ValueError(kind)
    return {k: r[k] for k in KEEP[kind] if r.get(k) is not None}


def wanted(kind, value):
    if kind != 'ip':
        return True
    try:
        return ipaddress.ip_address(value).is_global  # never send internal IPs out
    except ValueError:
        return False


def splunk_value(v):
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, dict):
        return json.dumps(v)
    return v


def enrich(records, kind, field, key, cache, base=BASE, warn=print):
    """Adds mlab_type, mlab_value and mlab_<key> to each record whose `field` holds a single value.
    Every record gets every output field (empty when unknown): splunklib takes the column list from the first record."""
    out = ['mlab_type', 'mlab_value'] + [f'mlab_{k}' for k in KEEP[kind]]
    warned = set()

    def once(msg):
        if msg not in warned:
            warned.add(msg)
            warn(msg)

    for r in records:
        for f in out:
            r.setdefault(f, None)
        v = r.get(field)
        if isinstance(v, str) and v and wanted(kind, v):  # multivalue fields: mvexpand first
            v = v.lower() if kind == 'hash' else v  # Sysmon writes hashes upper case
            res = cached_lookup(kind, v, key, cache, base, once)
            if res is not None:
                r['mlab_type'], r['mlab_value'] = kind, v
                for k, x in res.items():
                    r[f'mlab_{k}'] = splunk_value(x)
        yield r


def cached_lookup(kind, value, key, cache, base, warn):
    ck = f'{kind}:{value}'
    res = cache.get(ck)
    if res is not None:
        return res
    if cache.get(f'quota:{kind}'):
        warn(f'mlab.sh {kind} quota reached, {kind} lookups paused for up to an hour')
        return None
    try:
        res = lookup(kind, value, key, base)
    except QuotaReached:
        cache.put(f'quota:{kind}', True, QUOTA_BACKOFF)
        warn(f'mlab.sh {kind} quota reached, {kind} lookups paused for up to an hour')
        return None
    except Exception as e:  # network / API error: leave this value empty, retried next time
        warn(f'mlab.sh {kind} lookup failed: {e}')
        return None
    cache.put(ck, res)
    return res


def secret(splunkd_uri, session_key, name):
    """storage/passwords entry realm=mlab, username=name, as seen by the calling user (None if absent)."""
    from splunklib import client
    u = urllib.parse.urlsplit(splunkd_uri)
    service = client.Service(scheme=u.scheme, host=u.hostname, port=u.port, token=session_key,
                             app='mlab', owner='nobody')
    for p in service.storage_passwords.list(count=-1):
        if p.content.get('realm') == REALM and p.content.get('username') == name:
            return p.content.get('clear_password')
    return None
