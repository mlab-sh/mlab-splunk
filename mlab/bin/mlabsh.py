# mlab.sh lookups shared by the `mlab` search command and the `mlab_ir` alert action.
# Stdlib only, except secret() which uses the vendored splunklib.

import hashlib
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
PENDING_TTL = 3600       # a domain not scanned yet, or still scanning, is asked again after an hour
LOW_QUOTA = 0.1          # warn once when less than 10% of a kind's quota is left
REALM = 'mlab'           # storage/passwords realm: api_key (mlab.sh), ir_token (ir.mlab.sh)
USER_AGENT = 'mlab-splunk'

# Field looked up by default, and the response keys kept (as mlab_<key>) for each kind.
FIELDS = {'hash': 'file_hash', 'url': 'url', 'ip': 'src', 'cve': 'cve',
          'domain': 'query', 'email': 'src_user', 'ioc': '_raw'}
KEEP = {
    'hash': ('verdict', 'known_malicious', 'family', 'file_name', 'product', 'trust',
             'sources_hit', 'sources_answered', 'summary'),
    'url': ('host', 'findings', 'severities'),
    'cve': ('cvss_score', 'cvss_severity', 'epss_score', 'epss_percentile', 'in_kev', 'kev_date_added',
            'in_eu_kev', 'risk_score'),
    'ip': ('country_code', 'as', 'org', 'proxy', 'hosting', 'tor'),
    'domain': ('status', 'scan_date', 'score', 'grade', 'findings', 'severities'),
    'email': ('mailbox_type', 'is_disposable', 'is_free_provider', 'is_role', 'score', 'band',
              'spoofability', 'domain_age_days', 'findings', 'severities'),
    'ioc': ('ioc_total', 'ioc_types', 'iocs', 'truncated'),
}
IOC_MAX_BYTES = 1_048_576  # what /scan/ioc accepts

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


class KeyRefused(Exception):
    pass


KEY_REFUSED = ('mlab.sh refused the API key (401): unknown, revoked or expired. Keys expire after 90 days '
               'by default: create a new one (Organization settings > API keys) and save it in the app setup. '
               'mlab.sh lookups are skipped for the rest of this search')


class NotScanned(Exception):
    pass


def rate_limit(headers):
    """(remaining, limit, window seconds) from the X-RateLimit-* headers of a key call, or None."""
    try:
        return (int(headers['X-RateLimit-Remaining']), int(headers['X-RateLimit-Limit']),
                int(headers.get('X-RateLimit-Window') or QUOTA_BACKOFF))
    except (KeyError, TypeError, ValueError):
        return None


def call(url, key=None, data=None, meta=None):
    """GET (or POST `data` as JSON) and return the JSON body. `meta['rate']` gets the quota headers."""
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={'User-Agent': USER_AGENT})
    if body is not None:
        req.add_header('Content-Type', 'application/json')
    if key:
        req.add_header('Authorization', f'token {key}')
    try:
        with urllib.request.urlopen(req, timeout=20, context=TLS) as r:
            if meta is not None:
                meta['rate'] = rate_limit(r.headers)
            return json.load(r)
    except urllib.error.HTTPError as e:
        with e:
            body = e.read().decode(errors='replace')
        if e.code == 401 and key:
            raise KeyRefused(body)
        # spent quota: a 429 since 2026-10; older instances answer a 400 "... limit reached"
        if e.code == 429 or (e.code == 400 and 'limit' in body.lower()):
            raise QuotaReached(body)
        if e.code == 400 and 'no scan found' in body.lower():
            raise NotScanned(body)
        raise


def titles(findings):
    findings = findings or []
    return ([f.get('title') for f in findings],
            sorted({f.get('severity') for f in findings if f.get('severity')}))


def lookup(kind, value, key, base=BASE, meta=None):
    q = urllib.parse.quote(value, safe='')
    if kind == 'hash':
        r = call(f'{base}/scan/hash?hash={q}', key, meta=meta)
    elif kind == 'url':
        r = call(f'{base}/scan/url?url={q}', key, meta=meta)
        found, sev = titles(r.get('findings'))
        r = {'host': r.get('host'), 'findings': found, 'severities': sev}
    elif kind == 'cve':
        r = call(f'{VULN}/cve/{q}')  # public API: the key is not sent
    elif kind == 'ip':
        r = call(f'{base}/scan/ip?ip={q}', key, meta=meta)
        if isinstance(r.get('tor'), dict):
            r['tor'] = bool(r['tor'].get('is_tor'))
    elif kind == 'domain':
        # The last scan's v2 report. A Splunk search never launches a scan (that is a quota spend
        # per name): schedule the domains you watch on mlab.sh, this reads what they found.
        try:
            r = call(f'{base}/scan/domain/report?domain={q}', key, meta=meta)
        except NotScanned:
            return {'status': 'not_scanned'}
        score = r.get('score') if isinstance(r.get('score'), dict) else {}
        found, sev = titles(r.get('findings'))
        r = {'status': r.get('status'), 'scan_date': r.get('scan_date'), 'score': score.get('value'),
             'grade': score.get('grade'), 'findings': found, 'severities': sev}
    elif kind == 'email':
        r = call(f'{base}/scan/email?email={q}', key, meta=meta)
        score = r.get('score') if isinstance(r.get('score'), dict) else {}
        scan = r.get('domain_scan') if isinstance(r.get('domain_scan'), dict) else {}
        spoof = scan.get('spoofability') if isinstance(scan.get('spoofability'), dict) else {}
        found, sev = titles(r.get('findings'))
        r = dict(r, score=score.get('value'), band=score.get('band'), spoofability=spoof.get('verdict'),
                 domain_age_days=scan.get('domain_age_days'), findings=found, severities=sev)
    elif kind == 'ioc':
        r = call(f'{base}/scan/ioc', key, data={'text': value}, meta=meta)
        groups = r.get('iocs') if isinstance(r.get('iocs'), dict) else {}
        r = {'ioc_total': r.get('ioc_total'), 'ioc_types': sorted(groups), 'truncated': r.get('truncated'),
             'iocs': [f"{t}:{i.get('value')}" for t in sorted(groups) for i in groups[t] if i.get('value')]}
    else:
        raise ValueError(kind)
    return {k: r[k] for k in KEEP[kind] if r.get(k) is not None}


def wanted(kind, value):
    if kind == 'ioc':
        return len(value.encode()) <= IOC_MAX_BYTES
    if kind == 'email':
        return '@' in value and ' ' not in value
    if kind == 'domain':
        return '.' in value.strip('.') and ' ' not in value
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
            v = v.lower() if kind in ('hash', 'domain', 'email') else v  # Sysmon writes hashes upper case
            v = v.rstrip('.') if kind == 'domain' else v  # DNS logs keep the root dot
            res = cached_lookup(kind, v, key, cache, base, once)
            if res is not None:
                r['mlab_type'], r['mlab_value'] = kind, v
                for k, x in res.items():
                    r[f'mlab_{k}'] = splunk_value(x)
        yield r


def cached_lookup(kind, value, key, cache, base, warn):
    # a pasted event can be long: key the cache on a digest of it
    ck = f'{kind}:' + (hashlib.sha256(value.encode()).hexdigest() if kind == 'ioc' else value)
    res = cache.get(ck)
    if res is not None:
        return res
    if getattr(cache, 'key_refused', False):
        return None
    if cache.get(f'quota:{kind}'):
        warn(f'mlab.sh {kind} quota reached, {kind} lookups paused for up to an hour')
        return None
    meta = {}
    try:
        res = lookup(kind, value, key, base, meta)
    except KeyRefused:
        cache.key_refused = True  # this run only: a fixed key works on the next search
        warn(KEY_REFUSED)
        return None
    except QuotaReached:
        cache.put(f'quota:{kind}', True, QUOTA_BACKOFF)
        warn(f'mlab.sh {kind} quota reached, {kind} lookups paused for up to an hour')
        return None
    except Exception as e:  # network / API error: leave this value empty, retried next time
        warn(f'mlab.sh {kind} lookup failed: {e}')
        return None
    rate = meta.get('rate')
    if rate:
        remaining, limit, window = rate
        if remaining <= 0:  # the last one this window: park the kind now instead of eating a 429
            cache.put(f'quota:{kind}', True, min(window, QUOTA_BACKOFF))
            warn(f'mlab.sh {kind} quota reached, {kind} lookups paused for up to an hour')  # same text: warned once
        elif limit and remaining < limit * LOW_QUOTA:
            warn(f'mlab.sh {kind} quota low: {remaining} of {limit} left')
    pending = kind == 'domain' and res.get('status') in ('not_scanned', 'in_progress')
    cache.put(ck, res, PENDING_TTL if pending else TTL)
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
