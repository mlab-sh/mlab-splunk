import os
import tempfile
import unittest

from helpers import FakeAPI
import mlabsh as m

SHA = 'a' * 64
HASH_OK = {'verdict': 'known_malicious', 'known_malicious': True, 'file_name': 'x.exe',
           'sources_hit': 1, 'sources': {'noise': 'dropped'}, 'cached': True}
HASH_FIELDS = ['mlab_type', 'mlab_value'] + [f'mlab_{k}' for k in m.KEEP['hash']]


class Enrich(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI({'/scan/hash': (200, HASH_OK)})
        self.cache = m.Cache(os.path.join(tempfile.mkdtemp(), 'c.db'))
        self.warnings = []

    def tearDown(self):
        self.api.close()
        self.cache.close()

    def go(self, records, kind='hash', field=None):
        return list(m.enrich(records, kind, field or m.FIELDS[kind], 'mlab_k', self.cache, self.api.url,
                             warn=self.warnings.append))

    def test_hash_end_to_end(self):
        r, = self.go([{'file_hash': SHA.upper(), 'dest': 'web01'}])
        req, = self.api.requests
        self.assertEqual(req['path'], f'/scan/hash?hash={SHA}')  # lower-cased
        self.assertEqual(req['headers']['Authorization'], 'token mlab_k')
        self.assertEqual({k: v for k, v in r.items() if v is not None}, {
            'file_hash': SHA.upper(), 'dest': 'web01', 'mlab_type': 'hash', 'mlab_value': SHA,
            'mlab_verdict': 'known_malicious', 'mlab_known_malicious': 'true', 'mlab_file_name': 'x.exe',
            'mlab_sources_hit': 1})

    def test_every_record_gets_every_output_field(self):
        # splunklib takes the column list from the first record: a field it lacks is dropped for all
        out = self.go([{'other': 1}, {'file_hash': SHA}, {'file_hash': ['x', 'y']}])
        for r in out:
            self.assertTrue(set(HASH_FIELDS) <= set(r), r)
        self.assertEqual([r['mlab_verdict'] for r in out], [None, 'known_malicious', None])
        self.assertEqual(len(self.api.requests), 1)  # multivalue skipped

    def test_custom_field(self):
        r, = self.go([{'sha': SHA}], field='sha')
        self.assertEqual(r['mlab_value'], SHA)

    def test_cache_hit_skips_api(self):
        self.go([{'file_hash': SHA}, {'file_hash': SHA}])
        self.go([{'file_hash': SHA}])
        self.assertEqual(len(self.api.requests), 1)

    def test_internal_and_garbage_ips_never_sent(self):
        for ip in ('10.0.0.1', '192.168.1.1', '127.0.0.1', '100.64.0.1', 'fe80::1', 'any', 'not-an-ip'):
            r, = self.go([{'src': ip}], 'ip')
            self.assertIsNone(r['mlab_type'], ip)
        self.assertEqual(self.api.requests, [])

    def test_quota_400_parks_only_that_kind(self):
        self.api.routes['/scan/ip'] = (400, {'error': 'IP lookup limit reached. Please try again later.'})
        self.go([{'src': '8.8.8.8'}, {'src': '1.1.1.1'}], 'ip')
        self.go([{'file_hash': SHA}])
        paths = [r['path'].split('?')[0] for r in self.api.requests]
        self.assertEqual(paths, ['/scan/ip', '/scan/hash'])  # 2nd IP never asked, hashes still are
        self.assertEqual(self.warnings, ['mlab.sh ip quota reached, ip lookups paused for up to an hour'])

    def test_other_errors_are_retried_next_time(self):
        self.api.routes['/scan/hash'] = (500, {'error': 'boom'})
        r, = self.go([{'file_hash': SHA}])
        self.go([{'file_hash': SHA}])
        self.assertEqual(len(self.api.requests), 2)  # neither cached nor parked
        self.assertIsNone(r['mlab_verdict'])
        self.assertIn('lookup failed', self.warnings[0])

    def test_plain_400_is_not_mistaken_for_quota(self):
        self.api.routes['/scan/hash'] = (400, {'error': 'invalid hash'})
        self.go([{'file_hash': SHA}])
        self.go([{'file_hash': SHA}])
        self.assertEqual(len(self.api.requests), 2)

    def test_url_and_ip_responses_trimmed(self):
        self.api.routes['/scan/url'] = (200, {'host': 'bit.ly', 'findings': [
            {'severity': 'high', 'title': 'Executable payload'}, {'severity': 'medium', 'title': 'Shortener'},
            {'severity': 'high', 'title': 'Other'}]})
        self.api.routes['/scan/ip'] = (200, {'country_code': 'DE', 'tor': {'available': True, 'is_tor': True},
                                             'rdap': {'big': 'dropped'}})
        url, = self.go([{'url': 'http://bit.ly/x.exe'}], 'url')
        ip, = self.go([{'src': '185.220.101.1'}], 'ip')
        self.assertEqual(url['mlab_findings'], ['Executable payload', 'Shortener', 'Other'])
        self.assertEqual(url['mlab_severities'], ['high', 'medium'])
        self.assertEqual(self.api.requests[0]['path'], '/scan/url?url=http%3A%2F%2Fbit.ly%2Fx.exe')
        self.assertEqual({k: v for k, v in ip.items() if v is not None},
                         {'src': '185.220.101.1', 'mlab_type': 'ip', 'mlab_value': '185.220.101.1',
                          'mlab_country_code': 'DE', 'mlab_tor': 'true'})

    def test_cve_keeps_prioritisation_fields_and_no_key(self):
        self.api.routes['/cve/CVE-2021-44228'] = (200, {
            'id': 'CVE-2021-44228', 'description': 'long text', 'cvss_score': 10.0, 'cvss_severity': 'CRITICAL',
            'epss_score': 0.94, 'in_kev': True, 'kev_date_added': '2021-12-10', 'in_eu_kev': False,
            'kev_due_date': None, 'references': [{'url': 'x'}], 'risk_score': 99.9})
        m.VULN, saved = self.api.url, m.VULN
        try:
            r, = self.go([{'cve': 'CVE-2021-44228'}], 'cve')
        finally:
            m.VULN = saved
        self.assertEqual({k: v for k, v in r.items() if k.startswith('mlab_') and v is not None}, {
            'mlab_type': 'cve', 'mlab_value': 'CVE-2021-44228', 'mlab_cvss_score': 10.0,
            'mlab_cvss_severity': 'CRITICAL', 'mlab_epss_score': 0.94, 'mlab_in_kev': 'true',
            'mlab_kev_date_added': '2021-12-10', 'mlab_in_eu_kev': 'false', 'mlab_risk_score': 99.9})
        self.assertIsNone(self.api.requests[0]['headers'].get('Authorization'))  # public API, key not leaked

    def test_quota_429_parks_the_kind(self):
        self.api.routes['/scan/hash'] = (429, {'error': 'Daily hash lookup quota reached.'}, {'Retry-After': '3600'})
        self.go([{'file_hash': SHA}, {'file_hash': 'b' * 64}])
        self.assertEqual(len(self.api.requests), 1)
        self.assertIn('quota reached', self.warnings[0])

    def test_rate_limit_headers_park_before_the_429(self):
        last = {'X-RateLimit-Limit': '100', 'X-RateLimit-Remaining': '0', 'X-RateLimit-Resource': 'hash',
                'X-RateLimit-Window': '86400'}
        self.api.routes['/scan/hash'] = (200, HASH_OK, last)
        out = self.go([{'file_hash': SHA}, {'file_hash': 'b' * 64}])
        self.assertEqual(len(self.api.requests), 1)  # the 2nd hash would have been the 429
        self.assertEqual(out[0]['mlab_verdict'], 'known_malicious')  # the last allowed answer is kept
        self.assertEqual(self.warnings, ['mlab.sh hash quota reached, hash lookups paused for up to an hour'])
        self.go([{'file_hash': 'x'}, {'file_hash': 'c' * 64}])
        self.assertEqual(len(self.api.requests), 1)  # still parked on the next search

    def test_low_quota_warns_once(self):
        self.api.routes['/scan/hash'] = (200, HASH_OK, {'X-RateLimit-Limit': '100', 'X-RateLimit-Remaining': '5'})
        self.go([{'file_hash': SHA}, {'file_hash': 'b' * 64}])
        self.assertEqual(len(self.api.requests), 2)
        self.assertEqual(self.warnings, ['mlab.sh hash quota low: 5 of 100 left'])

    def test_refused_key_warns_once_and_stops_the_run(self):
        self.api.routes['/scan/hash'] = (401, {'error': 'Unauthorized'})
        self.api.routes['/scan/ip'] = (401, {'error': 'Unauthorized'})
        out = self.go([{'file_hash': SHA}, {'file_hash': 'b' * 64}])
        self.go([{'src': '8.8.8.8'}], 'ip')
        self.assertEqual(len(self.api.requests), 1)
        self.assertEqual(self.warnings, [m.KEY_REFUSED])
        self.assertIn('expired', m.KEY_REFUSED)
        self.assertIsNone(out[0]['mlab_verdict'])
        self.api.routes['/scan/hash'] = (200, HASH_OK)  # nothing cached: a fixed key works next search
        self.cache.key_refused = False
        r, = self.go([{'file_hash': SHA}])
        self.assertEqual(r['mlab_verdict'], 'known_malicious')

    def test_domain_reads_the_v2_report(self):
        self.api.routes['/scan/domain/report'] = (200, {
            'schema': 'domain-report/2', 'domain': 'example.com', 'status': 'completed',
            'scan_date': '2026-11-01 10:00:00', 'score': {'value': 72, 'grade': 'C'},
            'findings': [{'severity': 'high', 'title': 'No DMARC', 'section': 'mail'},
                         {'severity': 'low', 'title': 'No CAA'}], 'dns': {'big': 'dropped'}})
        r, = self.go([{'query': 'Example.COM.'}], 'domain')
        self.assertEqual(self.api.requests[0]['path'], '/scan/domain/report?domain=example.com')
        self.assertEqual({k: v for k, v in r.items() if k.startswith('mlab_') and v is not None}, {
            'mlab_type': 'domain', 'mlab_value': 'example.com', 'mlab_status': 'completed',
            'mlab_scan_date': '2026-11-01 10:00:00', 'mlab_score': 72, 'mlab_grade': 'C',
            'mlab_findings': ['No DMARC', 'No CAA'], 'mlab_severities': ['high', 'low']})

    def test_domain_and_email_values_that_cannot_be_one_are_not_sent(self):
        for v in ('localhost', 'two words.com', '.'):
            r, = self.go([{'query': v}], 'domain')
            self.assertIsNone(r['mlab_type'], v)
        r, = self.go([{'src_user': 'a b@x.com'}], 'email')
        self.assertIsNone(r['mlab_type'])
        self.assertEqual(self.api.requests, [])

    def test_unscanned_domain_is_not_an_error(self):
        self.api.routes['/scan/domain/report'] = (400, {'error': 'No scan found for the provided domain.'})
        r, = self.go([{'query': 'new.example'}], 'domain')
        self.go([{'query': 'new.example'}], 'domain')
        self.assertEqual(r['mlab_status'], 'not_scanned')
        self.assertEqual(self.warnings, [])
        self.assertEqual(len(self.api.requests), 1)  # cached (for an hour)

    def test_email(self):
        self.api.routes['/scan/email'] = (200, {
            'email': 'a@x.com', 'mailbox_type': 'personal', 'is_disposable': True, 'is_free_provider': False,
            'is_role': False, 'score': {'value': 80, 'band': 'critical', 'reasons': ['x']},
            'domain_scan': {'spoofability': {'verdict': 'Trivially spoofable', 'summary': '...'}, 'domain_age_days': 3},
            'findings': [{'severity': 'high', 'title': 'Disposable domain'}]})
        r, = self.go([{'src_user': 'A@X.com'}, ], 'email')
        nope, = self.go([{'src_user': 'not-an-address'}], 'email')
        self.assertEqual(self.api.requests[0]['path'], '/scan/email?email=a%40x.com')
        self.assertEqual({k: v for k, v in r.items() if k.startswith('mlab_') and v is not None}, {
            'mlab_type': 'email', 'mlab_value': 'a@x.com', 'mlab_mailbox_type': 'personal',
            'mlab_is_disposable': 'true', 'mlab_is_free_provider': 'false', 'mlab_is_role': 'false',
            'mlab_score': 80, 'mlab_band': 'critical', 'mlab_spoofability': 'Trivially spoofable', 'mlab_domain_age_days': 3,
            'mlab_findings': ['Disposable domain'], 'mlab_severities': ['high']})
        self.assertIsNone(nope['mlab_type'])
        self.assertEqual(len(self.api.requests), 1)

    def test_ioc_posts_the_text_and_flattens_groups(self):
        self.api.routes['/scan/ioc'] = (200, {'status': 'ok', 'ioc_total': 3, 'truncated': False, 'iocs': {
            'ip': [{'value': '8.8.8.8', 'link': '/ip/8.8.8.8'}],
            'domain': [{'value': 'evil.com', 'link': '/domain/evil.com'}, {'value': 'bad.org', 'link': 'x'}]}})
        raw = 'beacon to 8.8.8.8 and evil.com, bad.org'
        r, = self.go([{'_raw': raw}, ], 'ioc')
        self.go([{'_raw': raw}], 'ioc')
        req, = self.api.requests  # the second one comes from the cache
        self.assertEqual((req['method'], req['path'], req['body']), ('POST', '/scan/ioc', {'text': raw}))
        self.assertEqual(req['headers']['Content-Type'], 'application/json')
        self.assertEqual(r['mlab_ioc_total'], 3)
        self.assertEqual(r['mlab_ioc_types'], ['domain', 'ip'])
        self.assertEqual(r['mlab_iocs'], ['domain:evil.com', 'domain:bad.org', 'ip:8.8.8.8'])
        self.assertEqual(r['mlab_truncated'], 'false')


class Cache(unittest.TestCase):
    def test_expiry(self):
        c = m.Cache(os.path.join(tempfile.mkdtemp(), 'c.db'))
        c.put('k', {'v': 1})
        c.put('old', {'v': 2}, ttl=-1)
        self.assertEqual(c.get('k'), {'v': 1})
        self.assertIsNone(c.get('old'))
        self.assertIsNone(c.get('missing'))
        c.close()

    def test_unwritable_cache_still_works(self):
        c = m.Cache('/nonexistent-dir/mlab-cache.db')
        c.put('k', 1)
        self.assertEqual(c.get('k'), 1)
        c.close()


if __name__ == '__main__':
    unittest.main()
