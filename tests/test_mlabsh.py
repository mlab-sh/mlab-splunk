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
