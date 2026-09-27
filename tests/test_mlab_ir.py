import csv
import gzip
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr

from helpers import BIN, FakeAPI
import mlab_ir as m

SHA = 'a' * 64
INGEST = '/api/v1/ingest/alert'
ROW = {'file_hash': SHA, 'dest': ['web01', '10.0.0.5'], 'file_path': '/tmp/x.exe', 'count': '2',
       'mlab_type': 'hash', 'mlab_value': SHA, 'mlab_verdict': 'known_malicious'}


def results_file(rows):
    """What Splunk hands the alert action: gzipped CSV, multivalue fields newline-joined + __mv_ column."""
    cols = sorted({k for r in rows for k in r})
    header = [c for k in cols for c in (k, f'__mv_{k}')]
    path = os.path.join(tempfile.mkdtemp(), 'results.csv.gz')
    with gzip.open(path, 'wt', newline='') as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            line = []
            for k in cols:
                v = r.get(k, '')
                line += ['\n'.join(v), ';'.join(f'${x}$' for x in v)] if isinstance(v, list) else [v, '']
            w.writerow(line)
    return path


class Payload(unittest.TestCase):
    def test_mapping(self):
        p = m.payload(ROW, 'mlab - Known malicious file', 'high')
        self.assertEqual(p['title'], 'mlab - Known malicious file')
        self.assertEqual(p['severity'], 'high')
        self.assertEqual(p['source'], 'splunk')
        self.assertNotIn('external_id', p)
        self.assertEqual(p['dedup_key'], f'splunk:mlab - Known malicious file:web01:{SHA}')
        self.assertEqual(p['tags'], ['mlab - Known malicious file'])
        self.assertEqual(p['description'].splitlines()[:3], [
            'Search: mlab - Known malicious file', f'file_hash: {SHA}', 'dest: web01, 10.0.0.5'])
        self.assertEqual(p['observables'], [
            {'value': 'web01', 'type': 'hostname'}, {'value': '10.0.0.5'},
            {'value': SHA, 'type': 'hash'},            # file_hash and mlab_value, kept once
            {'value': '/tmp/x.exe', 'type': 'filename'}])

    def test_es_notable_fields_win(self):
        p = m.payload({'rule_name': 'Brute force', 'urgency': 'critical', 'event_id': 'E1', 'severity': 'bogus',
                       'src': '8.8.8.8', 'mitre_technique_id': ['T1110', 'T1078']}, 'ES search', 'low')
        self.assertEqual((p['title'], p['severity'], p['external_id']), ('Brute force', 'critical', 'E1'))
        self.assertEqual(p['tags'], ['ES search', 'T1110', 'T1078'])
        self.assertEqual(p['dedup_key'], 'splunk:ES search')

    def test_raw_event(self):
        p = m.payload({'_raw': 'line1\nline2', '_time': '1', 'host': 'h', 'url': 'http://x', 'cve': 'CVE-1'}, 's')
        self.assertEqual(p['description'], 'Search: s\nhost: h\nurl: http://x\ncve: CVE-1\n\nline1\nline2')
        self.assertEqual(p['observables'], [{'value': 'http://x', 'type': 'url'}, {'value': 'CVE-1', 'type': 'cve'},
                                            {'value': 'h', 'type': 'hostname'}])
        self.assertEqual(p['severity'], 'medium')

    def test_mlab_ip_observable_untyped(self):
        self.assertEqual(m.payload({'mlab_type': 'ip', 'mlab_value': '8.8.8.8'}, 's')['observables'],
                         [{'value': '8.8.8.8'}])

    def test_csv_multivalue_but_raw_newlines_kept(self):
        row, = m.rows(results_file([{**ROW, '_raw': 'a\nb'}]))
        self.assertEqual(row['dest'], ['web01', '10.0.0.5'])
        self.assertEqual(row['_raw'], 'a\nb')
        self.assertNotIn('__mv_dest', row)


class Wire(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI({INGEST: (200, {'status': 'created', 'uuid': 'u1'})})
        self.p = {'search_name': 's', 'server_uri': 'https://127.0.0.1:8089', 'session_key': 'x',
                  'configuration': {'base_url': self.api.url + '/', 'severity': 'high'},
                  'results_file': results_file([ROW, {**ROW, 'mlab_value': 'b' * 64}])}

    def tearDown(self):
        self.api.close()

    def run_it(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = m.run(self.p, token='mlab_app_x')
        return code, err.getvalue()

    def test_one_alert_per_result(self):
        code, err = self.run_it()
        self.assertEqual(code, 0)
        self.assertEqual(len(self.api.requests), 2)
        req = self.api.requests[0]
        self.assertEqual((req['method'], req['path']), ('POST', INGEST))
        self.assertEqual(req['headers']['Authorization'], 'token mlab_app_x')
        self.assertEqual(req['body']['severity'], 'high')
        self.assertIn('INFO mlab_ir: s -> created u1', err)

    def test_result_cap(self):
        self.p['results_file'] = results_file([{'src': str(i)} for i in range(m.MAX_RESULTS + 5)])
        self.run_it()
        self.assertEqual(len(self.api.requests), m.MAX_RESULTS)

    def test_no_results_file_uses_result(self):  # e.g. ad-hoc adaptive response
        self.p['results_file'] = '/nonexistent.csv.gz'
        self.p['result'] = {'src': '8.8.8.8'}
        self.run_it()
        self.assertEqual(self.api.requests[0]['body']['observables'], [{'value': '8.8.8.8'}])

    def test_rate_limit_in_200_body_fails_but_sends_the_rest(self):
        self.api.routes[INGEST] = (200, {'status': 'error', 'error': 'Ingestion rate limit exceeded'})
        code, err = self.run_it()
        self.assertEqual((code, len(self.api.requests)), (2, 2))
        self.assertIn('ERROR mlab_ir: s: Ingestion rate limit exceeded', err)

    def test_http_error_fails(self):
        self.api.routes[INGEST] = (401, {'error': 'x'})
        self.assertEqual(self.run_it()[0], 2)

    def test_bad_severity_falls_back_to_medium(self):
        self.p['configuration']['severity'] = 'urgent'
        self.run_it()
        self.assertEqual(self.api.requests[0]['body']['severity'], 'medium')

    def test_missing_base_url(self):
        self.p['configuration'] = {}
        with self.assertRaisesRegex(ValueError, 'base_url'):
            m.run(self.p, token='t')


class Cli(unittest.TestCase):
    def cli(self, args, stdin=''):
        return subprocess.run([sys.executable, os.path.join(BIN, 'mlab_ir.py')] + args,
                              input=stdin, capture_output=True, text=True)

    def test_requires_execute(self):
        p = self.cli([])
        self.assertEqual(p.returncode, 1)
        self.assertIn('FATAL', p.stderr)

    def test_bad_payload_exits_2_without_traceback(self):
        p = self.cli(['--execute'], json.dumps({'configuration': {}}))
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stderr, 'ERROR mlab_ir: base_url (ir.mlab.sh URL) is not set\n')


if __name__ == '__main__':
    unittest.main()
