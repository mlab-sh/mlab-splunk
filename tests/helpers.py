"""A local HTTP server standing in for mlab.sh / ir.mlab.sh."""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'mlab', 'bin')
sys.path.insert(0, BIN)


class FakeAPI:
    """routes: {path_without_query: (status, json_body)}; records every request."""

    def __init__(self, routes):
        self.routes, self.requests = routes, []
        api = self

        class H(BaseHTTPRequestHandler):
            def handle_one(self):
                n = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(n) if n else b''
                api.requests.append({'method': self.command, 'path': self.path,
                                     'headers': dict(self.headers), 'body': json.loads(body) if body else None})
                status, out = api.routes.get(self.path.split('?')[0], (404, {'error': 'Not found'}))
                data = json.dumps(out).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = handle_one

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(('127.0.0.1', 0), H)
        self.url = f'http://127.0.0.1:{self.srv.server_port}'
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
