import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from harness.security_model import analyze


class ModelTests(unittest.TestCase):
    def test_mock_refusal_and_invalid_success(self):
        class Handler(BaseHTTPRequestHandler):
            response = {'message': {'content': json.dumps({'status': 'PROVIDER_BLOCKED',
                         'assessment': 'Synthetic refusal fixture', 'limitations': ['No review']})}}
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(self.response).encode())
            def log_message(self, *args):
                pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = 'http://127.0.0.1:' + str(server.server_port)
            self.assertEqual(analyze(url, 'fixture', 'test')['status'], 'PROVIDER_BLOCKED')
            Handler.response = {'message': {'content': '200 OK but no valid model output'}}
            self.assertEqual(analyze(url, 'fixture', 'test')['status'], 'MODEL_FAILED')
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_nonlocal_and_credential_urls_rejected(self):
        for url in ['https://external.invalid', 'http://user:pass@localhost', 'http://localhost/x']:
            with self.assertRaises(ValueError):
                analyze(url, 'fixture', 'test')

    def test_openrouter_requires_egress_optin_host_and_key(self):
        # The off-machine data path must be opted into explicitly.
        with self.assertRaises(ValueError):
            analyze('https://openrouter.ai', 'anthropic/claude', 'test', provider='openrouter')
        # Even with egress allowed: non-allowlisted host and non-TLS are rejected.
        for url in ['https://evil.invalid', 'http://openrouter.ai', 'https://user:pass@openrouter.ai']:
            with self.assertRaises(ValueError):
                analyze(url, 'm', 'test', provider='openrouter', allow_egress=True, api_key='k')
        # A real host but no key fails closed; never read a key from the URL or repo.
        saved = os.environ.pop('OPENROUTER_API_KEY', None)
        try:
            with self.assertRaises(ValueError):
                analyze('https://openrouter.ai', 'm', 'test', provider='openrouter', allow_egress=True)
        finally:
            if saved is not None:
                os.environ['OPENROUTER_API_KEY'] = saved

    def test_custom_router_openai_shape_and_remote_guards(self):
        # A loopback bring-your-own router needs no egress opt-in and no key, and the
        # OpenAI-compatible response (choices[].message.content) is parsed correctly.
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(200)
                self.end_headers()
                body = {'choices': [{'message': {'content': json.dumps(
                    {'status': 'REVIEWED', 'assessment': 'synthetic', 'limitations': []})}}]}
                self.wfile.write(json.dumps(body).encode())
            def log_message(self, *args):
                pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = 'http://127.0.0.1:' + str(server.server_port) + '/v1/chat/completions'
            result = analyze(url, 'any/model', 'test', provider='custom')
            self.assertEqual(result['status'], 'REVIEWED')
            self.assertEqual(result['egress'], 'local-loopback')
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        # A remote router must opt into egress, use TLS, and carry a key.
        with self.assertRaises(ValueError):  # no egress opt-in
            analyze('https://router.invalid/v1/chat/completions', 'm', 'test', provider='custom')
        with self.assertRaises(ValueError):  # non-loopback over http
            analyze('http://router.invalid/v1/chat/completions', 'm', 'test',
                    provider='custom', allow_egress=True, api_key='k')
        saved = os.environ.pop('AHS_ROUTER_API_KEY', None)
        try:
            with self.assertRaises(ValueError):  # remote, egress allowed, but no key
                analyze('https://router.invalid/v1/chat/completions', 'm', 'test',
                        provider='custom', allow_egress=True)
        finally:
            if saved is not None:
                os.environ['AHS_ROUTER_API_KEY'] = saved


if __name__ == '__main__':
    unittest.main()
