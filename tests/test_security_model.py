import json
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


if __name__ == '__main__':
    unittest.main()
