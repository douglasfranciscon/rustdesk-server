"""Mock da API de controle para testar o hbbs customizado.

Endpoints do contrato:
  POST /tokens/verify        {"token": "...", "ip": "..."} -> 200 {"user": "..."} | 403
  POST /peers/seen           {"id": "...", "ip": "..."}    -> 200
  POST /connections/attempt  {"target_id": ..., "result": ...} -> 200 (auditoria)
  POST /api/login            -> devolve access_token fixo "tok-aprovado"
  POST /api/currentUser, /api/logout, /api/heartbeat, /api/sysinfo -> 200 {}

Endpoints de teste (controle do mock em runtime):
  GET /_approve?token=X  -> adiciona X aos aprovados
  GET /_revoke?token=X   -> remove X dos aprovados
  GET /_state            -> mostra aprovados, peers vistos e tentativas

Uso: python mock_api.py [porta]  (default 21120)
"""
import json
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

APPROVED = {"tok-aprovado"}
PEERS_SEEN = {}
ATTEMPTS = []
MAX_ATTEMPTS = 200


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {fmt % args}")

    def _send(self, code, obj=None):
        body = json.dumps(obj or {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def do_GET(self):
        url = urlparse(self.path)
        qs = parse_qs(url.query)
        token = (qs.get("token") or [""])[0]
        if url.path == "/_approve" and token:
            APPROVED.add(token)
            self._send(200, {"approved": sorted(APPROVED)})
        elif url.path == "/_revoke" and token:
            APPROVED.discard(token)
            self._send(200, {"approved": sorted(APPROVED)})
        elif url.path == "/_state":
            self._send(200, {
                "approved": sorted(APPROVED),
                "peers_seen": PEERS_SEEN,
                "attempts": ATTEMPTS,
            })
        else:
            self._send(404)

    def do_POST(self):
        url = urlparse(self.path)
        body = self._body()
        if url.path == "/tokens/verify":
            token = body.get("token", "")
            ip = body.get("ip", "")
            if token in APPROVED:
                print(f"  verify OK token={token!r} ip={ip}")
                self._send(200, {"user": "douglas"})
            else:
                print(f"  verify NEGADO token={token!r} ip={ip}")
                self._send(403)
        elif url.path == "/peers/seen":
            pid = body.get("id", "")
            PEERS_SEEN[pid] = {"ip": body.get("ip", ""), "last_seen": datetime.now().isoformat()}
            print(f"  peer visto id={pid} ip={body.get('ip')}")
            self._send(200)
        elif url.path == "/connections/attempt":
            if len(ATTEMPTS) >= MAX_ATTEMPTS:
                del ATTEMPTS[0]
            ATTEMPTS.append(body)
            print(
                f"  tentativa {body.get('result')} kind={body.get('kind')}"
                f" alvo={body.get('target_id')} ip={body.get('ip')} user={body.get('user')}"
            )
            self._send(200)
        elif url.path == "/api/login":
            print(f"  login de {body.get('username')!r} id={body.get('id')} uuid={body.get('uuid')}")
            self._send(200, {
                "type": "access_token",
                "access_token": "tok-aprovado",
                "user": {"name": body.get("username", "atendente")},
            })
        elif url.path in ("/api/currentUser", "/api/logout", "/api/heartbeat", "/api/sysinfo"):
            self._send(200, {})
        else:
            self._send(404)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 21120
    print(f"Mock da API de controle em http://127.0.0.1:{port}")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
