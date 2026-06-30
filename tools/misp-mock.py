#!/usr/bin/env python3
"""Mock MISP server — serves test fixtures for threat-intel-arbiter development.
   Handles: /events/restSearch, /events/index, /warninglists/index
   Auth: X-MISP-Auth header (any value accepted for testing)
"""

import json
import os
import http.server
import glob

PORT = 8081
FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "testdata")

class MISPServer(http.server.HTTPServer):
    allow_reuse_address = True

class MISPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self._route()
    
    def do_POST(self):
        self._route()
    
    def _route(self):
        # Parse path
        path = self.path.split("?")[0]
        
        # Check auth
        auth = self.headers.get("Authorization", "")
        if not auth:
            self.send_error(401, "Missing Authorization header")
            return
        
        if path == "/events/restSearch" or path == "/events/index":
            self.serve_events()
        elif path == "/warninglists/index":
            self.serve_json({"response": []})
        elif path == "/noticelists/index":
            self.serve_json({"response": []})
        elif path == "/servers/getVersion":
            self.serve_json({"response": {"version": "2.4.999"}})
        elif path == "/users/view/me":
            self.serve_json({"response": {"User": {"id": "1", "email": "admin@misp.test", "role_id": "1"}}})
        else:
            self.send_error(404, f"Not found: {path}")
    
    def serve_events(self):
        events = []
        for f in sorted(glob.glob(os.path.join(FIXTURE_DIR, "misp_event_*.json"))):
            if "deleted" in f:
                continue
            try:
                data = json.load(open(f))
                events.extend(data.get("response", []))
            except:
                pass
        
        resp = {"response": events}
        self.serve_json(resp)
    
    def serve_json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    
    def log_message(self, format, *args):
        print(f"misp-mock: {args[0]}")

if __name__ == "__main__":
    print(f"MISP Mock Server starting on :{PORT}")
    print(f"Fixture directory: {FIXTURE_DIR}")
    print(f"Connect arbiter with: export MISP_API_KEY=test-key")
    print(f"                       ./arbiter --key=demo-key")
    print()
    server = MISPServer(("", PORT), MISPHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()
