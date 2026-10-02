#!/usr/bin/env python3
"""Loopback-only, synthetic OAuth fixture. Never use as an identity provider."""

import argparse
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

CLIENT_ID = "synthetic-rauthy-client"
CALLBACK = "http://127.0.0.1:8080/auth/v1/providers/callback"
FIXTURES = json.loads(Path(__file__).with_name("fixtures.json").read_text())
PKCE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}\Z")
PKCE_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def validate_callback(callback):
    parsed = urlsplit(callback)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or not parsed.path.startswith("/")
            or parsed.port is None or not 1 <= parsed.port <= 65535):
        raise ValueError("callback must be an exact http://127.0.0.1:PORT/path without query")
    return callback


def single_values(query):
    values = parse_qs(query, keep_blank_values=True, strict_parsing=True, max_num_fields=20)
    if any(len(items) != 1 for items in values.values()):
        raise ValueError("duplicate parameters")
    return {key: value[0] for key, value in values.items()}


class FixtureServer(HTTPServer):
    def __init__(self, port=0, scenario="numeric_no_email", callback=CALLBACK, clock=time.monotonic):
        self.callback = validate_callback(callback)
        self.claims = FIXTURES[scenario]
        self.clock = clock
        self.codes = {}
        self.tokens = {}
        super().__init__(("127.0.0.1", port), FixtureHandler)

    def prune(self):
        now = self.clock()
        self.codes = {key: value for key, value in self.codes.items() if value[1] > now}
        self.tokens = {key: value for key, value in self.tokens.items() if value > now}

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.server_port}"

    def provider_config(self):
        return {
            "name": "Synthetic OAuth fixture ONLY", "typ": "custom", "enabled": False,
            "issuer": self.base_url, "authorization_endpoint": self.base_url + "/authorize",
            "token_endpoint": self.base_url + "/token",
            "userinfo_endpoint": self.base_url + "/userinfo", "jwks_endpoint": None,
            "client_id": CLIENT_ID, "client_secret": None, "scope": "profile",
            "use_pkce": True, "client_secret_basic": False, "client_secret_post": False,
            "auto_onboarding": True, "auto_link": False,
            "admin_claim_path": None, "admin_claim_value": None,
            "mfa_claim_path": None, "mfa_claim_value": None,
        }


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass  # Do not log authorization codes, access tokens, or claims.

    def reply(self, status, body, location=None):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(payload)

    def error(self, name="invalid_request", status=400):
        self.reply(status, {"error": name})

    def do_GET(self):
        parsed = urlsplit(self.path)
        self.server.prune()
        if parsed.path == "/authorize":
            try:
                values = single_values(parsed.query)
            except ValueError:
                return self.error()
            if (values.get("response_type") != "code" or values.get("client_id") != CLIENT_ID
                    or values.get("redirect_uri") != self.server.callback
                    or not 1 <= len(values.get("state", "")) <= 512
                    or values.get("code_challenge_method") != "S256"
                    or not PKCE_CHALLENGE.fullmatch(values.get("code_challenge", ""))):
                return self.error()
            if len(self.server.codes) >= 256:
                return self.error("temporarily_unavailable", 503)
            code = secrets.token_urlsafe(32)
            self.server.codes[code] = (values["code_challenge"], self.server.clock() + 60)
            self.reply(302, {}, self.server.callback + "?" + urlencode({
                "code": code, "state": values["state"],
            }))
        elif parsed.path == "/userinfo" and not parsed.query:
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or auth[7:] not in self.server.tokens:
                return self.error("invalid_token", 401)
            self.reply(200, self.server.claims)
        else:
            self.error("not_found", 404)

    def do_POST(self):
        if self.path != "/token":
            return self.error("not_found", 404)
        if self.headers.get_content_type() != "application/x-www-form-urlencoded":
            return self.error()
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096 or "Transfer-Encoding" in self.headers:
                return self.error()
            values = single_values(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeError):
            return self.error()
        if values.get("client_id") != CLIENT_ID:
            return self.error("invalid_client", 401)
        if values.get("grant_type") != "authorization_code":
            return self.error("unsupported_grant_type")
        self.server.prune()
        # Consume even a failed exchange: fixture codes cannot be retried or replayed.
        pending = self.server.codes.pop(values.get("code", ""), None)
        verifier = values.get("code_verifier", "")
        if (pending is None or values.get("redirect_uri") != self.server.callback
                or not PKCE_VERIFIER.fullmatch(verifier)
                or not hmac.compare_digest(challenge(verifier), pending[0])):
            return self.error("invalid_grant")
        if len(self.server.tokens) >= 256:
            return self.error("temporarily_unavailable", 503)
        token = secrets.token_urlsafe(32)
        self.server.tokens[token] = self.server.clock() + 300
        # Deliberately access-token-only; no OIDC id_token or fabricated claims.
        self.reply(200, {"access_token": token, "token_type": "Bearer", "expires_in": 300})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=19090)
    parser.add_argument("--scenario", choices=sorted(FIXTURES), default="numeric_no_email")
    parser.add_argument("--callback", default=CALLBACK)
    args = parser.parse_args()
    with FixtureServer(args.port, args.scenario, args.callback) as server:
        print("SYNTHETIC LOCAL TEST ONLY; config is disabled by default", flush=True)
        print(json.dumps(server.provider_config(), indent=2), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
