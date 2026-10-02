"""Tests the synthetic provider itself, NOT a running Rauthy deployment."""

import json
import threading
import unittest
from http.client import HTTPConnection
from urllib.parse import parse_qs, urlencode, urlsplit

from stub import CALLBACK, CLIENT_ID, FIXTURES, FixtureServer, challenge, validate_callback


class OAuthFixtureTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.server = FixtureServer(clock=lambda: self.now)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.verifier = "fixture_verifier_" + "x" * 40

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.assertFalse(self.thread.is_alive())

    def request(self, method, path, body=None, headers=None):
        conn = HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), json.loads(response.read())
        finally:
            conn.close()

    def authorize(self, **overrides):
        values = {
            "response_type": "code", "client_id": CLIENT_ID, "redirect_uri": CALLBACK,
            "state": "synthetic_state_+=&", "code_challenge": challenge(self.verifier),
            "code_challenge_method": "S256",
        }
        values.update(overrides)
        return self.request("GET", "/authorize?" + urlencode(values))

    def code(self):
        status, headers, _body = self.authorize()
        self.assertEqual(status, 302)
        params = parse_qs(urlsplit(headers["Location"]).query)
        self.assertEqual(params["state"], ["synthetic_state_+=&"])
        return params["code"][0]

    def exchange(self, code, **overrides):
        values = {
            "grant_type": "authorization_code", "client_id": CLIENT_ID,
            "redirect_uri": CALLBACK, "code": code, "code_verifier": self.verifier,
        }
        values.update(overrides)
        return self.request("POST", "/token", urlencode(values),
                            {"Content-Type": "application/x-www-form-urlencoded"})

    def test_all_claims_round_trip_without_enrichment(self):
        for name, claims in FIXTURES.items():
            with self.subTest(scenario=name):
                self.server.claims = claims
                status, headers, token = self.exchange(self.code())
                self.assertEqual(status, 200)
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertEqual(set(token), {"access_token", "token_type", "expires_in"})
                status, headers, actual = self.request(
                    "GET", "/userinfo", headers={"Authorization": "Bearer " + token["access_token"]})
                self.assertEqual(status, 200)
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertEqual(actual, claims)
                self.assertNotIn("preferred_username", actual)
                self.assertIsNot(actual.get("email_verified"), True)

    def test_code_is_single_use(self):
        code = self.code()
        self.assertEqual(self.exchange(code)[0], 200)
        self.assertEqual(self.exchange(code)[2], {"error": "invalid_grant"})

    def test_pkce_mismatch_consumes_code(self):
        code = self.code()
        self.assertEqual(self.exchange(code, code_verifier="y" * 43)[0], 400)
        self.assertEqual(self.exchange(code)[0], 400)

    def test_expired_code_is_rejected(self):
        code = self.code()
        self.now += 60
        self.assertEqual(self.exchange(code)[0], 400)

    def test_expired_access_token_is_rejected(self):
        token = self.exchange(self.code())[2]["access_token"]
        self.now += 300
        self.assertEqual(self.request("GET", "/userinfo", headers={
            "Authorization": "Bearer " + token})[0], 401)

    def test_redirect_is_pinned_at_authorization_and_exchange(self):
        evil = "http://127.0.0.1:1234/wrong"
        self.assertEqual(self.authorize(redirect_uri=evil)[0], 400)
        self.assertEqual(self.exchange(self.code(), redirect_uri=evil)[0], 400)

    def test_rejects_wrong_client(self):
        self.assertEqual(self.authorize(client_id="wrong")[0], 400)
        self.assertEqual(self.exchange(self.code(), client_id="wrong")[0], 401)

    def test_rejects_non_authorization_code_flows(self):
        self.assertEqual(self.authorize(response_type="token")[0], 400)
        self.assertEqual(self.exchange(self.code(), grant_type="refresh_token")[0], 400)

    def test_requires_state_and_s256(self):
        for values in [{"state": ""}, {"code_challenge_method": "plain"},
                       {"code_challenge": ""}, {"code_challenge": "!" * 43}]:
            with self.subTest(values=values):
                self.assertEqual(self.authorize(**values)[0], 400)

    def test_rejects_duplicate_query_parameters(self):
        self.assertEqual(self.request("GET", "/authorize?state=a&state=b")[0], 400)

    def test_rejects_duplicate_form_parameters(self):
        body = urlencode({"client_id": CLIENT_ID}) + "&client_id=another"
        self.assertEqual(self.request("POST", "/token", body, {
            "Content-Type": "application/x-www-form-urlencoded"})[0], 400)

    def test_userinfo_requires_bearer_token(self):
        for auth in ["", "Bearer guessed", "Basic guessed"]:
            self.assertEqual(self.request("GET", "/userinfo", headers={
                "Authorization": auth})[0], 401)

    def test_rejects_wrong_content_type_and_large_body(self):
        self.assertEqual(self.request("POST", "/token", "{}")[0], 400)
        self.assertEqual(self.request("POST", "/token", "x" * 4097, {
            "Content-Type": "application/x-www-form-urlencoded"})[0], 400)

    def test_unknown_routes_are_not_served(self):
        for method, path in [("GET", "/"), ("GET", "/.well-known/openid-configuration"),
                             ("GET", "/userinfo?access_token=guess"), ("POST", "/userinfo")]:
            self.assertEqual(self.request(method, path)[0], 404)

    def test_provider_config_is_disabled_and_never_auto_links(self):
        config = self.server.provider_config()
        self.assertFalse(config["enabled"])
        self.assertFalse(config["auto_link"])
        self.assertTrue(config["use_pkce"])
        self.assertIsNone(config["client_secret"])
        self.assertIsNone(config["admin_claim_path"])
        self.assertIsNone(config["mfa_claim_path"])
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        for endpoint in ["issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint"]:
            self.assertEqual(urlsplit(config[endpoint]).netloc,
                             f"127.0.0.1:{self.server.server_port}")

    def test_callback_refuses_remote_ambiguous_and_non_http_targets(self):
        for callback in ["https://example.invalid/callback", "http://localhost:8080/callback",
                         "http://0.0.0.0:8080/callback", "http://127.0.0.1:8080/callback?x=y",
                         "http://user@127.0.0.1:8080/callback", "http://127.0.0.1:8080/cb#frag",
                         "http://127.0.0.1/callback", "http://127.0.0.1:0/callback"]:
            with self.subTest(callback=callback), self.assertRaises(ValueError):
                validate_callback(callback)

    def test_fixture_identity_and_email_edge_cases_are_preserved(self):
        no_email = FIXTURES["numeric_no_email"]
        null_email = FIXTURES["numeric_null_email"]
        numeric = FIXTURES["numeric_unverified_email"]
        string_id = FIXTURES["string_id"]
        renamed = FIXTURES["renamed_user"]
        other = FIXTURES["same_email_other_id"]
        self.assertNotIn("email", no_email)
        self.assertIsNone(null_email["email"])
        self.assertIs(type(numeric["id"]), int)
        self.assertIs(type(string_id["id"]), str)
        self.assertEqual(str(numeric["id"]), string_id["id"])
        self.assertEqual(numeric["id"], renamed["id"])
        self.assertNotEqual(numeric["username"], renamed["username"])
        self.assertEqual(numeric["email"], other["email"])
        self.assertNotEqual(numeric["id"], other["id"])
        self.assertNotIn("email_verified", FIXTURES["numeric_unstated_verification"])
        for claims in FIXTURES.values():
            if claims.get("email"):
                self.assertTrue(claims["email"].endswith("@example.invalid"))


if __name__ == "__main__":
    unittest.main()
