import base64
import json
import unittest

from tools.integrations.auth_security_audit.jwt_inspector import JWTFormatError, inspect_jwt
from tools.integrations.auth_security_audit.jwt_zap_runner import build_zap_replacer_config, validate_compact_token


def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


class JWTInspectorTests(unittest.TestCase):
    def setUp(self):
        self.token = b64({"alg": "RS256", "typ": "JWT"}) + "." + b64({"exp": 2000, "iat": 1000, "iss": "issuer", "aud": "api", "sub": "private-user"}) + ".signature"

    def test_inspects_claim_names_without_claim_values(self):
        result = inspect_jwt(self.token, now_epoch=1500)
        self.assertEqual(result["algorithm"], "RS256")
        self.assertIn("sub", result["claim_names"])
        self.assertNotIn("sub", result)
        self.assertFalse(result["expired"])
        self.assertEqual(result["expires_in_seconds"], 500)

    def test_flags_expired_and_missing_issuer(self):
        token = b64({"alg": "none"}) + "." + b64({"exp": 900}) + "."
        result = inspect_jwt(token, now_epoch=1000)
        self.assertTrue(result["expired"])
        self.assertTrue(any("alg=none" in warning for warning in result["warnings"]))
        self.assertTrue(any("iss" in warning for warning in result["warnings"]))

    def test_rejects_invalid_compact_token(self):
        with self.assertRaises(JWTFormatError):
            inspect_jwt("not-a-token")

    def test_rejects_newline_token(self):
        with self.assertRaises(ValueError):
            validate_compact_token("abc.def.ghi\n")

    def test_zap_config_is_target_origin_scoped_and_contains_bearer_header(self):
        config = build_zap_replacer_config("https://app.example.test:8443/login", self.token)
        self.assertIn("matchtype=REQ_HEADER", config)
        self.assertIn("matchstr=Authorization", config)
        self.assertIn("replacement=Bearer "+self.token, config)
        self.assertIn("app\\\\.example\\\\.test:8443", config)

    def test_rejects_unsupported_header(self):
        with self.assertRaises(ValueError):
            build_zap_replacer_config("https://app.example.test", self.token, "Cookie")


if __name__ == "__main__":
    unittest.main()
