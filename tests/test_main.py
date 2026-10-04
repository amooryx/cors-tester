import io
import ssl
import unittest
import urllib.error
import urllib.request
from email.message import Message
from types import SimpleNamespace
from unittest.mock import patch

import main
import rclib


class _Response:
    status = 200

    def __init__(self, headers):
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _context(target="https://api.example.test/resource", origin=main.DEFAULT_ORIGIN, yes=False):
    return rclib.Context(
        args=SimpleNamespace(yes=yes, origin=origin, authorization=None),
        tool="cors-tester",
        target=target,
    )


class MainTests(unittest.TestCase):
    def test_normalizes_targets_and_origins(self):
        self.assertEqual(main._normalize_target("api.example.test"), "https://api.example.test")
        self.assertEqual(main._normalize_origin("HTTPS://Audit.Example:443/"), "https://audit.example")
        self.assertEqual(main._normalize_origin("http://[::1]:8080"), "http://[::1]:8080")

    def test_rejects_unsafe_target_and_non_origin_probe_values(self):
        for target in ("ftp://api.example.test", "https://user:pass@api.example.test", "https://api.example.test/#fragment"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                main._normalize_target(target)
        for origin in ("null", "https://audit.example/path", "https://audit.example?x=1"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                main._normalize_origin(origin)

    def test_reflection_is_recorded_as_observation_not_confirmed_risk(self):
        origin = "https://owned-audit.example"
        headers = Message()
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Vary"] = "Origin"
        opener = SimpleNamespace(open=lambda request, timeout: _Response(headers))
        captured_handlers = []

        def capture_opener(*handlers):
            captured_handlers.extend(handlers)
            return opener

        ctx = _context(origin=origin)
        with patch.object(urllib.request, "build_opener", side_effect=capture_opener), patch(
            "sys.stderr", new_callable=io.StringIO
        ):
            self.assertEqual(main.run(ctx), 0)

        observation = ctx.data["cors_observation"]
        self.assertEqual(observation["assessment"], "observed_only")
        self.assertEqual(observation["access_control_allow_origin"], origin)
        self.assertEqual(observation["access_control_allow_credentials"], "true")
        self.assertEqual([finding.severity for finding in ctx.findings], ["info"])
        self.assertTrue(any(isinstance(h, urllib.request.HTTPSHandler) for h in captured_handlers))
        tls_handler = next(h for h in captured_handlers if isinstance(h, urllib.request.HTTPSHandler))
        self.assertTrue(tls_handler._context.check_hostname)
        self.assertEqual(tls_handler._context.verify_mode, ssl.CERT_REQUIRED)
        redirect_handler = next(
            h for h in captured_handlers if isinstance(h, main._NoRedirectHandler)
        )
        self.assertIsNone(redirect_handler.redirect_request(None, None, 302, "", {}, "https://elsewhere.test"))

    def test_request_uses_a_bounded_timeout_and_reserved_default_origin(self):
        headers = Message()
        calls = {}

        def open_request(request, timeout):
            calls["timeout"] = timeout
            calls["origin"] = request.get_header("Origin")
            calls["authorization"] = request.get_header("Authorization")
            return _Response(headers)

        ctx = _context(yes=True)
        ctx.args.authorization = "approved staging audit"
        with patch.object(
            urllib.request, "build_opener", return_value=SimpleNamespace(open=open_request)
        ):
            self.assertEqual(main.run(ctx), 0)

        self.assertEqual(calls["timeout"], main.REQUEST_TIMEOUT)
        self.assertEqual(calls["timeout"], 10)
        self.assertEqual(calls["origin"], main.DEFAULT_ORIGIN)
        self.assertIsNone(calls["authorization"])
        self.assertEqual(ctx.data["cors_observation"]["http_status"], 200)
        self.assertTrue(ctx.data["authorization_context_provided"])

    def test_redirect_is_reported_without_following(self):
        headers = Message()
        headers["Location"] = "http://127.0.0.1/private"

        def reject_redirect(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 302, "Found", headers, None)

        ctx = _context()
        with patch.object(
            urllib.request, "build_opener", return_value=SimpleNamespace(open=reject_redirect)
        ):
            self.assertEqual(main.run(ctx), 0)
        self.assertEqual(ctx.data["cors_observation"]["http_status"], 302)

    def test_noninteractive_mode_requires_authorization_context(self):
        ctx = _context(yes=True)
        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(main.run(ctx), 2)
        self.assertIn("--authorization", stderr.getvalue())
        self.assertNotIn("cors_observation", ctx.data)

    def test_target_secrets_are_redacted_from_context_json(self):
        ctx = _context("https://user:secret@api.example.test/path?token=private#fragment")
        target = ctx.to_json()["target"]
        self.assertEqual(target, "https://api.example.test/path?[redacted]")
        self.assertNotIn("secret", target)
        self.assertNotIn("private", target)

    def test_request_errors_do_not_echo_exception_text(self):
        ctx = _context()
        with patch.object(
            urllib.request,
            "build_opener",
            return_value=SimpleNamespace(
                open=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    urllib.error.URLError("https://user:secret@api.example.test/?token=private")
                )
            ),
        ), patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(main.run(ctx), 1)
        self.assertIn("URLError", stderr.getvalue())
        self.assertNotIn("secret", stderr.getvalue())
        self.assertNotIn("private", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
