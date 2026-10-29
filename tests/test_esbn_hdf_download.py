import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import esbn_hdf_download as m  # noqa: E402

MPRN = "10000000001"
NOW = datetime(2026, 1, 20, 12, 0)
LOGIN_URL = f"https://{m.LOGIN_HOST}/tenant/{m.B2C_POLICY}/oauth2/v2.0/authorize"
LOGIN_PAGE = 'var SETTINGS = {"csrf": "c1", "transId": "t1", "remoteResource": "https://cdn.example/captcha.html"};'
CAPTCHA_PAGE = ('<div class="g-recaptcha-response"></div>'
                'var SETTINGS = {"csrf": "c2", "transId": "t2", "remoteResource": "https://cdn.example/captcha.html"};'
                'var SA_FIELDS = {"AttributeFields": [{"ID": "g-recaptcha-response-x"}]};')
# real hand-off form from the /energymanagement/ entry point carries only state + code
HANDOFF = ('<form id="auto" action="https://myaccount.esbnetworks.ie/signin-oidc" method="post">'
           '<input type="hidden" name="state" value="s"/><input type="hidden" name="code" value="cd"/></form>')


def hdf(last="19-01-2026 23:30", mprn=MPRN, rows=3, day="18-01-2026"):
    lines = [",".join(m.HDF_HEADER)]
    lines += [f"{mprn},000000000000000001,0.2500,Active Import Interval (kWh),{day} 0{i}:00"
              for i in range(rows - 1)]
    lines.append(f"{mprn},000000000000000001,0.1000,Active Import Interval (kWh),{last}")
    return ("\r\n".join(lines) + "\r\n").encode()


def resp(status=200, body=b"", url="https://myaccount.esbnetworks.ie/", headers=None):
    r = requests.Response()
    r.status_code = status
    r._content = body.encode() if isinstance(body, str) else body
    r.url = url
    r.headers.update(headers or {})
    r.encoding = "utf-8"
    return r


class FakePortal(requests.Session):
    """Scripted stand-in for the ESB portal; records every call."""

    def __init__(self, *, logged_in=False, captcha=False, password_ok=True,
                 download=None, still_captcha=False):
        super().__init__()
        if logged_in:
            self.cookies.set("session", "1")
        self.captcha = captcha
        self.password_ok = password_ok
        self.still_captcha = still_captcha
        self.download_resp = resp(200, hdf()) if download is None else download
        self.calls = []
        self.confirmed_count = 0

    @property
    def logged_in(self):
        return "session" in self.cookies

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        if url == f"{m.PORTAL}/":
            if self.logged_in:
                return resp(200, "<html>home</html>", url=url)
            return resp(200, LOGIN_PAGE, url=LOGIN_URL)
        if url == m.CONSUMPTION_PAGE:
            if self.logged_in:
                return resp(200, "<html>consumption</html>", url=m.CONSUMPTION_PAGE)
            return resp(200, LOGIN_PAGE, url=LOGIN_URL)
        if url.endswith("/SelfAsserted"):
            data = kw.get("data", {})
            if "password" in data and not self.password_ok:
                return resp(200, '{"status":"400","message":"Invalid username or password."}')
            return resp(200, '{"status":"200"}')
        if url.endswith("/confirmed"):
            self.confirmed_count += 1
            if self.captcha and (self.confirmed_count == 1 or self.still_captcha):
                return resp(200, CAPTCHA_PAGE, url=url)
            return resp(200, HANDOFF, url=url)
        if url == "https://cdn.example/captcha.html":
            # same shape as ESB's real template: key lives in a module-imported script
            return resp(200, "<script type=\"module\">import { bootstrapCaptcha } from "
                             "'https://cdn.example/js/site.min.js?v=1';</script>", url=url)
        if url == "https://cdn.example/js/site.min.js?v=1":
            return resp(200, 'grecaptcha.render("c",{sitekey:"SITEKEY",callback:f})', url=url)
        if url.endswith("/signin-oidc"):
            self.cookies.set("session", "1")
            return resp(302, headers={"location": "/"})
        if url == m.TOKEN_URL:
            return resp(200, '{"token":"xsrf"}')
        if url == m.DOWNLOAD_URL:
            if isinstance(self.download_resp, list):
                return self.download_resp.pop(0)
            return self.download_resp
        raise AssertionError(f"unexpected {method} {url}")


class FakeCaptcha:
    def __init__(self, balances=(9.0, 8.997), fail=None):
        self.balances = list(balances)
        self.fail = fail
        self.solved = []

    def balance(self):
        if self.fail == "balance":
            raise m.RunError("2Captcha getBalance", "2Captcha API key was rejected")
        if self.fail == "unreachable":
            raise m.RunError("2Captcha getBalance", "request failed (ConnectionError)")
        return self.balances.pop(0) if len(self.balances) > 1 else self.balances[0]

    def solve_recaptcha_v2(self, page_url, site_key):
        if self.fail == "zero":
            raise m.RunError("2Captcha createTask", "2Captcha account is out of credit")
        self.solved.append((page_url, site_key))
        return "TOKEN"


class RunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "hdf.csv"
        self.cfg = m.Config(username="u@example.com", password="pw", mprn=MPRN, output_path=self.out,
                            twocaptcha_api_key="k", alert_webhook_url="https://hook.example/x")
        self.alerts = []
        patcher = mock.patch.object(m, "send_alert",
                                    lambda url, level, reason, details=None: self.alerts.append((level, reason)))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_full_login_without_captcha_saves_csv(self):
        portal, solver = FakePortal(), FakeCaptcha()
        self.assertEqual(m.run(self.cfg, captcha=solver, session=portal, now=NOW), 0)
        self.assertEqual(self.out.read_bytes(), hdf())
        self.assertEqual(solver.solved, [])
        self.assertEqual(self.alerts, [])
        download = [c for c in portal.calls if c[1] == m.DOWNLOAD_URL][0]
        self.assertEqual(download[0], "POST")
        self.assertEqual(download[2]["json"], {"mprn": MPRN, "searchType": "intervalkwh"})
        self.assertEqual(download[2]["headers"]["X-XSRF-TOKEN"], "xsrf")
        self.assertEqual(download[2]["headers"]["x-ReturnUrl"], m.CONSUMPTION_PAGE)

    def test_existing_session_skips_login(self):
        portal = FakePortal(logged_in=True)
        m.run(self.cfg, captcha=FakeCaptcha(), session=portal, now=NOW)
        self.assertFalse(any(c[1].endswith("/SelfAsserted") for c in portal.calls))

    def test_login_starts_from_portal_home(self):
        portal = FakePortal()
        m.run(self.cfg, captcha=FakeCaptcha(), session=portal, now=NOW)
        urls = [c[1] for c in portal.calls]
        self.assertLess(urls.index(f"{m.PORTAL}/"), urls.index(m.DOWNLOAD_URL))
        self.assertEqual(urls[0], m.CONSUMPTION_PAGE)  # session check first

    def test_refused_saved_session_signs_in_fresh_once(self):
        portal = FakePortal(logged_in=True, download=[resp(500), resp(200, hdf())])
        self.assertEqual(m.run(self.cfg, captcha=FakeCaptcha(), session=portal, now=NOW), 0)
        self.assertEqual(sum(c[1].endswith("/signin-oidc") for c in portal.calls), 1)

    def test_fresh_sign_in_failure_does_not_loop(self):
        portal = FakePortal(logged_in=True, download=[resp(500), resp(500)])
        with self.assertRaises(m.RunError):
            m.run(self.cfg, captcha=FakeCaptcha(), session=portal, now=NOW)
        self.assertEqual(sum(c[1] == m.DOWNLOAD_URL for c in portal.calls), 2)

    def test_captcha_path_submits_solution_under_page_claim(self):
        portal, solver = FakePortal(captcha=True), FakeCaptcha()
        self.assertEqual(m.run(self.cfg, captcha=solver, session=portal, now=NOW), 0)
        self.assertEqual(solver.solved[0][1], "SITEKEY")
        posts = [c[2]["data"] for c in portal.calls if c[1].endswith("/SelfAsserted")]
        self.assertEqual(posts[1], {"g-recaptcha-response-x": "TOKEN", "request_type": "RESPONSE"})

    def test_handoff_posts_form_fields(self):
        portal = FakePortal()
        m.run(self.cfg, captcha=FakeCaptcha(), session=portal, now=NOW)
        post = [c for c in portal.calls if c[1].endswith("/signin-oidc")][0]
        self.assertEqual(post[2]["data"], {"state": "s", "code": "cd"})

    def test_wrong_password_fails_at_credentials(self):
        with self.assertRaises(m.RunError) as ctx:
            m.run(self.cfg, captcha=FakeCaptcha(), session=FakePortal(password_ok=False), now=NOW)
        self.assertEqual(ctx.exception.step, "submit credentials")
        self.assertIn("Invalid username or password", ctx.exception.reason)
        self.assertFalse(self.out.exists())

    def test_captcha_without_key_fails_clearly(self):
        cfg = m.Config(**{**self.cfg.__dict__, "twocaptcha_api_key": None})
        with self.assertRaises(m.RunError) as ctx:
            m.run(cfg, captcha=None, session=FakePortal(captcha=True), now=NOW)
        self.assertIn("no TWOCAPTCHA_API_KEY", ctx.exception.reason)

    def test_captcha_still_shown_after_solution_fails(self):
        with self.assertRaises(m.RunError) as ctx:
            m.run(self.cfg, captcha=FakeCaptcha(), session=FakePortal(captcha=True, still_captcha=True), now=NOW)
        self.assertIn("still showed a CAPTCHA", ctx.exception.reason)

    def test_out_of_credit_is_its_own_failure(self):
        with self.assertRaises(m.RunError) as ctx:
            m.run(self.cfg, captcha=FakeCaptcha(fail="zero"), session=FakePortal(captcha=True), now=NOW)
        self.assertIn("out of credit", ctx.exception.reason)

    def test_rejected_key_fails_before_touching_esb(self):
        portal = FakePortal()
        with self.assertRaises(m.RunError):
            m.run(self.cfg, captcha=FakeCaptcha(fail="balance"), session=portal, now=NOW)
        self.assertEqual(portal.calls, [])

    def test_2captcha_unreachable_warns_and_continues(self):
        self.assertEqual(m.run(self.cfg, captcha=FakeCaptcha(fail="unreachable"),
                               session=FakePortal(), now=NOW), 0)
        self.assertEqual(self.alerts[0][0], "warning")
        self.assertTrue(self.out.exists())

    def test_moved_endpoint_405_names_the_cause(self):
        portal = FakePortal(download=resp(405, headers={"Allow": "GET"}))
        with self.assertRaises(m.RunError) as ctx:
            m.run(self.cfg, captcha=FakeCaptcha(), session=portal, now=NOW)
        self.assertEqual(ctx.exception.step, "HDF download")
        self.assertIn("moved the download endpoint", ctx.exception.reason)

    def test_html_instead_of_csv_keeps_previous_file(self):
        self.out.write_bytes(b"previous good file")
        portal = FakePortal(download=resp(200, "<!DOCTYPE html><html>sign in</html>"))
        with self.assertRaises(m.RunError) as ctx:
            m.run(self.cfg, captcha=FakeCaptcha(), session=portal, now=NOW)
        self.assertIn("HTML page", ctx.exception.reason)
        self.assertEqual(self.out.read_bytes(), b"previous good file")

    def test_low_balance_warns_but_saves(self):
        solver = FakeCaptcha(balances=(1.503, 1.5))
        self.assertEqual(m.run(self.cfg, captcha=solver, session=FakePortal(captcha=True), now=NOW), 0)
        self.assertTrue(self.out.exists())
        level, reason = self.alerts[0]
        self.assertEqual(level, "warning")
        self.assertIn("$1.50", reason)
        self.assertIn("500 solves left", reason)

    def test_low_balance_warns_even_without_a_solve(self):
        m.run(self.cfg, captcha=FakeCaptcha(balances=(0.5,)), session=FakePortal(), now=NOW)
        self.assertEqual(self.alerts[0][0], "warning")
        self.assertNotIn("solves left", self.alerts[0][1])

    def test_healthy_balance_is_silent(self):
        m.run(self.cfg, captcha=FakeCaptcha(balances=(9.0, 8.99)), session=FakePortal(captcha=True), now=NOW)
        self.assertEqual(self.alerts, [])


class ValidateTests(unittest.TestCase):
    def test_good_file(self):
        s = m.validate_hdf(hdf(), MPRN, 7, NOW)
        self.assertEqual(s.rows, 3)
        self.assertEqual(s.last, datetime(2026, 1, 19, 23, 30))

    def test_bom_is_accepted(self):
        m.validate_hdf(b"\xef\xbb\xbf" + hdf(), MPRN, 7, NOW)

    def assertInvalid(self, content, needle, mprn=MPRN):
        with self.assertRaises(m.RunError) as ctx:
            m.validate_hdf(content, mprn, 7, NOW)
        self.assertIn(needle, ctx.exception.reason)

    def test_rejections(self):
        self.assertInvalid(b"", "empty")
        self.assertInvalid(b"<html></html>", "HTML")
        self.assertInvalid(b"a,b,c\r\n1,2,3\r\n", "unexpected header")
        self.assertInvalid((",".join(m.HDF_HEADER) + "\r\n").encode(), "no readings")
        self.assertInvalid(hdf(), "different MPRN", mprn="19999999999")
        self.assertInvalid(hdf(last="01-01-2026 00:30", day="01-01-2026"), "older than 7 days")
        self.assertInvalid(hdf(last="not a date"), "unparseable")
        self.assertInvalid(hdf() + b"1,2\r\n", "columns")


class ConfigTests(unittest.TestCase):
    BASE = {"ESBN_USERNAME": "u", "ESBN_PASSWORD": "p", "ESBN_MPRN": MPRN, "OUTPUT_PATH": "/tmp/x.csv"}

    def test_defaults(self):
        cfg = m.Config.from_env(self.BASE)
        self.assertEqual(cfg.twocaptcha_min_balance, 2.0)
        self.assertIsNone(cfg.twocaptcha_api_key)
        self.assertEqual(cfg.max_data_age_days, 7)

    def test_missing_and_bad_values(self):
        for broken in ({"ESBN_PASSWORD": ""}, {"ESBN_MPRN": "123"}, {"TWOCAPTCHA_MIN_BALANCE": "two"}):
            with self.assertRaises(m.ConfigError):
                m.Config.from_env({**self.BASE, **broken})

    def test_env_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
            f.write("# c\n\nexport ESBN_USERNAME='a b'\nESBN_MPRN=\"123\"\n")
        self.addCleanup(os.unlink, f.name)
        self.assertEqual(m.load_env_file(Path(f.name)), {"ESBN_USERNAME": "a b", "ESBN_MPRN": "123"})

    def test_mask(self):
        self.assertEqual(m.mask_mprn(MPRN), "********001")


class MainTests(unittest.TestCase):
    def test_failure_alerts_and_exits_1(self):
        sent = []
        env = {**ConfigTests.BASE, "ALERT_WEBHOOK_URL": "https://hook.example/x"}
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(m, "send_alert", lambda *a, **k: sent.append(a)), \
             mock.patch.object(m, "run", side_effect=m.RunError("HDF download", "HTTP 500")):
            self.assertEqual(m.main([]), 1)
        self.assertEqual(sent[0][1:], ("error", "failed at HDF download: HTTP 500"))

    def test_unexpected_exception_still_alerts(self):
        sent = []
        with mock.patch.dict(os.environ, ConfigTests.BASE, clear=True), \
             mock.patch.object(m, "send_alert", lambda *a, **k: sent.append(a)), \
             mock.patch.object(m, "run", side_effect=KeyError("boom")):
            self.assertEqual(m.main([]), 1)
        self.assertIn("unexpected error", sent[0][2])

    def test_config_error_exits_2(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(m, "send_alert"):
            self.assertEqual(m.main([]), 2)

    def test_systemd_failure_alert_dedupes(self):
        sent = []
        with mock.patch.object(m, "send_alert", lambda *a, **k: sent.append(a)):
            m.systemd_failure_alert({"MONITOR_EXIT_CODE": "exited", "MONITOR_EXIT_STATUS": "1"})
            self.assertEqual(sent, [])
            m.systemd_failure_alert({"MONITOR_EXIT_CODE": "killed", "MONITOR_EXIT_STATUS": "TERM"})
            self.assertEqual(len(sent), 1)
            self.assertIn("killed TERM", sent[0][2])


class TwoCaptchaTests(unittest.TestCase):
    def solver(self, payload):
        session = mock.Mock()
        session.post.return_value = resp(200, json.dumps(payload))
        return m.TwoCaptcha("k", 10, session=session, poll_seconds=0)

    def test_balance(self):
        self.assertEqual(self.solver({"errorId": 0, "balance": 12.3456}).balance(), 12.3456)

    def test_error_codes(self):
        for code, needle in (("ERROR_ZERO_BALANCE", "out of credit"),
                             ("ERROR_KEY_DOES_NOT_EXIST", "rejected"),
                             ("ERROR_OTHER", "ERROR_OTHER")):
            with self.assertRaises(m.RunError) as ctx:
                self.solver({"errorId": 1, "errorCode": code}).balance()
            self.assertIn(needle, ctx.exception.reason)


if __name__ == "__main__":
    unittest.main()
