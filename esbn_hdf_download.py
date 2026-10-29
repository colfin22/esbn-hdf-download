#!/usr/bin/env python3
"""Download the ESB Networks smart-meter HDF (half-hourly kWh CSV) for one MPRN.

Runs once and exits. Configuration comes from environment variables (see
.env.example). Exit codes: 0 = CSV saved (possibly with a warning),
1 = run failed, 2 = configuration error.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from html.parser import HTMLParser
from http.cookiejar import LoadError, MozillaCookieJar
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

__version__ = "1.0.0"

LOG = logging.getLogger("esbn-hdf-download")

PORTAL = "https://myaccount.esbnetworks.ie"
LOGIN_HOST = "login.esbnetworks.ie"
B2C_POLICY = "B2C_1A_signup_signin"
B2C_TENANT_PATH = f"https://{LOGIN_HOST}/esbntwkscustportalprdb2c01.onmicrosoft.com/{B2C_POLICY}"
CONSUMPTION_PAGE = f"{PORTAL}/energymanagement/historic-consumption"
TOKEN_URL = f"{PORTAL}/af/t"
DOWNLOAD_URL = f"{PORTAL}/energymanagement/api/consumption/DownloadHdfPeriodic"

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0"
HDF_HEADER = ["MPRN", "Meter Serial Number", "Read Value", "Read Type", "Read Date and End Time"]
HDF_DATE_FORMAT = "%d-%m-%Y %H:%M"
MAX_CSV_BYTES = 50 * 1024 * 1024
DEFAULT_CAPTCHA_CLAIM = "g-recaptcha-response-toms"
TWOCAPTCHA_API = "https://api.2captcha.com"
HTTP_TIMEOUT = 60


class RunError(Exception):
    """A failure with a human-readable reason; the step says where it broke."""

    def __init__(self, step: str, reason: str) -> None:
        super().__init__(f"{step}: {reason}")
        self.step = step
        self.reason = reason


class ConfigError(Exception):
    pass


# --------------------------------------------------------------------------- config


@dataclass(frozen=True)
class Config:
    username: str
    password: str
    mprn: str
    output_path: Path
    twocaptcha_api_key: str | None = None
    twocaptcha_min_balance: float = 2.0
    twocaptcha_timeout: int = 180
    max_data_age_days: int = 7
    alert_webhook_url: str | None = None
    cookie_file: Path | None = None
    search_type: str = "intervalkwh"

    @classmethod
    def from_env(cls, env: dict[str, str]) -> "Config":
        def req(name: str) -> str:
            value = env.get(name, "").strip()
            if not value:
                raise ConfigError(f"{name} is not set")
            return value

        def opt(name: str) -> str | None:
            value = env.get(name, "").strip()
            return value or None

        def num(name: str, default: float, kind: type) -> float:
            raw = opt(name)
            if raw is None:
                return default
            try:
                return kind(raw)
            except ValueError as exc:
                raise ConfigError(f"{name} must be a number, got {raw!r}") from exc

        mprn = req("ESBN_MPRN")
        if not re.fullmatch(r"\d{11}", mprn):
            raise ConfigError("ESBN_MPRN must be the 11-digit MPRN")
        cookie = opt("ESBN_COOKIE_FILE")
        return cls(
            username=req("ESBN_USERNAME"),
            password=req("ESBN_PASSWORD"),
            mprn=mprn,
            output_path=Path(req("OUTPUT_PATH")),
            twocaptcha_api_key=opt("TWOCAPTCHA_API_KEY"),
            twocaptcha_min_balance=num("TWOCAPTCHA_MIN_BALANCE", 2.0, float),
            twocaptcha_timeout=int(num("TWOCAPTCHA_TIMEOUT_SECONDS", 180, int)),
            max_data_age_days=int(num("MAX_DATA_AGE_DAYS", 7, int)),
            alert_webhook_url=opt("ALERT_WEBHOOK_URL"),
            cookie_file=Path(cookie) if cookie else None,
            search_type=opt("ESBN_SEARCH_TYPE") or "intervalkwh",
        )


def load_env_file(path: Path) -> dict[str, str]:
    """Minimal KEY=VALUE parser (comments, blank lines, optional quotes)."""
    values: dict[str, str] = {}
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        if not sep or not key.strip():
            raise ConfigError(f"{path}:{lineno}: expected KEY=VALUE")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def mask_mprn(mprn: str) -> str:
    return "*" * (len(mprn) - 3) + mprn[-3:]


# --------------------------------------------------------------------------- alerts


def send_alert(url: str | None, level: str, reason: str, *, details: dict | None = None) -> None:
    """POST {"level","source","reason",...} to the webhook. Never raises."""
    if not url:
        return
    payload = {"level": level, "source": "esbn-hdf-download", "reason": reason}
    if details:
        payload.update(details)
    try:
        response = requests.post(url, json=payload, timeout=15)
        if response.status_code >= 400:
            LOG.error("alert webhook returned HTTP %s", response.status_code)
    except requests.RequestException as exc:
        LOG.error("alert webhook POST failed: %s", exc.__class__.__name__)


# --------------------------------------------------------------------------- 2Captcha


class TwoCaptcha:
    def __init__(self, api_key: str, timeout: int, session: requests.Session | None = None,
                 poll_seconds: float = 5.0) -> None:
        self._key = api_key
        self._timeout = timeout
        self._poll = poll_seconds
        self._http = session or requests.Session()

    def _call(self, method: str, body: dict) -> dict:
        step = f"2Captcha {method}"
        try:
            response = self._http.post(f"{TWOCAPTCHA_API}/{method}",
                                       json={"clientKey": self._key, **body}, timeout=30)
            data = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise RunError(step, f"request failed ({exc.__class__.__name__})") from exc
        if not isinstance(data, dict):
            raise RunError(step, "unexpected response")
        if data.get("errorId", 0) != 0:
            code = str(data.get("errorCode") or data.get("errorId"))
            if code == "ERROR_ZERO_BALANCE":
                raise RunError(step, "2Captcha account is out of credit")
            if code in ("ERROR_KEY_DOES_NOT_EXIST", "ERROR_WRONG_USER_KEY"):
                raise RunError(step, "2Captcha API key was rejected")
            raise RunError(step, f"2Captcha error {code}")
        return data

    def balance(self) -> float:
        value = self._call("getBalance", {}).get("balance")
        if not isinstance(value, (int, float)):
            raise RunError("2Captcha getBalance", "no balance in response")
        return float(value)

    def solve_recaptcha_v2(self, page_url: str, site_key: str) -> str:
        task = self._call("createTask", {"task": {
            "type": "RecaptchaV2TaskProxyless", "websiteURL": page_url, "websiteKey": site_key}})
        task_id = task.get("taskId")
        if not task_id:
            raise RunError("2Captcha createTask", "no taskId in response")
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            time.sleep(self._poll)
            result = self._call("getTaskResult", {"taskId": task_id})
            if result.get("status") == "ready":
                token = (result.get("solution") or {}).get("gRecaptchaResponse")
                if not token:
                    raise RunError("2Captcha getTaskResult", "empty solution")
                return token
        raise RunError("2Captcha getTaskResult", f"no solution within {self._timeout}s")


# --------------------------------------------------------------------------- HTML helpers


def extract_js_object(body: str, name: str) -> dict | None:
    match = re.search(rf"var {name}\s*=\s*(\{{.*?\}});", body, re.DOTALL)
    if not match:
        return None
    try:
        value = json.loads(match.group(1))
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def b2c_settings(body: str, step: str) -> tuple[str, str]:
    settings = extract_js_object(body, "SETTINGS") or {}
    csrf, trans_id = settings.get("csrf"), settings.get("transId")
    if not isinstance(csrf, str) or not csrf or not isinstance(trans_id, str) or not trans_id:
        raise RunError(step, "sign-in page did not contain the expected SETTINGS block "
                             "(ESB may have changed their login page)")
    return csrf, trans_id


def is_captcha_page(body: str) -> bool:
    lowered = body.lower()
    return "g-recaptcha-response" in lowered or "captcha.html" in lowered or "not a robot" in lowered


def captcha_claim_id(body: str) -> str:
    fields = (extract_js_object(body, "SA_FIELDS") or {}).get("AttributeFields")
    if isinstance(fields, list):
        for field in fields:
            field_id = field.get("ID") if isinstance(field, dict) else None
            if isinstance(field_id, str) and "recaptcha" in field_id.lower():
                return field_id
    return DEFAULT_CAPTCHA_CLAIM


def find_site_key(body: str) -> str | None:
    for pattern in (r"data-sitekey\s*=\s*['\"]([^'\"]+)['\"]", r"sitekey\s*:\s*['\"]([^'\"]+)['\"]"):
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def script_sources(body: str, base: str) -> list[str]:
    sources = re.findall(r"<script[^>]+src\s*=\s*['\"]([^'\"]+)['\"]", body, re.IGNORECASE)
    # ESB's CAPTCHA template pulls its script in via a module import, not src=
    sources += re.findall(r"import\s+[^'\"]*['\"]([^'\"]+\.js[^'\"]*)['\"]", body)
    return [urljoin(base, src) for src in sources]


class _FormParser(HTMLParser):
    def __init__(self, form_id: str) -> None:
        super().__init__()
        self._form_id = form_id
        self._inside = False
        self.action: str | None = None
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "form" and a.get("id") == self._form_id:
            self._inside = True
            self.action = a.get("action")
        elif tag == "input" and self._inside and a.get("name"):
            self.fields[a["name"]] = a.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._inside = False


def parse_form(body: str, form_id: str) -> tuple[str | None, dict[str, str]]:
    parser = _FormParser(form_id)
    parser.feed(body)
    return parser.action, parser.fields


# --------------------------------------------------------------------------- CSV validation


@dataclass(frozen=True)
class HdfSummary:
    rows: int
    first: datetime
    last: datetime


def validate_hdf(content: bytes, mprn: str, max_age_days: int, now: datetime | None = None) -> HdfSummary:
    step = "CSV validation"
    if not content:
        raise RunError(step, "download was empty")
    if len(content) > MAX_CSV_BYTES:
        raise RunError(step, f"download is {len(content)} bytes, over the {MAX_CSV_BYTES} limit")
    if content.lstrip()[:1] == b"<":
        raise RunError(step, "download was an HTML page, not a CSV (session or endpoint problem)")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RunError(step, "download is not UTF-8 text") from exc

    reader = csv.reader(io.StringIO(text))
    header = next(reader, None)
    if header is None or [h.strip() for h in header] != HDF_HEADER:
        raise RunError(step, f"unexpected header {header!r} (ESB may have changed the file format)")

    rows = 0
    first = last = None
    for lineno, row in enumerate(reader, 2):
        if not row:
            continue
        if len(row) != len(HDF_HEADER):
            raise RunError(step, f"line {lineno} has {len(row)} columns, expected {len(HDF_HEADER)}")
        if row[0].strip() != mprn:
            raise RunError(step, f"line {lineno} is for a different MPRN")
        try:
            float(row[2])
            stamp = datetime.strptime(row[4].strip(), HDF_DATE_FORMAT)
        except ValueError as exc:
            raise RunError(step, f"line {lineno} has an unparseable value or date") from exc
        first = stamp if first is None or stamp < first else first
        last = stamp if last is None or stamp > last else last
        rows += 1

    if rows == 0 or first is None or last is None:
        raise RunError(step, "CSV has a header but no readings")
    now = now or datetime.now()
    if now - last > timedelta(days=max_age_days):
        raise RunError(step, f"newest reading is {last:%d-%m-%Y %H:%M}, older than "
                             f"{max_age_days} days (ESB export may be stuck)")
    return HdfSummary(rows=rows, first=first, last=last)


def write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------- ESBN client


class EsbnClient:
    def __init__(self, cfg: Config, captcha: TwoCaptcha | None,
                 session: requests.Session | None = None) -> None:
        self.cfg = cfg
        self.captcha = captcha
        self.captcha_solved = False
        self.http = session or requests.Session()
        self.http.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-IE,en;q=0.9",
        })
        self._jar: MozillaCookieJar | None = None
        if cfg.cookie_file:
            self._jar = MozillaCookieJar(str(cfg.cookie_file))
            if cfg.cookie_file.exists():
                try:
                    self._jar.load(ignore_discard=True, ignore_expires=True)
                except (LoadError, OSError):
                    LOG.warning("cookie file unreadable, starting a fresh session")
            for cookie in self._jar:
                self.http.cookies.set_cookie(cookie)

    # -- plumbing

    def _request(self, method: str, url: str, step: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", HTTP_TIMEOUT)
        try:
            return self.http.request(method, url, **kwargs)
        except requests.Timeout as exc:
            raise RunError(step, "timed out") from exc
        except requests.RequestException as exc:
            raise RunError(step, f"request failed ({exc.__class__.__name__})") from exc

    def _expect_ok(self, response: requests.Response, step: str) -> requests.Response:
        if response.status_code >= 400:
            raise RunError(step, f"HTTP {response.status_code}")
        return response

    @staticmethod
    def _on_login_page(response: requests.Response) -> bool:
        return urlparse(response.url).hostname == LOGIN_HOST or "var SETTINGS" in response.text

    def save_cookies(self) -> None:
        if self._jar is None or self.cfg.cookie_file is None:
            return
        self._jar.clear()
        for cookie in self.http.cookies:
            self._jar.set_cookie(cookie)
        self.cfg.cookie_file.parent.mkdir(parents=True, exist_ok=True)
        self._jar.save(ignore_discard=True, ignore_expires=True)
        os.chmod(self.cfg.cookie_file, 0o600)

    # -- login

    def ensure_logged_in(self, *, fresh: bool = False) -> bool:
        """Return True if an existing session was reused, False after a full sign-in."""
        step = "open consumption page"
        if fresh:
            self.http.cookies.clear()
        else:
            page = self._expect_ok(self._request("GET", CONSUMPTION_PAGE, step), step)
            if not self._on_login_page(page):
                LOG.info("existing portal session still valid, no login needed")
                return True
        LOG.info("signing in to ESB Networks")
        # Sign in from the portal home page, as a browser does: signing in straight from the
        # consumption page gives a session the download endpoint answers with HTTP 500.
        home = self._expect_ok(self._request("GET", f"{PORTAL}/", "open sign-in page"), "open sign-in page")
        self._login(home)
        page = self._expect_ok(self._request("GET", CONSUMPTION_PAGE, step), step)
        if self._on_login_page(page):
            raise RunError(step, "still redirected to sign-in after login completed")
        return False

    def _login(self, login_page: requests.Response) -> None:
        csrf, trans_id = b2c_settings(login_page.text, "sign-in page")
        self._self_asserted(csrf, trans_id, {"signInName": self.cfg.username,
                                             "password": self.cfg.password,
                                             "request_type": "RESPONSE"}, "submit credentials")
        confirmed = self._confirmed(csrf, trans_id)
        if is_captcha_page(confirmed.text):
            confirmed = self._solve_captcha(confirmed)
        self._post_back(confirmed.text)

    def _self_asserted(self, csrf: str, trans_id: str, data: dict, step: str) -> None:
        response = self._expect_ok(self._request(
            "POST", f"{B2C_TENANT_PATH}/SelfAsserted", step,
            params={"tx": trans_id, "p": B2C_POLICY}, data=data, allow_redirects=False,
            headers={"x-csrf-token": csrf, "X-Requested-With": "XMLHttpRequest",
                     "Origin": f"https://{LOGIN_HOST}",
                     "Accept": "application/json, text/javascript, */*; q=0.01"}), step)
        try:
            status = str(response.json().get("status"))
        except (ValueError, AttributeError):
            status = None
        if status != "200":
            message = ""
            try:
                message = str(response.json().get("message") or "")
            except (ValueError, AttributeError):
                pass
            raise RunError(step, f"rejected by ESB sign-in (status {status}) {message}".strip())

    def _confirmed(self, csrf: str, trans_id: str) -> requests.Response:
        step = "sign-in confirmation"
        return self._expect_ok(self._request(
            "GET", f"{B2C_TENANT_PATH}/api/CombinedSigninAndSignup/confirmed", step,
            params={"rememberMe": "false", "csrf_token": csrf, "tx": trans_id, "p": B2C_POLICY}), step)

    def _solve_captcha(self, page: requests.Response) -> requests.Response:
        step = "CAPTCHA"
        if self.captcha is None:
            raise RunError(step, "ESB asked for a CAPTCHA and no TWOCAPTCHA_API_KEY is configured")
        csrf, trans_id = b2c_settings(page.text, step)
        claim = captcha_claim_id(page.text)
        site_key = self._site_key(page)
        LOG.info("ESB asked for a CAPTCHA, sending it to 2Captcha")
        token = self.captcha.solve_recaptcha_v2(page.url, site_key)
        self.captcha_solved = True
        self._self_asserted(csrf, trans_id, {claim: token, "request_type": "RESPONSE"},
                            "submit CAPTCHA solution")
        confirmed = self._confirmed(csrf, trans_id)
        if is_captcha_page(confirmed.text):
            raise RunError(step, "ESB still showed a CAPTCHA after the 2Captcha solution")
        return confirmed

    def _site_key(self, page: requests.Response) -> str:
        step = "CAPTCHA site key"
        if key := find_site_key(page.text):
            return key
        remote = (extract_js_object(page.text, "SETTINGS") or {}).get("remoteResource")
        if isinstance(remote, str) and remote:
            template = self._expect_ok(self._request("GET", remote, step), step)
            if key := find_site_key(template.text):
                return key
            for src in script_sources(template.text, remote):
                script = self._expect_ok(self._request("GET", src, step), step)
                if key := find_site_key(script.text):
                    return key
        raise RunError(step, "could not find the reCAPTCHA site key")

    def _post_back(self, body: str) -> None:
        step = "complete sign-in"
        action, fields = parse_form(body, "auto")
        # post every field the form carries, as a browser would; code + state are the essentials
        missing = [name for name in ("state", "code") if not fields.get(name)]
        if not action or missing:
            empty = sorted(name for name, value in fields.items() if not value)
            raise RunError(step, f"sign-in hand-off form incomplete (missing {missing or 'action'}; "
                                 f"fields seen {sorted(fields)}, empty {empty}, "
                                 f"{len(body)} bytes); wrong password or ESB changed their login")
        response = self._request("POST", action, step, data=fields, allow_redirects=False)
        location = response.headers.get("location", "")
        target = urlparse(urljoin(action, location))
        if response.status_code not in (302, 303) or target.hostname != urlparse(PORTAL).hostname:
            raise RunError(step, f"portal did not accept the sign-in (HTTP {response.status_code})")

    # -- download

    def download(self) -> bytes:
        step = "XSRF token"
        headers = {"x-ReturnUrl": CONSUMPTION_PAGE}
        response = self._expect_ok(self._request("GET", TOKEN_URL, step, headers=headers), step)
        try:
            token = response.json()["token"]
        except (ValueError, KeyError, TypeError) as exc:
            raise RunError(step, "token endpoint did not return a token") from exc

        step = "HDF download"
        response = self._request("POST", DOWNLOAD_URL, step,
                                 json={"mprn": self.cfg.mprn, "searchType": self.cfg.search_type},
                                 headers={"X-XSRF-TOKEN": token, "x-ReturnUrl": CONSUMPTION_PAGE,
                                          "Referer": CONSUMPTION_PAGE, "Accept": "*/*"},
                                 allow_redirects=False)
        if response.status_code in (301, 302, 303, 307, 308):
            raise RunError(step, "redirected (session not accepted)")
        if response.status_code == 404 or response.status_code == 405:
            raise RunError(step, f"HTTP {response.status_code} - ESB has likely moved the download "
                                 "endpoint again; check the portal's consumption page script")
        return self._expect_ok(response, step).content


# --------------------------------------------------------------------------- run


def run(cfg: Config, *, captcha: TwoCaptcha | None = None, session: requests.Session | None = None,
        now: datetime | None = None) -> int:
    LOG.info("esbn-hdf-download %s for MPRN %s", __version__, mask_mprn(cfg.mprn))
    if captcha is None and cfg.twocaptcha_api_key:
        captcha = TwoCaptcha(cfg.twocaptcha_api_key, cfg.twocaptcha_timeout)

    balance_before = None
    if captcha is not None:
        try:
            balance_before = captcha.balance()
            LOG.info("2Captcha balance: $%.2f", balance_before)
        except RunError as exc:
            if "rejected" in exc.reason:
                raise
            # 2Captcha unreachable: ESB may not ask for a CAPTCHA, so carry on and say so.
            LOG.warning("could not read 2Captcha balance: %s", exc.reason)
            send_alert(cfg.alert_webhook_url, "warning", f"could not read 2Captcha balance: {exc.reason}")

    client = EsbnClient(cfg, captcha, session)
    try:
        reused = client.ensure_logged_in()
        try:
            content = client.download()
        except RunError as exc:
            if not reused:
                raise
            # A saved session can look valid but be refused; sign in fresh once, never more.
            LOG.warning("download with saved session failed (%s), signing in fresh", exc.reason)
            client.ensure_logged_in(fresh=True)
            content = client.download()
    finally:
        client.save_cookies()

    summary = validate_hdf(content, cfg.mprn, cfg.max_data_age_days, now)
    write_atomic(cfg.output_path, content)
    LOG.info("saved %s: %d readings, %s to %s", cfg.output_path, summary.rows,
             f"{summary.first:%d-%m-%Y}", f"{summary.last:%d-%m-%Y %H:%M}")

    if captcha is not None and balance_before is not None:
        balance = captcha.balance() if client.captcha_solved else balance_before
        cost = balance_before - balance if client.captcha_solved else 0.0
        if client.captcha_solved:
            LOG.info("2Captcha balance after solve: $%.2f (this run cost $%.4f)", balance, cost)
        if balance < cfg.twocaptcha_min_balance:
            reason = f"2Captcha balance low: ${balance:.2f} (warning threshold ${cfg.twocaptcha_min_balance:.2f})"
            if cost > 0:
                reason += f", about {int(balance // cost)} solves left at this run's cost"
            LOG.warning(reason)
            send_alert(cfg.alert_webhook_url, "warning", reason,
                       details={"balance": round(balance, 4)})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--env-file", type=Path, help="read settings from this KEY=VALUE file")
    parser.add_argument("--systemd-failure-alert", action="store_true",
                        help="for an OnFailure= unit: alert unless the main run already did")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    env = dict(os.environ)
    try:
        if args.env_file:
            env.update(load_env_file(args.env_file))
        if args.systemd_failure_alert:
            return systemd_failure_alert(env)
        cfg = Config.from_env(env)
    except (ConfigError, OSError) as exc:
        LOG.error("configuration error: %s", exc)
        send_alert(env.get("ALERT_WEBHOOK_URL"), "error", f"configuration error: {exc}")
        return 2

    try:
        return run(cfg)
    except RunError as exc:
        LOG.error("FAILED at %s: %s", exc.step, exc.reason)
        send_alert(cfg.alert_webhook_url, "error", f"failed at {exc.step}: {exc.reason}",
                   details={"step": exc.step})
    except Exception as exc:  # noqa: BLE001 - anything unexpected must still alert
        LOG.exception("FAILED with an unexpected error")
        send_alert(cfg.alert_webhook_url, "error", f"unexpected error: {exc.__class__.__name__}: {exc}")
    return 1


def systemd_failure_alert(env: dict[str, str]) -> int:
    """Run from OnFailure=. Exit status 1 or 2 means the script already alerted itself."""
    code, status = env.get("MONITOR_EXIT_CODE", ""), env.get("MONITOR_EXIT_STATUS", "")
    unit = env.get("MONITOR_UNIT", "esbn-hdf-download.service")
    if code == "exited" and status in ("1", "2"):
        LOG.info("%s already sent its own alert (exit %s)", unit, status)
        return 0
    send_alert(env.get("ALERT_WEBHOOK_URL"), "error",
               f"{unit} failed without reporting ({code or 'unknown'} {status}); see journalctl -u {unit}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
