# esbn-hdf-download

Downloads your ESB Networks smart-meter data, the half-hourly kWh "HDF" CSV from
[myaccount.esbnetworks.ie](https://myaccount.esbnetworks.ie), and saves it to a file. No MQTT
and no Home Assistant needed. It runs once and exits, so you schedule it with cron or a systemd timer.

It's built to **fail loudly**:

- a non-zero exit code, plus a log line naming the step that broke (sign-in, CAPTCHA, token, download, validation)
- an optional webhook POST on every failure
- the CSV is checked before it's saved: expected header, your MPRN on every row, parseable values and dates, newest reading recent enough. An HTML login page or a stuck export is never written over your last good file.
- one attempt per run, with no retry loop, so a broken run can't keep spending CAPTCHA credit

## Requirements

- Python 3.10+
- `requests`
- An ESB Networks online account with your MPRN added
- Optional: a [2Captcha](https://2captcha.com) API key. ESB sometimes shows a reCAPTCHA at sign-in; without a key, those runs fail with a clear message.

## Install

```sh
git clone https://github.com/colfin22/esbn-hdf-download.git /opt/esbn-hdf-download
cd /opt/esbn-hdf-download
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

install -d -m 700 /etc/esbn-hdf-download /var/lib/esbn-hdf-download
install -m 600 .env.example /etc/esbn-hdf-download/esbn.env
# edit /etc/esbn-hdf-download/esbn.env
```

Run it once by hand:

```sh
.venv/bin/python esbn_hdf_download.py --env-file /etc/esbn-hdf-download/esbn.env
```

## Configuration

All settings are environment variables. `--env-file` reads them from a `KEY=VALUE` file, and see [`.env.example`](.env.example) for the full list.

| Variable | Required | Default | |
|---|---|---|---|
| `ESBN_USERNAME` / `ESBN_PASSWORD` | yes | | ESB Networks account |
| `ESBN_MPRN` | yes | | 11-digit MPRN |
| `OUTPUT_PATH` | yes | | where the CSV is written |
| `ESBN_COOKIE_FILE` | no | | reuse the portal session between runs |
| `TWOCAPTCHA_API_KEY` | no | | solve sign-in reCAPTCHAs |
| `TWOCAPTCHA_MIN_BALANCE` | no | `2.00` | warn below this balance (USD) |
| `TWOCAPTCHA_TIMEOUT_SECONDS` | no | `180` | |
| `MAX_DATA_AGE_DAYS` | no | `7` | fail if the newest reading is older |
| `ALERT_WEBHOOK_URL` | no | | JSON POST on failure/warning |

## Alerts

When `ALERT_WEBHOOK_URL` is set, the script POSTs:

```json
{"level": "error", "source": "esbn-hdf-download", "reason": "failed at HDF download: HTTP 500", "step": "HDF download"}
```

- `level: "error"`: the run failed, and the previous CSV is untouched.
- `level: "warning"`: the CSV was saved, but something needs attention. Usually the
  2Captcha balance is under `TWOCAPTCHA_MIN_BALANCE`; the message includes the balance and,
  after a solve, roughly how many solves are left at that run's cost.

Point it at anything that takes a JSON POST: a Node-RED `http in` node, a Home Assistant webhook automation, ntfy, and so on.

## 2Captcha credit

When a key is configured, every run reads the balance (a free API call). It reads it again after a
solve and logs what that run cost. Running out of credit, or a rejected key, gets its own error
message rather than a generic sign-in failure.

## systemd

Example units are in [`examples/systemd`](examples/systemd):

```sh
cp examples/systemd/esbn-hdf-download*.{service,timer} /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now esbn-hdf-download.timer
```

`esbn-hdf-download-failed.service` is the `OnFailure=` handler. It sends an alert if the run
was killed or timed out, i.e. failed before the script could report it, and stays quiet
when the script has already alerted.

To do something with the file after a good run (copy it elsewhere, trigger an import), add an
`ExecStartPost=` in a drop-in. It only runs when the download succeeded.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | CSV saved (check the log/webhook for warnings) |
| 1 | run failed, previous CSV kept |
| 2 | configuration error |

## When ESB change their portal

ESB Networks change the portal without notice, which is the usual cause of breakage. The failing
step in the log tells you where to look. A `404`/`405` at "HDF download" means the endpoint moved;
the current one is in the consumption page's script bundle (search it for `DownloadHdfPeriodic`).

## Tests

```sh
python3 -m unittest discover -s tests
```

## Licence

MIT. Not affiliated with ESB Networks.
