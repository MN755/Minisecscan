# MiniSecScan

Passive checks for web security headers, mixed content, password forms, cookies,
and other HTML security signals. Findings produce a JSON report, score, and exit
status. This is a heuristic scanner, not a complete security assessment.

## Run a scan

Requires Python 3.11 or newer.

```sh
python -m pip install -r requirements.txt
python run.py --url https://your-owned-site.example --min-score 75 --fail-on HIGH --out report.json
```

Replace the example URL with a running website you own or have permission to scan.
A GitHub source repository URL scans GitHub's rendered page, not the application's
source code. Local HTML is also supported:

```sh
python run.py --file ./dist/index.html --min-score 75 --fail-on HIGH --out report.json
```

File mode checks HTML only; it cannot assess a server's headers or TLS.

## Scanner CI

The `scan` check validates this scanner against controlled pages rather than
depending on an unrelated public website. Run its regression suite locally with
OpenSSL installed:

```sh
python -m unittest discover -s tests -v
```

Tests exercise both CLI distributions over a real loopback HTTPS server with an
ephemeral trusted test certificate. Secure pages must pass the default score of
75 and HIGH severity policy. Pages with missing security headers, mixed content,
unsafe password forms, or insecure cookies must fail. Tests also verify TLS
rejection, connection failures, local-file scans, and configurable score/severity
thresholds. Certificates and keys stay in temporary directories and are never
uploaded.

CI additionally runs the composite action against the secure HTTPS fixture and
checks its actual score, grade, and findings outputs. A separate deliberate
vulnerable fixture must fail and export its findings/report; CI fails if it passes
or fails for a different reason. No scanner rule or policy
threshold is relaxed. Fixture success validates the scanner integration; it does
not certify any externally hosted website.

## Scan an actual website in Actions

Run **Actions → MiniSecScan → Run workflow** and supply an owned HTTPS website in
`target_url`. Alternatively, set repository variable `MINISECSCAN_TARGET_URL` to
scan that website on pull requests and pushes to `main` as well. No target is
configured by default. Without either value, the separately named
`configured website scan` job is skipped; the mandatory scanner regression check
still runs. This is explicitly an unconfigured website scan, not a clean result.

Website scans retain `min_score: 75` and `fail_on: HIGH`. Both action copies accept
`url`, `file`, `min_score`, `fail_on`, `output_json`, and `artifact_name` inputs and
expose `score`, `grade`, and `findings` outputs. JSON reports are uploaded even
when the scan fails, provided the scanner produced a report. Do not put
credentials in target URLs or public reports.
