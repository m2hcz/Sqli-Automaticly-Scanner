# Auto-Mapper Scanner

[![node](https://img.shields.io/badge/Node-18%2B-339933?logo=node.js\&logoColor=white)](#)
[![parallel](https://img.shields.io/badge/Parallel-crawl%20%7C%20scan-informational)](#)
[![status](https://img.shields.io/badge/Status-alpha-success)](#)

> **Single-file Crawler + Active Scanner** (Node 18+, global `fetch`).
> Maps a **same-origin** web app, discovers links/forms, and probes for **SQLi**, **Reflected XSS**, **Open Redirect**, **LFI/Path Traversal**, and **DOM XSS indicators** using fast heuristics.
> **AUTHORIZED TESTING ONLY.** · Made by **m2hcs** · `auto-mapper-scanner.js`

---

## Table of Contents

* [Features](#features)
* [What’s New](#whats-new)
* [Requirements](#requirements)
* [Install](#install)
* [Quick Start](#quick-start)
* [Usage / CLI](#usage--cli)
* [Outputs](#outputs)
* [Detection Details & Thresholds](#detection-details--thresholds)
* [How It Works](#how-it-works)
* [Tuning & Performance](#tuning--performance)
* [Limitations](#limitations)
* [CI / Automation](#ci--automation)
* [Ethics & Legality](#ethics--legality)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)

---

## Features

* 🧭 **Same-origin crawler (BFS)** with dedupe by `(method, url, enc, param-names)`.
* ⚡ **Aggressive parallelism** with a **minimum of 10 workers** enforced for both crawl and scan.
* 🧪 **Per-parameter heuristic probes**:

  * **SQL Injection**

    * *Error-based*: broad signature list (MySQL/Postgres/SQLite/MSSQL/Oracle/ODBC/…)
    * *Boolean-based*: differential content comparison
    * *Time-based*: `SLEEP/pg_sleep/WAITFOR`, `BENCHMARK(MD5)`, string/numeric variants
    * *Union/Order hints*: `UNION SELECT NULL,…`, `ORDER BY N`, `@@version`, `version()`, alt comment styles
  * **Reflected XSS**: multi-context payloads with random token + **CSP awareness** note
  * **Open Redirect**: common & encoded variants, `//`, `%2f`, backslashes, odd whitespace/paths
  * **LFI / Path Traversal**: Unix/Windows, double-encoding, `php://filter`, null byte, etc.
  * **DOM XSS indicators**: static source→sink HTML patterns (no JS execution)
* 🧾 **Human-friendly summary** (stdout) **or** **JSON** (`--json`) for pipelines.
* 🧱 Guardrails: timeouts, response body cap (`--max-body-kb`), endpoint-per-page cap.
* 🔇 **Verbosity**: `silent|minimal|normal|debug|trace` (+ `--verbose`).

---

## What’s New

* ✅ **Minimum workers = 10** for `--concurrency` and `--scan-concurrency` (enforced).
* ✅ **Expanded SQLi payloads**: extra escapes, *BENCHMARK/MD5*, `dbms_pipe.receive_message` (string), more comment styles.
* ✅ **Stronger Open Redirect set**: `///`, `%2f%2f`, `%09`, backslashes, mixed path tricks.
* ✅ **Broader Traversal/LFI set**: double-encoding, `file://`, `php://filter` with convert/string modes.
* ✅ **Larger XSS payload set**: autofocus/onfocus, body onload, textarea escapes, pseudo `javascript:`.
* ✅ **CSP presence note** on XSS findings.
* ✅ Updated usage/help to reflect the new defaults.

---

## Requirements

* **Node.js 18+** (relies on global `fetch`)
* Network access to the target
* Explicit permission to test the target

---

## Install

**Drop-in**

```bash
curl -O https://raw.githubusercontent.com/<your-user>/<repo>/main/auto-mapper-scanner.js
node auto-mapper-scanner.js --help
```

**Repository**

```bash
git clone https://github.com/<your-user>/<repo>.git
cd <repo>
node auto-mapper-scanner.js --help
```

**Docker**

```Dockerfile
FROM node:18-alpine
WORKDIR /scan
COPY auto-mapper-scanner.js ./
ENTRYPOINT ["node","auto-mapper-scanner.js"]
```

```bash
docker build -t mapper-scan .
docker run --rm mapper-scan --url "https://app.example.com/"
```

---

## Quick Start

```bash
node auto-mapper-scanner.js --url "https://staging.example.com/"
```

More breadth + auth:

```bash
node auto-mapper-scanner.js \
  --url "https://staging.example.com/app" \
  --max-pages 400 --max-depth 5 \
  --concurrency 16 --scan-concurrency 16 \
  --header "Cookie: session=XYZ"
```

Emit JSON:

```bash
node auto-mapper-scanner.js --url "https://staging.example.com" --json > report.json
```

---

## Usage / CLI

```bash
node auto-mapper-scanner.js --url "https://target/"
  [--max-pages 200 --max-depth 3 --concurrency 10 --scan-concurrency 10]
  [--timeout 15000 --sleep 4 --max-body-kb 512]
  [--verbosity silent|minimal|normal|debug|trace | --verbose]
  [--json]
  [--param-ignore "(csrf|token)"]
  [--header "Cookie: sid=abc"]   # repeatable
```

| Option               |        Default | Description                                                |         |        |        |          |          |                                  |
| -------------------- | -------------: | ---------------------------------------------------------- | ------- | ------ | ------ | -------- | -------- | -------------------------------- |
| `--url`              | **(required)** | Entry URL; defines the **same-origin** scope.              |         |        |        |          |          |                                  |
| `--max-pages`        |          `200` | Crawl page cap.                                            |         |        |        |          |          |                                  |
| `--max-depth`        |            `3` | Link depth limit.                                          |         |        |        |          |          |                                  |
| `--concurrency`      |    **min. 10** | Crawl workers (enforced minimum = 10).                     |         |        |        |          |          |                                  |
| `--scan-concurrency` |    **min. 10** | Scan workers (enforced minimum = 10).                      |         |        |        |          |          |                                  |
| `--timeout` (ms)     |        `15000` | Per-request timeout.                                       |         |        |        |          |          |                                  |
| `--sleep` (s)        |            `4` | Base for time-based SQLi.                                  |         |        |        |          |          |                                  |
| `--max-body-kb`      |          `512` | Cap on captured response body per request.                 |         |        |        |          |          |                                  |
| `--verbosity`        |       `normal` | \`silent                                                   | minimal | normal | debug  | trace\`. |          |                                  |
| `--verbose`          |              — | Shortcut for `debug`.                                      |         |        |        |          |          |                                  |
| `--json`             |            off | Emit JSON to stdout.                                       |         |        |        |          |          |                                  |
| `--param-ignore`     |       \`/(csrf | xsrf                                                       | token   | auth   | passwd | password | pwd)/i\` | Skip volatile/secret-ish params. |
| `--header`           |           `{}` | Extra header (repeatable): `Cookie`, `Authorization`, etc. |         |        |        |          |          |                                  |

> **Auth tip:**
> `--header "Cookie: session=XYZ" --header "Authorization: Bearer <token>"`

---

## Outputs

### Text (stdout)

```
=== SUMMARY ===
Analyzed endpoints: 87
- SQLi (boolean-based): 2
  GET https://staging.example.com/search [q] (ΔF=0.41 vs ΔT=0.08)
- XSS (reflected): 1
  GET https://staging.example.com/profile [name] (No CSP header observed)
- Open Redirect: 1
  GET https://staging.example.com/callback [next] (to=https://example.com/evil)
```

### JSON (`--json`)

```json
{
  "url": "https://staging.example.com",
  "analyzedEndpoints": 87,
  "findings": [
    {
      "type": "SQLi (union/order heuristic)",
      "endpoint": "https://staging.example.com/items",
      "method": "GET",
      "param": "page",
      "note": "Δ≈1.06"
    }
  ]
}
```

---

## Detection Details & Thresholds

* **Boolean-based SQLi**
  Compute two deltas vs. baseline (`ΔT` for *true*, `ΔF` for *false*). Flag if
  `ΔF − ΔT ≥ 0.20` **or** HTTP `status` differs.

* **Union/Order heuristic**
  Compare injected response to baseline; flag if **SQL error signatures** match **or** `Δ ≥ 0.35`.
  *Payloads*: `ORDER BY 1..6`, `UNION SELECT NULL[, …]`, `@@version`, `version()`, comment variations (`-- -`, `#`, `/*`).

* **Time-based SQLi**
  Flag if `response.timeMs ≥ baseline.timeMs + max(1800ms, sleep*800ms)`.
  *Payloads*: `SLEEP(s)`, `pg_sleep(s)`, `WAITFOR DELAY '0:0:s'`, `BENCHMARK(200000,MD5(1))`, `dbms_pipe.receive_message('a',s)` (string context).

* **Reflected XSS**
  Look for raw token reflection **without** encoding + executable contexts (`<script>`, `onerror=`, `<svg/onload>`, etc.).
  Note whether a `Content-Security-Policy` header is present.

* **Open Redirect**
  Check 3xx + `Location`/final URL containing `example.com` **or** body mention.
  *Payloads*: `https://…`, `//…`, `///…`, `%2f%2f…`, `%09`, backslashes, path tricks.

* **LFI / Traversal**
  Positive content signatures (`/etc/passwd`, `win.ini`) **or** include/require error messages.

> These are **heuristics**. Treat findings as **indicators** for manual validation.

---

## How It Works

1. **Crawl (same-origin)**

   * Basic headers (`Accept:*/*`, tool `User-Agent`)
   * Extract links + forms via lightweight regex
   * Build unique endpoints `(method,url,enc,params)`

2. **Baseline**

   * Two baseline requests per endpoint to stabilize `status/time/body`
   * Apply `maxBodyKB` cap

3. **Per-parameter Probing**

   * SQLi (error/boolean/union/time)
   * Reflected XSS (token + contexts)
   * Open Redirect (encoding tricks)
   * LFI/Traversal (Unix/Win/PHP streams)

4. **Report**

   * Group by type; print summary or JSON

---

## Tuning & Performance

* **Coverage**: raise `--max-pages` / `--max-depth`.
* **Speed**: scale `--concurrency` / `--scan-concurrency` (min=10; mind WAF/rate limits).
* **Robustness**: increase `--timeout` and `--sleep` on noisy networks.
* **Noise**: strengthen `--param-ignore` to skip CSRF/nonces and secrets.
* **Heavy pages**: lower `--max-body-kb` on very large HTML.

---

## Limitations

* **Heuristic** engine, not a full exploit tool: false positives/negatives are possible.
* **No JS execution**: DOM XSS indicators are static (non-executing).
* **Same-origin only**: cross-origin links are ignored by design.
* **Regex HTML parsing**: ultra-fast; highly dynamic forms may be missed.

---

## CI / Automation

```yaml
name: mapper-scan
on:
  workflow_dispatch:
  push:
    branches: [ main ]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 18 }
      - name: Run scan
        run: node auto-mapper-scanner.js --url "${{ secrets.TARGET_URL }}" --json > report.json
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: mapper-report
          path: report.json
```

---

## Ethics & Legality

Use this tool **only** against systems you **own** or have **explicit authorization** to test.
Respect applicable laws, scope, and organizational policies.

---

## Roadmap

* Automatic repeatability/stability checks (multiple runs per payload)
* Noise control (“ghost param”) to adapt thresholds dynamically
* SARIF / NDJSON / SQLite exports

---

## Contributing

Issues and PRs are welcome. Please include:

* Minimal reproducible target snippets (redacted)
* Before/after metrics for signal quality or performance
* Relevant logs or JSON findings (redacted)

--
