# Auto-Mapper Scanner

[![node](https://img.shields.io/badge/Node-18%2B-339933?logo=node.js\&logoColor=white)](#)
[![parallel](https://img.shields.io/badge/Parallel-crawl%20%7C%20scan-informational)](#)
[![status](https://img.shields.io/badge/Status-alpha-success)](#)

> Single-file **crawler + active scanner** for same-origin web apps.
> Discovers links/forms and probes for **SQLi**, **Reflected XSS**, **Open Redirect**, **LFI/Traversal**, and **DOM XSS indicators** using fast, lightweight heuristics.
> Made by **m2hcs** · `auto-mapper-scanner.js` · **Node 18+ (global `fetch`)**

---

## Table of Contents

* [Features](#features)
* [Requirements](#requirements)
* [Install](#install)
* [Quick Start](#quick-start)
* [Usage / CLI](#usage--cli)
* [Examples](#examples)
* [Outputs](#outputs)
* [How It Works](#how-it-works)
* [Tuning](#tuning)
* [Limitations](#limitations)
* [Ethics & Legality](#ethics--legality)
* [CI / Automation](#ci--automation)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)

---

## Features

* 🧭 **Same-origin crawler (BFS)**
  Discovers links & HTML forms without a browser; de-dups endpoints by `(method, url, enc, param-names)`.

* ⚡ **Parallelized crawl & scan**
  Control workers with `--concurrency` and `--scan-concurrency`.

* 🧪 **Heuristic probes** (per parameter)

  * **SQLi**: error-based, boolean differential (content deltas), time-based (`SLEEP/pg_sleep/WAITFOR`), and union/order hints.
  * **Reflected XSS**: multi-context payloads with random tokens; notes presence/absence of **CSP**.
  * **Open Redirect**: common & encoded variants; redirect-chain aware.
  * **LFI / Path Traversal**: Unix/Windows paths, encoded bypasses, `php://filter`; flags include/require error leaks.
  * **DOM XSS indicators**: static HTML source→sink heuristics (non-executing).

* 🧰 **Form & query fuzzing** with **skip regex** for volatile params (`--param-ignore`).

* 🧾 **Readable summary** (stdout) **or** **JSON** (`--json`) for pipelines.

* 🧱 **Safety rails**: timeouts, response body cap, endpoint cap.

---

## Requirements

* **Node.js 18+** (uses global `fetch`)
* Network access to the target environment

---

## Install

**Drop-in script**

```bash
curl -O https://raw.githubusercontent.com/<your-user>/<your-repo>/main/auto-mapper-scanner.js
node auto-mapper-scanner.js --help
```

**Repository**

```bash
git clone https://github.com/<your-user>/<your-repo>.git
cd <your-repo>
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

Authenticated area with higher breadth:

```bash
node auto-mapper-scanner.js \
  --url "https://staging.example.com/app" \
  --max-pages 600 --max-depth 5 \
  --concurrency 12 --scan-concurrency 12 \
  --header "Cookie: session=XYZ"
```

JSON report for CI:

```bash
node auto-mapper-scanner.js --url "https://staging.example.com" --json > report.json
```

---

## Usage / CLI

```bash
node auto-mapper-scanner.js --url "https://target/"
  [--max-pages 200] [--max-depth 3]
  [--concurrency 5] [--scan-concurrency 5]
  [--timeout 15000] [--sleep 4]
  [--max-body-kb 512]
  [--verbosity silent|minimal|normal|debug|trace | --verbose]
  [--json]
  [--param-ignore "(csrf|token)"]
  [--header "Cookie: sid=abc"]  # repeatable
```

| Option               |   Type |  Default | Description                                                     |         |        |        |          |            |                             |
| -------------------- | -----: | -------: | --------------------------------------------------------------- | ------- | ------ | ------ | -------- | ---------- | --------------------------- |
| `--url`              | string |        — | Start URL; defines **same-origin** scope.                       |         |        |        |          |            |                             |
| `--max-pages`        |    int |    `200` | Crawl cap (pages fetched).                                      |         |        |        |          |            |                             |
| `--max-depth`        |    int |      `3` | Link depth cap.                                                 |         |        |        |          |            |                             |
| `--concurrency`      |    int |      `5` | Parallel **crawl** workers.                                     |         |        |        |          |            |                             |
| `--scan-concurrency` |    int |      `5` | Parallel **scan** workers.                                      |         |        |        |          |            |                             |
| `--timeout`          |     ms |  `15000` | Per-request timeout.                                            |         |        |        |          |            |                             |
| `--sleep`            |      s |      `4` | Baseline for time-based SQLi.                                   |         |        |        |          |            |                             |
| `--max-body-kb`      |     KB |    `512` | Cap captured response body size.                                |         |        |        |          |            |                             |
| `--verbosity`        |   enum | `normal` | \`silent                                                        | minimal | normal | debug  | trace\`. |            |                             |
| `--verbose`          |   flag |      off | Shortcut for `debug`.                                           |         |        |        |          |            |                             |
| `--json`             |   flag |      off | Emit JSON report to stdout.                                     |         |        |        |          |            |                             |
| `--param-ignore`     |  regex |  \`(csrf | xsrf                                                            | token   | auth   | passwd | password | pwd)\` (i) | Skip params matching regex. |
| `--header`           |     kv |     `{}` | Extra header; **repeatable** (e.g., `Cookie`, `Authorization`). |         |        |        |          |            |                             |

**Auth tip**

```bash
--header "Cookie: session=XYZ" --header "Authorization: Bearer <token>"
```

---

## Examples

Focus only on endpoints with redirect-like params and run deeper:

```bash
node auto-mapper-scanner.js \
  --url "https://example.com" \
  --max-pages 800 --max-depth 6 \
  --param-ignore "(csrf|xsrf|nonce|__RequestVerificationToken)"
```

Skip noisy body sizes on a heavy app:

```bash
node auto-mapper-scanner.js \
  --url "https://example.com" \
  --max-body-kb 256 --timeout 20000
```

Emit JSON and text in one go (tee):

```bash
node auto-mapper-scanner.js --url "https://example.com" --json | tee report.json
```

---

## Outputs

### Text (stdout)

```
=== SUMMARY ===
Analyzed endpoints: 87
- SQLi (boolean-based): 2
  GET https://staging.example.com/search [q] (ΔF=0.41 vs ΔT=0.08)
  POST https://staging.example.com/api/items [page]
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
      "type": "SQLi (boolean-based)",
      "endpoint": "https://staging.example.com/search",
      "method": "GET",
      "param": "q",
      "note": "ΔF=0.41 vs ΔT=0.08"
    }
  ]
}
```

---

## How It Works

1. **Crawl (same-origin)**
   BFS over HTML pages; extracts links and forms; lightly parses HTML via regex; collects query/form parameters.
   Heuristic **DOM XSS indicators** are flagged from static HTML (source + sink patterns).

2. **Endpoint catalog**
   Unique by `(method, url, encoding, param-names)` to avoid redundant scans.

3. **Baseline & Probing**
   For each endpoint, fetch a **baseline** (twice) to stabilize timing/content.
   For each parameter (unless ignored), run tests:

   * **SQLi**: error signatures; **boolean differential** (composite delta of length diff + 1−Jaccard); **union/order hints**; **time-based**.
   * **Reflected XSS**: random-token payloads across contexts; note CSP presence.
   * **Open Redirect**: common names & encoded variants (`//`, `%2f`).
   * **LFI / Traversal**: `/etc/passwd`, `win.ini`, encoded traversal, `php://filter`, plus include/require error leaks.

4. **Report**
   Streams a grouped text summary or structured JSON.

---

## Tuning

* **Breadth**: Increase `--max-pages` / `--max-depth`.
* **Speed**: Raise `--concurrency` / `--scan-concurrency` (mind rate-limits/WAFs).
* **Stability**: Adjust `--timeout` and `--max-body-kb` for slow/heavy endpoints.
* **Noise**: Strengthen `--param-ignore` to skip CSRF/nonces and login secrets.
* **Time-based SQLi**: Increase `--sleep` for noisy networks.

---

## Limitations

* **Heuristics only**: findings are **indicators** for triage, not proofs of exploitability.
* **No JS execution**: **DOM XSS** is static; dynamic sinks in runtime JS may be missed.
* **Same-origin** by design: cross-origin links are ignored.
* **Regex HTML parsing**: extremely fast, but complex dynamic forms can be missed.
* **Env-dependent deltas**: timing/content signals can vary (false +/− possible).

---

## Ethics & Legality

Run this tool **only** against targets you **own** or have **explicit permission** to test.
Respect organizational policies and applicable laws.

---

## CI / Automation

Minimal GitHub Actions workflow that uploads a JSON artifact:

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
        with:
          node-version: 18
      - name: Run scan
        run: node auto-mapper-scanner.js --url "${{ secrets.TARGET_URL }}" --json > report.json
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: mapper-report
          path: report.json
```

---

## Roadmap

* Optional **headless mode** (opt-in) to confirm DOM XSS.
* Smarter **form filling** and content-type aware strategies.
* Extended source/sink patterns & CSP parsing.
* **SARIF** export; **NDJSON** streaming; **SQLite** store.
* Adaptive rate-limit/backoff strategies.

---

## Contributing

Issues and PRs are welcome. Please include:

---
