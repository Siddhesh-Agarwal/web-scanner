# Web Vulnerability Scanner

## What this project does

Scans a target URL for:

1. Exposed credentials in client-side JavaScript (inline + external scripts)
2. Unauthenticated or sensitive endpoints (/.env, /admin, /graphql, etc.)
3. Open/listable S3 buckets referenced in page source

## Single entrypoint

```
uv run main.py <URL> [--output/-o report.md] [--disable-ai]
```

Example:

```
uv run main.py https://example.com --output report.md
uv run main.py https://example.com --disable-ai
```

## How it works (pipeline)

1. **Fetch** — GET the URL, follow redirects, capture final URL + HTML
2. **Collect** — Extract all `<script src>` + inline JS; fire requests at SENSITIVE_PATHS list
3. **S3 extract** — Regex HTML + JS for `*.s3.amazonaws.com` references, then probe each bucket
4. **Analyze (Claude)** — Send JS content to Claude for credential detection; send endpoint probe results to Claude for access control analysis (skipped if `--disable-ai` is set)
5. **Report** — Aggregate findings sorted by severity → markdown

## Environment

```sh
ANTHROPIC_API_KEY=sk-ant-...   # required
```

## Dependencies

```sh
uv sync
```

Required packages: `httpx`, `beautifulsoup4`, `anthropic`, `typer`, `rich`

## Severity definitions

| Level    | Meaning                                             |
| -------- | --------------------------------------------------- |
| critical | Credentials or PII directly readable                |
| high     | Unauthenticated access to sensitive admin/data APIs |
| medium   | Information disclosure, CORS misconfiguration       |
| low      | Missing headers, best-practice violations           |

## What Claude should NOT do

- Do not run this against targets without explicit authorization
- Do not modify SENSITIVE_PATHS to include destructive or write-method probes
- Do not store scan output containing credentials in version control

## Extending the scanner

- Add new paths to `SENSITIVE_PATHS` in scanner.py
- Adjust `MAX_JS_CHARS` if you want deeper analysis (raises token cost)
- Swap `MODEL` constant to `claude-haiku-4-5` for cheaper/faster runs with lower accuracy
