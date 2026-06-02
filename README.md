# Web Security Scanner

A CLI tool that scans target URLs for exposed credentials in JavaScript, unauthenticated endpoints, and open S3 buckets.

## Features

- **Credential Detection** — Finds exposed API keys, tokens, and secrets in inline and external JavaScript
- **Endpoint Auditing** — Probes for sensitive paths like `/.env`, `/admin`, `/graphql`, `/swagger.json`
- **S3 Bucket Discovery** — Detects S3 bucket references in page source and checks if they are publicly listable
- **AI-Powered Analysis** — Uses Claude to intelligently analyze JavaScript and endpoint responses

## Requirements

- Python 3.14+
- Anthropic API key

## Installation

```sh
uv sync
```

## Usage

```sh
uv run main.py <URL> [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `--output`, `-o` | Write report to a file |
| `--disable-ai` | Skip AI analysis (JS credentials and endpoint audit) |

### Examples

```sh
# Basic scan
uv run main.py https://example.com

# Save report to file
uv run main.py https://example.com --output report.md

# Skip AI analysis (faster, no API costs)
uv run main.py https://example.com --disable-ai
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Your Anthropic API key for Claude analysis |

## How It Works

1. **Fetch** — Retrieves the target URL HTML, following redirects
2. **Collect** — Extracts all `<script>` tags (inline + external) and probes sensitive paths
3. **Analyze** — Sends JS content and endpoint results to Claude for security analysis (unless `--disable-ai`)
4. **S3 Check** — Extracts S3 bucket references and tests public listability
5. **Report** — Outputs findings sorted by severity

## Severity Levels

| Level | Description |
|-------|-------------|
| Critical | Credentials or PII directly readable |
| High | Unauthenticated access to sensitive APIs |
| Medium | Information disclosure, CORS issues |
| Low | Missing security headers |

## Security Notice

Only scan targets you have explicit authorization to test. Do not store scan reports containing credentials in version control.