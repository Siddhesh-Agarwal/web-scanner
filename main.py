#!/usr/bin/env python3
"""
scanner.py — Web vulnerability scanner using Claude API for analysis.

Usage:
    python3 scanner.py <URL> [--output/-o report.md] [--disable-ai]

Checks:
    - Exposed credentials in client-side JS (inline + external)
    - Unauthenticated/sensitive endpoints
    - Open/listable S3 buckets

Requires:
    pip install httpx beautifulsoup4 anthropic typer
    ANTHROPIC_API_KEY env var set
"""

import json
import re
import sys
from datetime import datetime
from urllib.parse import urljoin, urlparse
from zoneinfo import ZoneInfo

import anthropic
import httpx
import typer
from bs4 import BeautifulSoup

app = typer.Typer(rich_markup_mode="rich")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

MODEL = "claude-opus-4-5"
MAX_JS_CHARS = 40_000  # per-file cap before sending to Claude
MAX_SNIPPET = 500  # chars of response body to keep for probes

SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/.aws/credentials",
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/secrets.json",
    "/api/users",
    "/api/admin",
    "/api/v1/secrets",
    "/api/v1/users",
    "/api/v1/admin",
    "/admin",
    "/phpinfo.php",
    "/wp-config.php",
    "/graphql",
    "/graphql?query={__schema{types{name}}}",
    "/swagger.json",
    "/openapi.json",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/.well-known/security.txt",
    "/server-status",
    "/debug",
]

S3_PATTERN = re.compile(
    r"https?://([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])"
    r"(?:\.s3[\.\-]([a-z0-9\-]+)?\.?amazonaws\.com|\.s3\.amazonaws\.com)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Phase 1: Collectors
# ---------------------------------------------------------------------------


def fetch_page(url: str) -> tuple[str, str]:
    """Return (html_text, final_url). Raises on network failure."""
    r = httpx.get(
        url,
        follow_redirects=True,
        timeout=15,
        headers={"User-Agent": "Mozilla/5.0 (security-scanner/1.0)"},
    )
    r.raise_for_status()
    return r.text, str(r.url)


def collect_js_files(base_url: str, html: str) -> list[dict]:
    """Extract inline and external JS from a page."""
    soup = BeautifulSoup(html, "html.parser")
    results = []

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if isinstance(src, str):
            js_url = urljoin(base_url, src)
            try:
                r = httpx.get(
                    js_url,
                    timeout=10,
                    follow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if r.status_code == 200:
                    results.append({"url": js_url, "content": r.text[:MAX_JS_CHARS]})
            except Exception as exc:
                results.append({"url": js_url, "content": "", "error": str(exc)})
        elif tag.string and tag.string.strip():
            results.append(
                {"url": "inline", "content": tag.string.strip()[:MAX_JS_CHARS]}
            )

    return results


def probe_endpoints(base_url: str) -> list[dict]:
    """Fire requests at known sensitive paths."""
    origin = "{u.scheme}://{u.netloc}".format(u=urlparse(base_url))
    results = []

    for path in SENSITIVE_PATHS:
        target = origin + path
        try:
            r = httpx.get(
                target,
                timeout=5,
                follow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            results.append(
                {
                    "path": path,
                    "url": target,
                    "status": r.status_code,
                    "content_type": r.headers.get("content-type", ""),
                    "snippet": r.text[:MAX_SNIPPET],
                    "headers": {
                        k: v
                        for k, v in r.headers.items()
                        if k.lower()
                        in {
                            "server",
                            "x-powered-by",
                            "content-type",
                            "access-control-allow-origin",
                            "www-authenticate",
                        }
                    },
                }
            )
        except Exception as exc:
            results.append({"path": path, "url": target, "error": str(exc)})

    return results


# ---------------------------------------------------------------------------
# Phase 2: S3 bucket checks (deterministic, no Claude needed)
# ---------------------------------------------------------------------------


def extract_s3_buckets(html: str, js_files: list[dict]) -> list[str]:
    combined = html + "\n".join(f["content"] for f in js_files)
    matches = S3_PATTERN.findall(combined)
    return list({m[0] for m in matches})  # dedupe by bucket name


def check_bucket(bucket_name: str) -> dict:
    url = f"https://{bucket_name}.s3.amazonaws.com/"
    try:
        r = httpx.get(url, timeout=10)
        listable = "<ListBucketResult" in r.text
        return {
            "bucket": bucket_name,
            "url": url,
            "status": r.status_code,
            "listable": listable,
            "snippet": r.text[:300],
        }
    except Exception as exc:
        return {"bucket": bucket_name, "url": url, "error": str(exc)}


# ---------------------------------------------------------------------------
# Phase 3: Claude analysis
# ---------------------------------------------------------------------------

CREDENTIAL_PROMPT = """\
You are a security auditor. Analyze the JavaScript content below for exposed credentials.

Look for:
- API keys (patterns: sk-, pk-, AIza, AKIA, Bearer tokens hardcoded)
- Database connection strings
- AWS/GCP/Azure credentials
- Stripe, Twilio, SendGrid, Mailgun keys
- Private keys or JWT secrets
- Auth tokens assigned to JS variables

Return ONLY a JSON object, no markdown, no preamble:
{{
  "findings": [
    {{
      "severity": "critical|high|medium|low",
      "type": "credential_type",
      "evidence": "exact_snippet_max_100_chars",
      "context": "surrounding_code_for_locating_it",
      "recommendation": "one_line_fix"
    }}
  ]
}}

If no findings, return {{"findings": []}}.

JS SOURCE ({url}):
{content}
"""

ENDPOINT_PROMPT = """\
You are a security auditor. Analyze these HTTP probe results for access control issues.

Assess each endpoint for:
- Sensitive data exposed on 200 responses (/.env, /config.json, credentials, stack traces)
- Admin/internal APIs accessible without authentication
- Verbose error messages leaking internals
- CORS misconfiguration (access-control-allow-origin: *)
- Missing security headers
- GraphQL introspection enabled

Probe results (JSON):
{results}

Return ONLY a JSON object, no markdown, no preamble:
{{
  "findings": [
    {{
      "severity": "critical|high|medium|low",
      "path": "/path",
      "issue": "one_sentence_description",
      "evidence": "status_code_and_or_snippet",
      "recommendation": "one_line_fix"
    }}
  ]
}}

If no findings, return {{"findings": []}}.
"""


def _call_claude(client: anthropic.Anthropic, prompt: str) -> list[dict]:
    msg = client.messages.create(
        model=MODEL,
        max_tokens=2048,
        messages=[{"role": "user", "content": prompt}],
    )
    text = msg.content[0].text.strip()
    # Strip accidental markdown fences
    text = re.sub(r"^```[a-z]*\n?", "", text)
    text = re.sub(r"\n?```$", "", text)
    try:
        return json.loads(text).get("findings", [])
    except json.JSONDecodeError:
        print("[warn] Claude returned non-JSON; skipping block", file=sys.stderr)
        return []


def analyze_js(client: anthropic.Anthropic, js_files: list[dict]) -> list[dict]:
    all_findings = []
    for f in js_files:
        if not f.get("content") or len(f["content"]) < 50:
            continue
        findings = _call_claude(
            client,
            CREDENTIAL_PROMPT.format(url=f["url"], content=f["content"]),
        )
        for finding in findings:
            finding["source_url"] = f["url"]
        all_findings.extend(findings)
    return all_findings


def analyze_endpoints(client: anthropic.Anthropic, probes: list[dict]) -> list[dict]:
    # Filter to only probes with interesting status codes to reduce noise+tokens
    interesting = [
        p
        for p in probes
        if p.get("status") in {200, 201, 206, 301, 302, 401, 403, 500, 503}
        or "error" not in p
    ]
    if not interesting:
        return []
    return _call_claude(
        client,
        ENDPOINT_PROMPT.format(results=json.dumps(interesting, indent=2)),
    )


# ---------------------------------------------------------------------------
# Phase 4: Report generation
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def build_report(
    target_url: str,
    js_findings: list[dict],
    endpoint_findings: list[dict],
    s3_results: list[dict],
) -> str:
    now = datetime.now(tz=ZoneInfo("")).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Security Scan Report",
        "",
        f"**Target:** {target_url}  ",
        f"**Scanned:** {now}  ",
        "",
        "---",
        "",
    ]

    # Summary counts
    all_findings = js_findings + endpoint_findings
    by_severity: dict[str, int] = {}
    for f in all_findings:
        s = f.get("severity", "low")
        by_severity[s] = by_severity.get(s, 0) + 1

    s3_open = [r for r in s3_results if r.get("listable")]

    lines += [
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["critical", "high", "medium", "low"]:
        lines.append(f"| {sev.capitalize()} | {by_severity.get(sev, 0)} |")
    lines += [
        f"| Open S3 buckets | {len(s3_open)} |",
        "",
        "---",
        "",
    ]

    # JS credential findings
    lines += ["## Exposed Credentials in JavaScript", ""]
    sorted_js = sorted(
        js_findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "low"), 3)
    )
    if sorted_js:
        for f in sorted_js:
            lines += [
                f"### [{f.get('severity', '?').upper()}] {f.get('type', 'Unknown')}",
                "",
                f"- **Source:** `{f.get('source_url', '?')}`",
                f"- **Evidence:** `{f.get('evidence', '')}`",
                f"- **Context:** {f.get('context', '')}",
                f"- **Fix:** {f.get('recommendation', '')}",
                "",
            ]
    else:
        lines += ["No credential exposures found.", ""]

    # Endpoint findings
    lines += ["---", "", "## Unauthenticated / Sensitive Endpoints", ""]
    sorted_ep = sorted(
        endpoint_findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "low"), 3)
    )
    if sorted_ep:
        for f in sorted_ep:
            lines += [
                f"### [{f.get('severity', '?').upper()}] {f.get('path', '?')}",
                "",
                f"- **Issue:** {f.get('issue', '')}",
                f"- **Evidence:** {f.get('evidence', '')}",
                f"- **Fix:** {f.get('recommendation', '')}",
                "",
            ]
    else:
        lines += ["No unauthenticated endpoint issues found.", ""]

    # S3 findings
    lines += ["---", "", "## S3 Bucket Exposure", ""]
    if s3_results:
        for r in s3_results:
            status = (
                "🔴 OPEN (listable)"
                if r.get("listable")
                else f"status={r.get('status', '?')}"
            )
            lines += [
                f"- **{r['bucket']}** — {status}",
                f"  - URL: {r.get('url', '')}",
            ]
            if r.get("error"):
                lines.append(f"  - Error: {r['error']}")
        lines.append("")
    else:
        lines += ["No S3 bucket references found.", ""]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def scan(url: str, output_path: str | None = None, disable_ai: bool = False) -> str:

    typer.echo(f"[1/4] Fetching [cyan]{url}[/cyan] ...", file=sys.stderr)
    html, final_url = fetch_page(url)

    typer.echo("[2/4] Collecting JS files and probing endpoints ...", file=sys.stderr)
    js_files = collect_js_files(final_url, html)
    probes = probe_endpoints(final_url)
    buckets = extract_s3_buckets(html, js_files)
    typer.echo(
        f"      [dim]{len(js_files)} JS files, {len(probes)} probes, {len(buckets)} S3 refs[/dim]",
        file=sys.stderr,
    )

    if disable_ai:
        typer.echo("[3/4] [dim]AI analysis disabled, skipping ...[/dim]", file=sys.stderr)
        js_findings = []
        endpoint_findings = []
        s3_results = [check_bucket(b) for b in buckets]
    else:
        client = anthropic.Anthropic()
        typer.echo(f"[3/4] Analyzing with [bold yellow]Claude ({MODEL})[/bold yellow] ...", file=sys.stderr)
        js_findings = analyze_js(client, js_files)
        endpoint_findings = analyze_endpoints(client, probes)
        s3_results = [check_bucket(b) for b in buckets]

    typer.echo("[4/4] Building report ...", file=sys.stderr)
    report = build_report(final_url, js_findings, endpoint_findings, s3_results)

    if output_path:
        with open(output_path, "w") as fh:
            fh.write(report)
        typer.secho(f"✓ Report written to {output_path}", fg=typer.colors.GREEN, file=sys.stderr)
    else:
        typer.echo(report)

    return report


@app.command()
def main(
    url: str,
    output: str | None = typer.Option(None, "--output", "-o", help="Write report to this file (default: stdout)"),
    disable_ai: bool = typer.Option(False, "--disable-ai", help="Skip AI analysis (JS credentials and endpoint audit)"),
) -> None:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    scan(url, output, disable_ai)


if __name__ == "__main__":
    app()
