# waf-fu

AWS WAF v2 log browser and replayer with an interactive TUI. Pulls logs
from CloudWatch, S3, and the WAF sampling API (with SQLite caching),
displays them in a split-pane terminal UI with auth detection and
YAML-based filtering, and replays requests through Firefox, Chrome, or
curl with full header/cookie/body fidelity. Supports batch export to
curl, JSON, and HAR.

## Install

### From PyPI

```
uv pip install waf-fu

pipx install waf-fu
```

### From git

```
uv pip install git+https://gitrdun.trustedsec.net/cloud/aws/waf-fu.git

pipx install git+https://gitrdun.trustedsec.net/cloud/aws/waf-fu.git
```

### From a local clone

```
git clone https://gitrdun.trustedsec.net/cloud/aws/waf-fu.git
cd waf-fu

uv pip install .

pipx install .
```

The included `uv.toml` configures `uv pip` to install into the system
Python rather than creating a virtualenv. pipx and `uv tool install`
always use their own isolated environments.

## Requirements

**Python** >= 3.12

**AWS credentials** configured via profile, environment variables, or
instance role. See [IAM Permissions](#iam-permissions) for per-source
requirements.

### Python packages

| Package    | Min version | Required for               |
|------------|-------------|----------------------------|
| boto3      | any         | AWS log fetching           |
| selenium   | 4.26        | Chrome and Firefox replay  |
| trio       | any         | Chrome CDP replay internals|

`boto3` and `selenium` are declared in `pyproject.toml` and installed
automatically. `trio` is a transitive dependency of the Chrome backend.

### Browser replay backends

Browser replay is optional. Curl replay works with no extra dependencies.

**Firefox** (recommended for header fidelity):

| Component   | Min version | Install                                                          |
|-------------|-------------|------------------------------------------------------------------|
| Firefox     | 120         | `sudo dnf install firefox` / `sudo apt install firefox`         |
| geckodriver | 0.35.0      | `sudo dnf install geckodriver` / `sudo apt install firefox-geckodriver` or [github.com/mozilla/geckodriver/releases](https://github.com/mozilla/geckodriver/releases) (>= 0.35.0) |
| selenium    | 4.26        | `uv pip install 'selenium>=4.26'`                                |

Firefox replay uses WebDriver BiDi network interception to inject the
original request's method, headers, cookies, and body. BiDi network
support requires geckodriver >= 0.35 and selenium >= 4.26. Older
versions fall back to an XHR-based approach that cannot inject custom
headers.

**Chrome / Chromium:**

| Component    | Min version | Install                                                              |
|--------------|-------------|----------------------------------------------------------------------|
| Chrome       | 118         | `sudo dnf install google-chrome-stable` / `sudo apt install google-chrome-stable` or Chromium |
| chromedriver | 118         | `sudo dnf install chromedriver` / `sudo apt install chromium-driver` or [googlechromelabs.github.io/chrome-for-testing](https://googlechromelabs.github.io/chrome-for-testing/) |
| selenium     | 4.26        | `uv pip install 'selenium>=4.26'`                                    |

Chrome replay uses CDP (Chrome DevTools Protocol) Fetch domain to
intercept and modify requests. Method, headers, body, and cookies are
all injected via CDP.

Driver paths can be overridden with `--chromedriver PATH` and
`--geckodriver PATH` if auto-detection does not find the correct binary.

## Quick start

```
# Interactive TUI -- browse and replay
waf-fu --log-group "aws-waf-logs-my-acl"

# No log group -- interactively select from discovered groups
waf-fu --profile myprofile --region us-east-1

# S3 WAF logs instead of CloudWatch
waf-fu --s3-bucket aws-waf-logs-my-bucket

# Discover and fetch every log source across all regions
waf-fu --inventory

# Pre-filter before the TUI opens
waf-fu --start 4h --action BLOCK

# Offline mode -- cached records only, no AWS calls
waf-fu --db-only

# Replay through a proxy (Burp, mitmproxy, etc.)
waf-fu --log-group "aws-waf-logs-my-acl" --proxy 127.0.0.1:8080

# Non-interactive batch export
waf-fu --log-group "aws-waf-logs-my-acl" --mode batch-curl -o replay.sh

# Export cached records to JSON
waf-fu --export logs.json

# Debug mode -- log replay details to file (client data redacted)
waf-fu --log-group "aws-waf-logs-my-acl" --debug
```

## Log sources

waf-fu pulls WAF logs from three sources and merges them per-request:

| Source     | CLI flag                        | Data                                                |
|------------|---------------------------------|-----------------------------------------------------|
| CloudWatch | `--log-group` (default)         | Full WAF log JSON (headers, URI, query, action)     |
| S3         | `--s3-bucket`                   | Same as CloudWatch, from S3 delivery                |
| WAF API    | `--log-location waf`            | Sampled requests with unredacted fields             |

Use `--log-location cwl|s3|waf` to restrict to a single source, or
`--inventory` to discover and fetch all sources across all regions
automatically.

Records from different sources are merged by correlation key so you see
a single unified view per request, with the richest data from each.

## IAM Permissions

Each source needs its own IAM permissions, scoped to the CLI flags that
trigger it.

### CloudWatch Logs

Required for: default operation, `--log-location cwl`

- `logs:FilterLogEvents` -- fetch log records from CloudWatch
- `logs:DescribeLogGroups` -- discover log groups matching `aws-waf-logs-*`

### S3

Required for: `--s3-bucket`, `--log-location s3`, `--inventory`

- `s3:ListAllMyBuckets` -- discover WAF log buckets by name prefix
- `s3:ListBucket` -- list log objects in a WAF log bucket
- `s3:GetObject` -- download gzip-compressed log files

### WAFv2

Required for: `--log-location waf`, `--inventory`, auto-enrichment

- `wafv2:ListWebACLs` -- discover web ACLs
- `wafv2:GetWebACL` -- enumerate rules for sampled request queries
- `wafv2:GetLoggingConfiguration` -- discover which log destinations (CWL, S3) an ACL uses
- `wafv2:GetSampledRequests` -- retrieve unredacted request samples (bypasses RedactedFields)

Minimum viable: only CloudWatch Logs permissions are required. S3 and
WAFv2 permissions are optional and enable additional data sources. The
tool falls back gracefully when permissions are missing.
