# OWASP ZAP Integration for Cerberus

This integration connects Cerberus to the **official OWASP ZAP Docker image**.
It is intentionally configured for the ZAP **Baseline Scan** only. The baseline
scan spiders the supplied HTTP(S) target for a limited time and waits for ZAP's
passive rules to finish. It does not run an active attack scan.

## Requirements

- Python 3.11 or later (uses only the Python standard library).
- Docker Desktop on Windows/macOS or Docker Engine on Linux.
- A running Docker daemon and internet access when refreshing the official image. Use `--no-pull` offline when the image is already cached locally.
- Permission to test the target website.

ZAP itself is not copied into this repository. When the launcher runs, it
refreshes the official image `ghcr.io/zaproxy/zaproxy:stable` using Docker.
The image is cached by Docker and reused by later runs. This keeps the GitHub
repository small and avoids a separate manual ZAP installation.

## Run from the Cerberus repository root

### Interactive mode

```powershell
python tools/integrations/owasp_zap/cli.py
```

Enter the authorized target URL when prompted, then type `YES` at the
authorization prompt.

### One-line mode

```powershell
python tools/integrations/owasp_zap/cli.py --target https://example.com --authorized
```

Optional spider duration (1-10 minutes):

```powershell
python tools/integrations/owasp_zap/cli.py --target https://example.com --authorized --minutes 2
```

Use `--no-pull` only when the official image is already cached locally:

```powershell
python tools/integrations/owasp_zap/cli.py --target https://example.com --authorized --no-pull
```

The command prints Docker/ZAP output directly in the VS Code integrated
terminal. No VS Code extension or project-wide dependency change is required.

## Reports

Each run creates timestamped reports under:

`tools/integrations/owasp_zap/reports/`

- HTML: convenient human-readable report.
- JSON: machine-readable findings for future Cerberus ingestion.
- XML: structured report for compatible tools.

Generated reports are ignored by the nested `.gitignore` and are not committed
to Git accidentally.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed without WARN/FAIL alerts. |
| `1` | Scan completed and ZAP reported at least one FAIL alert. |
| `2` | Scan completed with WARN alerts (this is not a scanner startup failure). |
| `3` | Invalid input, Docker/ZAP execution error, or scan timeout. |
| `4` | Authorization confirmation was declined or unavailable. |

By default, ZAP baseline alerts are reported as warnings. Do not treat a
warning as proof that a vulnerability is exploitable.

## Cerberus Python wrapper

```python
import asyncio
from tools.wrappers.owasp_zap_wrapper import OWASPZAPWrapper

async def main():
    zap = OWASPZAPWrapper()
    result = await zap.baseline_scan(
        "https://example.com",
        authorized=True,
        minutes=1,
    )
    print(result)

asyncio.run(main())
```

The `authorized=True` value is an explicit caller assertion. Applications
integrating this wrapper must obtain and store engagement authorization
through Cerberus' Scope of Engagement / Rules of Engagement workflow before
calling it.

## Tests

From the repository root:

```powershell
python -m unittest discover -s tools/integrations/owasp_zap/tests -v
```

Tests do not contact a target and do not require Docker.

## Important limitations

- This is a passive baseline integration, not a full active penetration test.
- It does not attempt exploitation, brute force, credential guessing, or
  destructive payloads.
- HTTP(S) URL syntax is validated locally; authorization and target scope must
  still be verified by the operator and Cerberus engagement workflow.
- The stable Docker tag is updated by the ZAP project. Running the launcher
  refreshes that tag; use change-control policy if your environment requires
  image digest pinning.
- The ZAP Docker image and ZAP application are maintained by the OWASP ZAP
  project. Refer to the upstream license and documentation before redistribution
  or enterprise deployment.

## Upstream references

- ZAP source: https://github.com/zaproxy/zaproxy
- ZAP Docker user guide: https://www.zaproxy.org/docs/docker/about/
- ZAP baseline scan: https://www.zaproxy.org/docs/docker/baseline-scan/
