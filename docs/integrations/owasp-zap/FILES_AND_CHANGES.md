# Cerberus - OWASP ZAP Integration: Added Files and Change Manifest

## Integration approach

OWASP ZAP is connected through its official Docker image:
`ghcr.io/zaproxy/zaproxy:stable`.

The Cerberus repository receives only the adapter, command-line launcher,
tests, and documentation. The upstream scanner binaries are not copied into
the repository. A clean clone can run the integration after Python and Docker
are installed; Docker pulls the official image automatically when the launcher
runs.

## Existing project files modified

**None.**

The original project files were left unchanged. This is an add-only integration.
No existing backend, frontend, configuration, dependency, wrapper, or root
documentation file was edited or deleted.

## New files

| Path | Purpose |
|---|---|
| `tools/integrations/owasp_zap/__init__.py` | Exposes the integration module API. |
| `tools/integrations/owasp_zap/runner.py` | Validates target URLs, pulls the official ZAP image, runs baseline scan, and reports output paths/status. |
| `tools/integrations/owasp_zap/cli.py` | Interactive and argument-based terminal launcher for VS Code. |
| `tools/integrations/owasp_zap/README.md` | Requirements, usage, reports, exit codes, limitations, and upstream references. |
| `tools/integrations/owasp_zap/reports/.gitkeep` | Keeps the reports directory in Git. |
| `tools/integrations/owasp_zap/reports/.gitignore` | Prevents generated scan reports from being committed. |
| `tools/integrations/owasp_zap/tests/__init__.py` | Test package marker. |
| `tools/integrations/owasp_zap/tests/test_runner.py` | Offline unit tests for URL checks, command construction, and authorization guard. |
| `tools/wrappers/owasp_zap_wrapper.py` | Async Cerberus wrapper for agent/service integration. |
| `docs/integrations/owasp-zap/FILES_AND_CHANGES.md` | This file-change manifest. |
| `docs/integrations/owasp-zap/Cerberus_OWASP_ZAP_Code.pdf` | Complete reference containing every new Python source file. |
| `docs/integrations/owasp-zap/Cerberus_OWASP_ZAP_Added_Files_and_Changes.pdf` | Arabic report listing added files, run instructions, verification, and limitations. |

## Run command

Interactive:

```powershell
python tools/integrations/owasp_zap/cli.py
```

Non-interactive:

```powershell
python tools/integrations/owasp_zap/cli.py --target https://example.com --authorized
```

## Execution flow

1. Validate that the target is an HTTP or HTTPS URL.
2. Require an operator authorization confirmation (interactive `YES` or `--authorized`).
3. Verify Docker CLI availability.
4. Pull/refresh the official OWASP ZAP stable Docker image.
5. Run `zap-baseline.py` with the selected target and time-boxed spider.
6. Save HTML, JSON, and XML reports under `tools/integrations/owasp_zap/reports/`.
7. Print the scan state and report locations into the current terminal.

## Safety and scope

This integration runs the ZAP baseline scan only. It does not use the full scan
script or active scan. The baseline uses a time-limited spider and passive
scanning. Operator authorization and the Cerberus engagement scope remain
mandatory; syntactic URL validation does not prove ownership.

## Verification

The automated tests are offline and do not attack or contact a target:

```powershell
python -m unittest discover -s tools/integrations/owasp_zap/tests -v
```

The code package uses only the Python standard library. Docker and its daemon
are external runtime prerequisites already consistent with the root project's
Docker-based development prerequisites.
