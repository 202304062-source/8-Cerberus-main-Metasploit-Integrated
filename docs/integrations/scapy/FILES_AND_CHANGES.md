# Cerberus Scapy Integration - Files and Changes

## Change policy

This integration follows the Cerberus Add-Only Principle. No pre-existing project file was edited,
removed, renamed, or overwritten. All implementation, wrapper, test, configuration, and
integration-documentation files listed below are new files.

## New files

| Path | Purpose |
|---|---|
| `tools/integrations/scapy/__init__.py` | Declares the new integration package. |
| `tools/integrations/scapy/requirements.txt` | Declares the Scapy Python dependency. |
| `tools/integrations/scapy/bootstrap.py` | Installs Scapy into the active interpreter on first run when absent. |
| `tools/integrations/scapy/runner.py` | URL validation, IPv4 resolution, HTTP HEAD inspection, bounded Scapy TCP probes, and JSON reporting. |
| `tools/integrations/scapy/cli.py` | Interactive and argument-based command-line entry point for VS Code terminals. |
| `tools/integrations/scapy/README.md` | Setup, usage, scope, platform, and troubleshooting notes. |
| `tools/integrations/scapy/tests/__init__.py` | Test package marker. |
| `tools/integrations/scapy/tests/test_runner.py` | Offline unit tests with mocked network operations. |
| `tools/integrations/scapy/reports/.gitkeep` | Keeps the report directory in Git. |
| `tools/integrations/scapy/reports/.gitignore` | Keeps runtime reports out of Git. |
| `tools/wrappers/scapy_integration_wrapper.py` | New async wrapper for Cerberus agents/services. |
| `docs/integrations/scapy/FILES_AND_CHANGES.md` | Human-readable record of new files and unchanged files. |
| `docs/integrations/scapy/Cerberus_Scapy_Code.pdf` | PDF listing of the integration source code and requirements. |
| `docs/integrations/scapy/Cerberus_Scapy_Added_Files_and_Changes.pdf` | PDF change inventory and run instructions. |

## Existing files modified

**None.** Existing Nmap, SQLMap, OWASP ZAP, backend, frontend, requirements, wrappers, project
configuration, and README files are preserved as provided in the source archive.

## Runtime behavior

- The launcher prompts for a single HTTP(S) URL when `--url` is not supplied.
- It requires the exact authorization phrase `I HAVE AUTHORIZATION` before any target network activity.
- If Scapy is absent, the launcher installs `tools/integrations/scapy/requirements.txt` using the
  active Python interpreter.
- It performs one DNS resolution to one IPv4 address, one HTTP(S) HEAD request, and no more than
  five sequential TCP SYN probes.
- It writes a JSON report to a timestamped directory under `tools/integrations/scapy/reports/`.
- On Windows, Npcap is a separate OS-level prerequisite for packet I/O. The integration does not
  attempt to silently install a packet-capture driver.

## Run in Visual Studio Code

From the Cerberus repository root:

```powershell
python tools/integrations/scapy/cli.py
```

Enter the authorized URL and confirm the authorization prompt. Direct invocation is also supported:

```powershell
python tools/integrations/scapy/cli.py --url "https://your-authorized-domain.example/"
```

## Offline test command

```powershell
python -m unittest discover -s tools/integrations/scapy/tests -v
```

The tests mock network operations and do not send packets to a target.

## Source references

- https://github.com/secdev/scapy
- https://scapy.readthedocs.io/en/latest/installation.html
- https://scapy.readthedocs.io/en/latest/usage.html
- https://github.com/secdev/scapy/blob/master/LICENSE
