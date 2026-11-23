# Cerberus Metasploit Integration - Added Files and Changes

## Summary

Added a separate Metasploit integration under `tools/integrations/metasploit/` and an async wrapper under `tools/wrappers/`. Two English PDF documents are stored in this folder. No pre-existing project file was edited, replaced, or deleted.

## New files

```text
tools/integrations/metasploit/
  __init__.py
  bootstrap.py
  cli.py
  runner.py
  README.md
  .runtime/.gitignore
  reports/.gitignore
  reports/.gitkeep
  tests/__init__.py
  tests/test_bootstrap.py
  tests/test_runner.py

tools/wrappers/metasploit_integration_wrapper.py

docs/integrations/metasploit/
  FILES_AND_CHANGES.md
  Cerberus_Metasploit_Code_English.pdf
  Cerberus_Metasploit_Added_Files_and_Changes_English.pdf
```

## File responsibilities

- `runner.py`: validates one HTTP(S) URL, resolves one IPv4 address, builds a fixed Metasploit console command sequence, invokes the single allow-listed HTTP version module, and writes a JSON report.
- `cli.py`: prompts for the target URL and an exact authorization phrase, locates Metasploit, and displays output in the VS Code terminal.
- `bootstrap.py`: locates `msfconsole`; on Windows, optionally downloads the official Rapid7 MSI into `.runtime`, checks its Authenticode signature for a valid Rapid7 publisher, and starts the normal interactive installer.
- `tools/wrappers/metasploit_integration_wrapper.py`: exposes the same bounded check as an async Cerberus wrapper.
- `tests/`: offline unit tests with DNS and process execution mocked.
- `.runtime/.gitignore`: keeps the downloaded installer/runtime files out of Git.
- `reports/`: stores generated JSON reports and ignores run output.

## Fixed module boundary

The integration invokes only `auxiliary/scanner/http/http_version`. It does not expose arbitrary Metasploit modules, exploit modules, payloads, listeners, sessions, brute force, or post-exploitation actions. One hostname is resolved to one IPv4 address; one port and one virtual host are configured; the thread count is fixed to one.

## Setup and operation

From the repository root in Visual Studio Code:

```powershell
python tools/integrations/metasploit/cli.py
```

Enter an HTTP(S) URL and type `I HAVE AUTHORIZATION` when prompted. If Metasploit is missing on Windows, the CLI offers to fetch the official Rapid7 MSI into the project-local ignored `.runtime` directory, validate its Authenticode publisher, and launch the interactive installer. It is not a silent installation. Windows Administrator permission and acceptance of the Rapid7 license may be required. On Linux/macOS, install Metasploit through Rapid7's official instructions or use an existing `msfconsole` on PATH.

## Outputs

Each completed run writes `summary.json` under `tools/integrations/metasploit/reports/<timestamp>_<host>_<id>/`. The terminal displays Metasploit's console output and the JSON summary.

## Validation performed

- New Metasploit integration tests: 21 passed.
- Existing Nmap tests: 11 passed.
- Existing Scapy tests: 10 passed.
- Existing Bettercap tests: 15 passed.
- Existing SQLMap tests: 14 passed.
- Existing OWASP ZAP tests: 9 passed.
- Existing authentication-security-audit tests: 20 passed.
- Total targeted tests: 100 passed.
- Python compilation and CLI `--help` checks passed.
- Automated tests mocked external DNS and process calls; no live Metasploit installation or real target scan was performed.
- Original archive files were checked byte-for-byte; no original project file was modified.

## Dependency note

The Metasploit Framework executable is not vendored into the repository. The committed integration handles the Windows installer download after user consent, but the official system installer still runs interactively and must be completed by the user. This is required for the Rapid7-managed framework dependencies and system installation. See Rapid7's official installation guidance: https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/.
