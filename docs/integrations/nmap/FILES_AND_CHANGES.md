# Cerberus Nmap Integration - Added Files and Verification

## Integration goal

Add a self-contained Nmap integration to the existing Cerberus repository. The
integration is invoked from the VS Code terminal, accepts an IP/domain/CIDR,
requests authorization, offers official-source installation when Nmap is absent,
streams output to the terminal, and writes structured reports.

## Add-only change policy

The input archive was `Cerberus-main-OWASP-ZAP-Integrated(2).zip`. The implementation
was extracted from that archive and changed by adding files only. No existing file
was edited, deleted, renamed, or replaced. In particular, these existing files remain
untouched:

- `tools/wrappers/nmap_wrapper.py` (legacy wrapper)
- `tools/wrappers/owasp_zap_wrapper.py`
- `tools/integrations/owasp_zap/**`
- prior ZAP documentation and PDFs
- root `.gitignore` and all application/backend/frontend files

A SHA-256 comparison was performed for every file present in the original archive.
All original-file hashes matched after integration; new files are listed below.

## New files

| Path | Purpose |
|---|---|
| `tools/integrations/nmap/__init__.py` | Public integration exports |
| `tools/integrations/nmap/runner.py` | Target validation, allow-listed command construction, execution, reports |
| `tools/integrations/nmap/installer.py` | Interactive bootstrap via official Nmap download or OS package manager |
| `tools/integrations/nmap/cli.py` | VS Code / PowerShell terminal entry point |
| `tools/integrations/nmap/README.md` | Install, run, profiles, reports, limitations |
| `tools/integrations/nmap/tests/__init__.py` | Test package marker |
| `tools/integrations/nmap/tests/test_runner.py` | Offline unit tests |
| `tools/integrations/nmap/reports/.gitignore` | Ignore generated scan artifacts |
| `tools/integrations/nmap/reports/.gitkeep` | Preserve empty reports directory |
| `tools/wrappers/nmap_integration_wrapper.py` | Async API wrapper for Cerberus agents |
| `docs/integrations/nmap/FILES_AND_CHANGES.md` | This change manifest |
| `docs/integrations/nmap/Cerberus_Nmap_Code.pdf` | Full source code listing |
| `docs/integrations/nmap/Cerberus_Nmap_Added_Files_and_Changes.pdf` | Change and verification report |

## Terminal usage

Interactive:

```powershell
python tools/integrations/nmap/cli.py
```

Direct target (still prompts for authorization):

```powershell
python tools/integrations/nmap/cli.py --target 192.0.2.10
```

Authorized engagement automation:

```powershell
python tools/integrations/nmap/cli.py --target 192.0.2.0/24 --profile discovery --authorized
```

Profiles: `discovery`, `quick`, and `standard`. CIDR target size defaults to a
maximum of 256 addresses. The hard configurable ceiling is 4096. Results are
written under `tools/integrations/nmap/reports/<timestamp>_<target>_<id>/`.

## Dependency/bootstrap model

No Nmap executable or binary installer is bundled. On first run, the CLI checks
for Nmap. If absent, it offers to fetch the latest official Windows setup program
from `nmap.org/download.html` and opens it interactively; on macOS/Linux it offers
Homebrew or the platform package manager. This avoids a separate manual Nmap
installation step for normal users while respecting the Nmap distribution license
and the OS-level Npcap/administrator permissions that may be needed.

## Safety controls

- Requires `authorized=True` in the programmatic runner or an exact `YES` response
  in interactive CLI mode (unless `--authorized` is supplied).
- Validates one host/domain/CIDR target; rejects URL schemes, shell metacharacters,
  Nmap options, comma-separated targets, and arbitrary target expressions.
- Enforces a CIDR target-size limit.
- Uses `subprocess.Popen([...], shell=False)`.
- Exposes only discovery, quick TCP connect, and standard TCP connect plus light
  service detection profiles; no script/vulnerability, brute force, spoofing, or
  evasion profiles are exposed.
- Uses a configurable process timeout and creates timestamped outputs.

## Tests executed

Command:

```powershell
python -m unittest discover -s tools/integrations/nmap/tests -v
```

The tests are offline and mock the Nmap process. They check target validation,
CIDR bounds, profile flags, authorization enforcement, shell-free invocation, and
summary-file creation. A live scan was deliberately not run during packaging.

## Upstream references

- Nmap GitHub source mirror: https://github.com/nmap/nmap
- Official download page: https://nmap.org/download.html
- Installation guide: https://nmap.org/book/install.html
- Windows installation: https://nmap.org/book/inst-windows.html
- Nmap command reference: https://nmap.org/book/man.html
