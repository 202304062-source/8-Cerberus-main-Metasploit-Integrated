# Cerberus Nmap Integration

This is an additive Nmap integration for Cerberus. It does **not** alter or replace
`tools/wrappers/nmap_wrapper.py`, the ZAP integration, or any existing project code.
It provides a dedicated, interactive CLI and an async Python wrapper.

## First run: no separate manual Nmap download needed

The repository does not vendor Nmap binaries. On first run, the launcher checks
for `nmap`/`nmap.exe`. If missing, it offers to fetch Nmap from its official source:

- Windows: reads the current installer link from `https://nmap.org/download.html`,
  downloads the official self-installer, and opens its setup wizard. Accept Npcap
  installation if prompted. Npcap may require administrator approval.
- macOS: offers `brew install nmap` (Homebrew must already be available).
- Linux: offers the native package manager (`apt-get`, `dnf`, `yum`, or `pacman`),
  using `sudo` when required.

This means the tool is included in the Cerberus repository and bootstraps Nmap at
runtime; the Nmap executable itself is fetched from the platform's official source
rather than copied into GitHub. The first setup requires network access.

## Run inside VS Code terminal / PowerShell

From the **Cerberus repository root**:

```powershell
python tools/integrations/nmap/cli.py
```

Enter one target (IP address, DNS hostname, or CIDR), then type `YES` to confirm
you own it or have written permission to assess it. If Nmap is missing, approve
the integrated installer prompt.

Direct invocation:

```powershell
python tools/integrations/nmap/cli.py --target 192.0.2.10
python tools/integrations/nmap/cli.py --target example.com --profile quick
python tools/integrations/nmap/cli.py --target 192.0.2.0/24 --profile discovery
```

Add `--authorized` only when authorization has already been obtained through the
Cerberus Scope of Engagement / Rules of Engagement workflow:

```powershell
python tools/integrations/nmap/cli.py --target 192.0.2.10 --profile standard --authorized
```

Useful options:

- `--profile discovery`: host discovery only (`-sn`).
- `--profile quick`: TCP connect scan of Nmap's fast port set (`-sT -F`).
- `--profile standard` (default): TCP connect scan of the top 1000 ports with
  light service/version detection (`-sT -sV --version-light --top-ports 1000`).
- `--max-hosts 256`: CIDR size limit, configurable up to 4096.
- `--timeout 1800`: maximum scan duration in seconds.
- `--output-dir PATH`: custom report destination.
- `--nmap-path PATH`: explicitly select `nmap.exe`/`nmap`.
- `--no-install`: fail instead of offering the bootstrap when Nmap is missing.

The CLI prints Nmap output directly in the VS Code terminal. Nmap receives an
argument array (not a shell command); arbitrary Nmap options, scan scripts,
stealth/evasion modes, and arbitrary target lists are not accepted by this CLI.

## Reports

Each run creates an isolated, timestamped folder under:

`tools/integrations/nmap/reports/`

Nmap `-oA` output provides `.nmap` (normal), `.gnmap` (grepable), and `.xml`
(machine-readable) files. Cerberus also writes `summary.json` with the target,
profile, exit code, duration, and report paths. The report directory is ignored by
Git except for `.gitkeep`.

## Python integration

```python
import asyncio
from tools.wrappers.nmap_integration_wrapper import NmapIntegrationWrapper

async def main():
    scanner = NmapIntegrationWrapper()
    result = await scanner.scan(
        "192.0.2.10",
        authorized=True,  # obtain this from the active SoE/ROE, not a user guess
        profile="standard",
    )
    print(result)

asyncio.run(main())
```

Callers in Cerberus must derive `authorized=True` from the active engagement
authorization and enforce the Scope of Engagement before invoking this wrapper.
The wrapper does not itself prove ownership or authorization.

## Tests

From the project root:

```powershell
python -m unittest discover -s tools/integrations/nmap/tests -v
```

These tests do not run Nmap or contact a network target.

## Safety and limitations

- Use only against assets you own or are explicitly authorized to test.
- The default maximum CIDR size is 256 addresses (hard ceiling: 4096 through an
  explicit option). Prefer a specific host or narrow CIDR.
- Profiles are limited to host discovery, a quick TCP connect scan, and a standard
  TCP connect/service-detection scan. No NSE vulnerability category, exploit,
  brute-force, spoofing, or evasion mode is exposed.
- TCP connect/service probes can still be visible to network monitoring and may
  affect fragile services. Coordinate the window with the asset owner.
- Nmap output is evidence of network observations, not confirmation of exploitability.
- Windows Npcap may be necessary for certain packet-level features; this integration
  uses TCP connect scanning by default and does not request privileged SYN scanning.
- Nmap is distributed under its own custom license. Review upstream licensing and
  do not redistribute Nmap binaries inside the Cerberus ZIP.

## Upstream references

- Nmap source mirror: https://github.com/nmap/nmap
- Official downloads: https://nmap.org/download.html
- Official installation guide: https://nmap.org/book/install.html
- Windows installation: https://nmap.org/book/inst-windows.html
- Reference guide: https://nmap.org/book/man.html
