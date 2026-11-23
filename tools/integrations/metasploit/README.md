# Cerberus Metasploit Framework Integration

This is an additive Cerberus integration for the official [Rapid7 Metasploit Framework](https://github.com/rapid7/metasploit-framework). It adds a terminal launcher, a bounded runner, an optional interactive Windows installer bootstrap, tests, and an async Cerberus wrapper. Existing project files and tool integrations are left untouched.

## Safety boundary

Metasploit is a modular penetration-testing and exploit-development framework. This integration deliberately does **not** expose arbitrary module names, exploit modules, payloads, listeners, sessions, brute-force modules, post-exploitation modules, or free-form `msfconsole` commands.

The only module selected by this integration is:

```text
auxiliary/scanner/http/http_version
```

The official module documentation describes it as displaying the target system's version information. It accepts one `RHOSTS` address, one TCP `RPORT`, optional TLS, and a virtual-host value. Cerberus resolves a single IPv4 address from the URL and runs the module with one thread. This is a limited HTTP service identification check, not an exploit or a complete vulnerability assessment.

Run it only against a website or host that you own or are explicitly authorized to assess. The CLI requires the exact phrase `I HAVE AUTHORIZATION` before starting.

## Run from Visual Studio Code

Open the Cerberus repository root in VS Code, select **Terminal > New Terminal**, then run:

```powershell
python tools/integrations/metasploit/cli.py
```

Enter one authorized URL, for example:

```text
https://your-authorized-domain.example
```

The CLI asks you to type:

```text
I HAVE AUTHORIZATION
```

You can also pass the URL directly:

```powershell
python tools/integrations/metasploit/cli.py --url "https://your-authorized-domain.example"
```

Optional arguments:

- `--msfconsole-path "C:\\Metasploit-framework\\bin\\msfconsole.bat"`: use a specific installation.
- `--timeout 300`: set the execution timeout (30-600 seconds).
- `--no-install`: do not offer the official Windows installer when Metasploit is missing.

The `msfconsole` output and result summary are printed in the VS Code terminal. A JSON report is saved under `tools/integrations/metasploit/reports/`.

## First-run setup and GitHub cloning

The Cerberus integration source, tests, launcher, and wrapper are committed with the project. The full Metasploit Framework is **not copied or vendored into this repository**. It is a large Ruby-based framework with system dependencies and an installer-managed environment; cloning Cerberus alone does not provide a working `msfconsole` executable.

If `msfconsole` is missing on Windows, the CLI offers to download the current official Rapid7 MSI into the ignored project-local `.runtime` directory. It checks the MSI's Windows Authenticode signature for a valid Rapid7 publisher and launches the normal interactive installer. It does not install silently. The installation requires the user to accept the Rapid7 license and may require Windows Administrator permission. After setup, reopen the VS Code terminal and run the command again if `msfconsole` is not immediately found.

On Linux/macOS, install Metasploit through the official Rapid7 instructions or use a pre-installed `msfconsole` (for example, on Kali). The integration finds it on `PATH` or accepts an explicit path. No package manager or remote shell script is run automatically.

Official setup reference: https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/

## Reports

Every completed run creates a timestamped folder under:

```text
tools/integrations/metasploit/reports/
```

`summary.json` records the normalized target origin, resolved IPv4, port, TLS state, fixed module name, console path, exit code, bounded output, duration, and scope limitations. Reports are local runtime output and are ignored by Git.

## Cerberus wrapper

```python
import asyncio
from tools.wrappers.metasploit_integration_wrapper import MetasploitIntegrationWrapper

async def main():
    integration = MetasploitIntegrationWrapper()
    result = await integration.inspect_http_service(
        "https://your-authorized-domain.example",
        authorized=True,  # derive this from the approved Scope of Engagement / ROE
    )
    print(result)

asyncio.run(main())
```

The calling agent/service must enforce the approved SoE/ROE before invoking the wrapper. `authorized=True` is an assertion from the caller, not independent proof of permission. The wrapper does not offer arbitrary Metasploit console commands.

## Tests

From the project root:

```powershell
python -m unittest discover -s tools/integrations/metasploit/tests -v
```

Tests mock DNS and `msfconsole` process execution. They do not contact real targets or launch Metasploit.

## Upstream and license

- Source: https://github.com/rapid7/metasploit-framework
- Official installation: https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/
- HTTP version module documentation: https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/auxiliary/scanner/http/http_version.md
- Upstream README identifies the Framework as open source under a BSD-style license; consult the upstream `COPYING` file for exact terms.

Cerberus does not vendor Metasploit source code or redistribute its installer. The helper downloads the installer directly from the official Rapid7 Windows installer host after explicit user consent.
