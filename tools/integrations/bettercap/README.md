# Cerberus Bettercap Integration

This is an additive, repository-contained integration for the official [Bettercap](https://github.com/bettercap/bettercap) network reconnaissance framework. It does not edit or replace the existing Scapy, Nmap, SQLMap, OWASP ZAP, or other tool integrations.

## Important scope distinction

Bettercap's `net.recon` module periodically reads the local operating system ARP table to detect hosts already represented on the local network. This integration accepts one HTTP(S) URL, resolves its hostname to one IPv4 address, and asks Bettercap to display that address if it exists in the local ARP cache. A public Internet website normally is not a local Layer-2 neighbor, so an empty match is expected for remote websites. This is **not** a website vulnerability scan, port scan, traffic capture, or proof that the website is secure.

Only these fixed Bettercap commands are used:

```text
net.recon on
sleep 3
net.recon off
net.show <resolved-ipv4>
q
```

The wait can be set from 1 to 10 seconds. The integration does not enable `net.probe`, `syn.scan`, `net.sniff`, `arp.spoof`, `dns.spoof`, proxies, Wi-Fi attacks, BLE operations, or credential collection.

## First run and automatic bootstrap

The Bettercap executable is not committed to Git. On first run, the Python bootstrapper queries the official GitHub release metadata and downloads the matching official prebuilt archive for the current supported platform into this integration's `.runtime/` folder. It extracts only the Bettercap executable. The bootstrapper pins release `v2.42.0` for reproducible installs and validates the release tag; when GitHub supplies an asset SHA-256 digest, it verifies that digest before extraction.

Supported prebuilt platform mappings in this integration:

- Windows amd64
- Linux amd64
- macOS arm64

The official Bettercap installation guide lists Windows support and the currently published prebuilt platform targets. Windows packet-capture capabilities depend on the local Npcap installation and suitable privileges. Install Npcap separately from its official source if Bettercap reports that the packet-capture driver is unavailable. Python cannot safely install or enable a system packet driver on behalf of the user.

## Run from Visual Studio Code terminal

Open the `Cerberus-main` repository root in VS Code, select **Terminal > New Terminal**, then run:

```powershell
python tools/integrations/bettercap/cli.py
```

Enter an authorized website URL, for example:

```text
https://your-authorized-domain.example
```

The CLI asks for this exact authorization phrase:

```text
I HAVE AUTHORIZATION
```

To provide the URL directly:

```powershell
python tools/integrations/bettercap/cli.py --url "https://your-authorized-domain.example"
```

To choose a network interface explicitly:

```powershell
python tools/integrations/bettercap/cli.py --url "https://your-authorized-domain.example" --interface "Ethernet"
```

Other options:

- `--wait-seconds 3`: local ARP observation window (1-10 seconds).
- `--no-install`: do not download Bettercap automatically; fail unless the project-local executable is already present.

## Runtime output

The Bettercap console output is printed in the VS Code terminal. Each run also writes `summary.json` under:

```text
tools/integrations/bettercap/reports/
```

The `.runtime/` folder stores the automatically bootstrapped Bettercap executable locally and is ignored by Git. Reports are ignored by Git as well. A fresh GitHub clone therefore contains the Python integration, docs, tests, and bootstrap logic; each user obtains the official binary on first run rather than committing an operating-system executable to the repository.

## Cerberus wrapper

```python
import asyncio
from tools.wrappers.bettercap_integration_wrapper import BettercapIntegrationWrapper

async def main():
    integration = BettercapIntegrationWrapper()
    result = await integration.inspect_target(
        "https://your-authorized-domain.example",
        authorized=True,  # derive from the active approved SoE/ROE
        wait_seconds=3,
    )
    print(result)

asyncio.run(main())
```

The service or agent invoking this wrapper must check the approved Scope of Engagement / Rules of Engagement first. The `authorized` argument is not an independent proof of permission.

## Tests

From the project root:

```powershell
python -m unittest discover -s tools/integrations/bettercap/tests -v
```

All unit tests mock Bettercap process execution and DNS; they do not send network packets or access a target.

## Upstream project and license

- Repository: https://github.com/bettercap/bettercap
- Installation: https://www.bettercap.org/project/installation/
- Interactive command-line session: https://www.bettercap.org/usage/interactive_session/
- `net.recon` module: https://www.bettercap.org/modules/ethernet/netrecon/
- Bettercap upstream license: GPL-3.0

Review Bettercap's upstream license and obligations before redistributing the integrated project.
