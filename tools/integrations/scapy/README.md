# Cerberus Scapy Integration

This is an additive, URL-driven integration of the official [Scapy](https://github.com/secdev/scapy)
packet-manipulation library. It adds a dedicated command-line tool and an async Cerberus wrapper.
It does not replace or edit existing Nmap, SQLMap, OWASP ZAP, or other project code.

## First run: Scapy is installed automatically

The launcher and its dependency file are included in the Cerberus repository. If Scapy is not
available in the active Python interpreter, the launcher automatically runs pip against this
integration's `requirements.txt`. It uses the same `python` executable that started the tool, so
an activated project virtual environment is respected. There is no need to clone Scapy separately
or manually download its source repository.

Scapy is installed from the Python package index. The upstream Scapy source is not vendored into
this repository. Windows has an additional operating-system prerequisite: Npcap is required for
Scapy packet I/O. Install Npcap once on the computer, then run the VS Code terminal with suitable
permissions (Administrator may be required). This driver cannot be installed safely or silently
by a Python package bootstrapper. Linux/macOS packet operations may also require root or suitable
network capabilities.

## Run from the VS Code terminal

Open the Cerberus project root in Visual Studio Code, choose **Terminal > New Terminal**, and run:

```powershell
python tools/integrations/scapy/cli.py
```

Enter one HTTP(S) URL, for example a target in your own test lab. The tool then asks you to type:

```text
I HAVE AUTHORIZATION
```

To provide the URL directly:

```powershell
python tools/integrations/scapy/cli.py --url "https://your-authorized-domain.example/"
```

To select up to five individual TCP ports:

```powershell
python tools/integrations/scapy/cli.py --url "https://your-authorized-domain.example/" --ports "443,80,8080"
```

Other options:

- `--http-timeout 5`: HTTP HEAD timeout (1-30 seconds).
- `--packet-timeout 1.5`: timeout per TCP SYN probe (0.2-5 seconds).
- `--no-install`: fail instead of automatically installing Scapy when it is missing.

## What the integration does

1. Validates one HTTP or HTTPS URL and derives its hostname and port.
2. Resolves the hostname to one IPv4 address. Only the first returned IPv4 address is assessed.
3. Sends one HTTP(S) `HEAD` request using normal TLS certificate validation. It does not follow redirects or download a response body. A small allow-listed set of response headers is recorded.
4. Sends at most five sequential TCP SYN probes to individual ports. The default list is the URL port plus common web ports, deduplicated and capped at five. When a SYN-ACK is received, the integration attempts to send a TCP reset immediately.
5. Prints progress and results in the VS Code terminal and writes `summary.json` under `tools/integrations/scapy/reports/`.

This is conservative network reconnaissance, not a web vulnerability scanner. It does not exploit services, submit attack payloads, crawl pages, brute-force credentials, enumerate databases, or capture network traffic. An open port or HTTP status is an observation, not proof of a vulnerability.

## Output

Each run creates a timestamped directory under:

`tools/integrations/scapy/reports/`

The `summary.json` report contains the normalized target (without URL query values), resolved IPv4 address, HTTP HEAD result, TCP probe results, duration, and limitations. Runtime reports are ignored by Git; only `.gitkeep` and `.gitignore` are committed.

## Python integration

```python
import asyncio
from tools.wrappers.scapy_integration_wrapper import ScapyIntegrationWrapper

async def main():
    scanner = ScapyIntegrationWrapper()
    result = await scanner.scan(
        "https://your-authorized-domain.example/",
        authorized=True,  # derive this from the active Cerberus SoE/ROE
        ports=(443, 80),
    )
    print(result)

asyncio.run(main())
```

Callers must enforce the active Scope of Engagement / Rules of Engagement before invoking the
wrapper. A boolean passed by a caller is not an independent proof of authorization.

## Tests

From the Cerberus repository root:

```powershell
python -m unittest discover -s tools/integrations/scapy/tests -v
```

Tests mock DNS, HTTP, and packet probing. They do not connect to a public target or send packets.

## Platform notes and upstream references

- Python 3.11+ is required by the current Cerberus project.
- Scapy is installed by pip from this integration's requirements file.
- Windows packet I/O requires Npcap; review the Scapy installation guide and Npcap's installation prompts.
- Run packet I/O only with the OS permissions required by your platform.
- Scapy is licensed under GPL-2.0-only. This integration imports the library as a dependency and does not copy Scapy's source into Cerberus. Review upstream terms before redistributing a modified or bundled copy.

References:

- Scapy upstream repository: https://github.com/secdev/scapy
- Scapy installation guide: https://scapy.readthedocs.io/en/latest/installation.html
- Scapy usage guide: https://scapy.readthedocs.io/en/latest/usage.html
- Scapy upstream license: https://github.com/secdev/scapy/blob/master/LICENSE
