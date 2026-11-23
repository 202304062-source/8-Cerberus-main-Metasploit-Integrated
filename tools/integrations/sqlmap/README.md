# Cerberus SQLMap Integration

This is an **add-only, separate-process launcher** for the official SQLMap SQL
injection testing tool. It gives a developer a simple interactive command in the
VS Code integrated terminal: enter one HTTP(S) URL, confirm written authorization,
and watch the upstream SQLMap output in the same terminal.

It does not replace or edit the existing `tools/wrappers/sqlmap_wrapper.py`.
That legacy wrapper is retained exactly as supplied in the input archive.

## First run: automatic project-local setup

The Cerberus repository contains the launcher, bootstrapper, tests, and usage
instructions. To respect SQLMap's separate licensing terms, the SQLMap source
is **not copied into Cerberus or bundled into this ZIP**. On first launch,
`bootstrap.py` automatically obtains the official SQLMap source from
`https://github.com/sqlmapproject/sqlmap` and places it under:

`tools/external/sqlmap_runtime/sqlmap/`

The downloaded upstream `LICENSE` file is kept alongside that source. The
runtime folder is ignored by Git, so it is not committed as part of Cerberus.
No separate manual SQLMap installation or separate user download is required;
Python 3.11+ and internet access are required for the first run. Git is used if
available, with a Python-standard-library ZIP download fallback. Later runs use
the local checkout and do not download it again.

## Run in Visual Studio Code

Open the **Cerberus project root** in VS Code, open **Terminal > New Terminal**,
and execute:

```powershell
python tools/integrations/sqlmap/cli.py
```

Enter a single target URL when prompted, for example a URL from your own local
training lab. Then type exactly:

```text
I HAVE AUTHORIZATION
```

The scanner output is written directly to the VS Code terminal. No VS Code
extension is required.

You may also supply the URL as an argument (the authorization prompt still
appears):

```powershell
python tools/integrations/sqlmap/cli.py --url "http://127.0.0.1:8080/item.php?id=1"
```

Optional process time limit (30-3600 seconds; default 900):

```powershell
python tools/integrations/sqlmap/cli.py --url "https://authorized.example/item?id=1" --timeout 600
```

## Default scan profile and safety boundary

The launcher exposes one constrained profile:

- One manually supplied HTTP or HTTPS URL only.
- Authorization confirmation is required for every run.
- `--level=1` and `--risk=1` limit the default test intensity.
- `--technique=BE` uses Boolean-based and error-based detection only; UNION,
  stacked-query, time-based, and inline-query techniques are not enabled.
- One thread, a 10-second request timeout, one retry, and redirects ignored.
- No crawler, form discovery, arbitrary command-line flags, database enumeration,
  data dumping, file read/write, OS shell, or SQL shell options are exposed.
- The upstream output is streamed to the terminal without being parsed by this
  Cerberus launcher.

This is a limited detection profile, not a guarantee of zero impact. SQL
injection tests actively send test requests and may affect fragile applications
or trigger security monitoring. Test only a system you own or have explicit
written permission to assess, during an approved test window. Syntactic URL
validation and the typed confirmation do not prove ownership or automatically
check Cerberus Scope of Engagement / Rules of Engagement records.

## Output

SQLMap stores its native session and text output under timestamped folders in:

`tools/integrations/sqlmap/reports/`

The output directory is ignored by Git except for `.gitkeep` and `.gitignore`.
The original SQLMap output remains in its upstream format; the integration does
not parse or reinterpret it as a vulnerability finding.

## Requirements

- Python 3.11 or later.
- Internet access on the first launch to fetch the official upstream source.
- Git is optional; the launcher falls back to a ZIP download using Python's
  standard library.
- VS Code is optional at runtime; any terminal in the project root works.

## Offline tests

From the Cerberus project root:

```powershell
python -m unittest discover -s tools/integrations/sqlmap/tests -v
```

These tests validate URL input, safe command construction, and ZIP archive path
handling only. They do not call GitHub, contact a target, or execute a scan.

## Licensing and upstream references

SQLMap is distributed by its maintainers under GPL version 2 or later, with
clarifications in its upstream `LICENSE`. The SQLMap maintainers state that
executing SQLMap and parsing its results can be considered a derived work, while
a typical shell/launch menu that simply displays raw SQLMap output is not treated
the same way in their published licensing explanation. This integration is
intentionally limited to a separate process and raw terminal output; it does not
import SQLMap modules or parse SQLMap output. This is a technical integration
note, not legal advice. Review the current upstream license and obtain the
appropriate licensing advice before changing this architecture or redistributing
modified SQLMap code.

- SQLMap source: https://github.com/sqlmapproject/sqlmap
- SQLMap README: https://github.com/sqlmapproject/sqlmap/blob/master/README.md
- SQLMap license: https://github.com/sqlmapproject/sqlmap/blob/master/LICENSE
- SQLMap licensing clarification: https://github.com/sqlmapproject/sqlmap/wiki/License
- SQLMap usage manual: https://github.com/sqlmapproject/sqlmap/wiki/Usage
