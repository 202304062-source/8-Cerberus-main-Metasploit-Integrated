# Cerberus SQLMap Integration - Added Files and Change Manifest

## Integration goal

Add an independently runnable SQLMap launcher to the existing Cerberus
repository. The user runs it from the VS Code terminal, enters one HTTP(S) URL,
confirms authorization, and sees the upstream SQLMap output in that terminal.
SQLMap is fetched automatically into a project-local runtime directory on first
use; no separate manual installation is required.

## Add-only change policy

The input archive was:

`4 Cerberus-main-OWASP-ZAP-NMAP-JWT-John-Hashcat-Integrated(3).zip`

The archive was extracted and the integration was added without editing,
deleting, renaming, or replacing any path that existed in the original archive.
In particular, the pre-existing `tools/wrappers/sqlmap_wrapper.py` was left
untouched. The new integration is separate from that legacy wrapper.

The original archive contained 1,245 ZIP entries. A per-file SHA-256 comparison
was performed after implementation to verify that every original file's bytes
remain unchanged. Only the new files listed below are added.

## New files

| Path | Purpose |
|---|---|
| `tools/integrations/sqlmap/__init__.py` | Exposes target validation and command construction helpers. |
| `tools/integrations/sqlmap/runner.py` | Validates one HTTP(S) URL and builds a constrained SQLMap command. |
| `tools/integrations/sqlmap/bootstrap.py` | Automatically fetches the official SQLMap checkout on first run (Git first, ZIP fallback). |
| `tools/integrations/sqlmap/cli.py` | Interactive VS Code terminal launcher with authorization confirmation and live output. |
| `tools/integrations/sqlmap/README.md` | Requirements, setup, usage, safety boundaries, output, tests, and licensing notes. |
| `tools/integrations/sqlmap/tests/__init__.py` | Test package marker. |
| `tools/integrations/sqlmap/tests/test_runner.py` | Offline tests for URL validation and constrained command construction. |
| `tools/integrations/sqlmap/tests/test_bootstrap.py` | Offline tests for safe SQLMap ZIP extraction and path-traversal rejection. |
| `tools/integrations/sqlmap/reports/.gitkeep` | Keeps the reports directory in Git. |
| `tools/integrations/sqlmap/reports/.gitignore` | Excludes generated SQLMap sessions and reports from Git. |
| `tools/external/sqlmap_runtime/.gitignore` | Excludes the auto-downloaded upstream SQLMap source from Git. |
| `docs/integrations/sqlmap/FILES_AND_CHANGES.md` | This change and verification manifest. |
| `docs/integrations/sqlmap/Cerberus_SQLMap_Code.pdf` | Source listing for all new Python integration and test files. |
| `docs/integrations/sqlmap/Cerberus_SQLMap_Added_Files_and_Changes.pdf` | English report of integration structure, operation, licensing, and verification. |

## Existing project files modified

**None.** No existing file was edited or removed. The legacy
`tools/wrappers/sqlmap_wrapper.py` remains as it was in the input archive.

## Run command

Interactive mode from the repository root:

```powershell
python tools/integrations/sqlmap/cli.py
```

Direct URL (the authorization prompt remains mandatory):

```powershell
python tools/integrations/sqlmap/cli.py --url "http://127.0.0.1:8080/item.php?id=1"
```

At the authorization prompt, type exactly `I HAVE AUTHORIZATION`.

## Automatic dependency model

SQLMap source is not vendored or edited in Cerberus. The first invocation fetches
the official upstream source into `tools/external/sqlmap_runtime/sqlmap/` and
retains its upstream LICENSE file. Git is used when available; otherwise, the
launcher tries official GitHub ZIP archive URLs using Python's standard library.
The first invocation requires internet access. Later invocations reuse the
project-local checkout. The user does not need to download or install SQLMap
manually or manage it as a separate application.

This arrangement is intentional because SQLMap's published license notes
specific restrictions on embedding and on executing/parsing its output. The
launcher therefore runs the upstream program as a separate process and streams
raw output without parsing it. Refer to the current upstream license before
redistributing or changing the integration model.

## Safety controls

- Requires a single HTTP(S) URL; rejects embedded URL credentials and malformed
  URLs.
- Requires an exact interactive authorization phrase for every scan.
- Restricts the scan to `--level=1`, `--risk=1`, `--technique=BE`, one thread,
  a 10-second request timeout, one retry, and ignored redirects.
- Does not enable UNION, stacked-query, time-based, or inline-query techniques.
- Does not expose crawling, forms discovery, database enumeration, data dumping,
  file access, SQL shell, OS shell, or arbitrary SQLMap flags.
- Uses an argument list with `shell=False` and streams raw upstream output to
  the current terminal.
- Stops the scanner after a configurable process timeout (30-3600 seconds).
- Does not claim that syntax validation or user confirmation proves ownership
  or checks the platform's Scope of Engagement / Rules of Engagement.

## Verification commands

```powershell
python -m unittest discover -s tools/integrations/sqlmap/tests -v
```

The tests are offline and do not call GitHub, contact a target, or run SQLMap.
A live scan was not performed while packaging.

## Upstream references

- Source repository: https://github.com/sqlmapproject/sqlmap
- README and install instructions: https://github.com/sqlmapproject/sqlmap/blob/master/README.md
- License: https://github.com/sqlmapproject/sqlmap/blob/master/LICENSE
- License clarification: https://github.com/sqlmapproject/sqlmap/wiki/License
- Usage manual: https://github.com/sqlmapproject/sqlmap/wiki/Usage
