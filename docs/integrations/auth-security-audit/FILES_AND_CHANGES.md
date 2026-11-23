# Cerberus Authentication, JWT, and Offline Hash Audit - Files and Changes

**Date:** 2026-11-22  
**Integration path:** `tools/integrations/auth_security_audit/`

## 1. Add-only verification

The supplied archive was used as the baseline. Its 1,225 original files were hashed with SHA-256 before work started. After the integration was added, every original file still had the same SHA-256 digest and every original path was present. No original file was edited, replaced, or deleted.

The integration is implemented only as new files. It does not modify the existing OWASP ZAP runner, Nmap runner, existing wrappers, or project configuration files.

## 2. New files

### Integration source

| New file | Responsibility |
|---|---|
| `tools/integrations/auth_security_audit/__init__.py` | Integration package marker and version. |
| `tools/integrations/auth_security_audit/cli.py` | Interactive terminal menu and command-line options for JWT+ZAP, John, and Hashcat. |
| `tools/integrations/auth_security_audit/jwt_inspector.py` | Local compact-JWT structure and time-claim inspection; does not verify signatures itself. |
| `tools/integrations/auth_security_audit/jwt_tool_installer.py` | Fetches pinned JWT Tool source, creates an isolated project-local virtual environment, and runs the decoder. |
| `tools/integrations/auth_security_audit/jwt_zap_runner.py` | Runs JWT Tool locally, writes a temporary target-scoped ZAP Replacer rule, reuses the existing ZAP Baseline runner design, redacts tokens from text reports, and writes a summary. |
| `tools/integrations/auth_security_audit/hash_tools_installer.py` | Finds or bootstraps official John/Hashcat Windows packages under the project runtime directory. |
| `tools/integrations/auth_security_audit/hash_audit_runner.py` | Validates local inputs and runs bounded offline dictionary-only audits. |
| `tools/integrations/auth_security_audit/README.md` | Setup, usage, scope, outputs, limitations, and licensing guidance. |
| `tools/integrations/auth_security_audit/.gitignore` | Keeps downloaded tools, venvs, pot files, reports, and transient runtime data out of Git. |
| `tools/integrations/auth_security_audit/reports/.gitkeep` | Retains the empty report directory in Git. |

### Automated tests

| New file | Coverage |
|---|---|
| `tools/integrations/auth_security_audit/tests/__init__.py` | Test package marker. |
| `tools/integrations/auth_security_audit/tests/test_jwt_inspector.py` | JWT structure, expiry, warnings, input validation, and target-scoped ZAP header config. |
| `tools/integrations/auth_security_audit/tests/test_jwt_zap_runner.py` | Authorization guard, report location, temporary config cleanup, and token redaction. |
| `tools/integrations/auth_security_audit/tests/test_hash_audit.py` | Local-only file validation, dictionary-only command building, format/mode validation, authorization, and runtime limits. |
| `tools/integrations/auth_security_audit/tests/test_installers.py` | Pinned JWT Tool release and installer metadata/digest handling; checks that the JWT is piped via stdin rather than process argv. |

### Cerberus wrappers

| New file | Responsibility |
|---|---|
| `tools/wrappers/jwt_zap_auth_wrapper.py` | Async adapter exposing the JWT + authenticated passive ZAP workflow to Cerberus agents/services. |
| `tools/wrappers/offline_hash_audit_wrapper.py` | Async adapter exposing offline John/Hashcat audit to Cerberus agents/services. |

## 3. Workflow design

### JWT Tool + OWASP ZAP

1. The user supplies an authorized HTTP(S) application URL and an existing compact JWT.
2. JWT Tool runs locally in decode mode. If a local PEM public key is supplied, JWT Tool is also asked to verify the signature with that key.
3. Cerberus inspects non-secret JWT metadata such as `alg`, claim names, and `exp`/`iat`/`nbf` timing. This structural inspection is not server-side authorization validation.
4. The integration creates a temporary ZAP Replacer properties file that adds `Authorization: Bearer <JWT>` only for the target's scheme, hostname, and port.
5. The existing ZAP Baseline execution pattern runs through the official stable Docker image. Baseline uses spidering and passive scanning; active attack scanning is not invoked.
6. The temporary properties file is removed, JWT strings are redacted from retained HTML/JSON/XML/text reports, and a summary JSON is saved.

The current workflow reuses an existing JWT. It does not automate login, refresh-token rotation, logout, server-side revocation, MFA, or role-transition testing. Those require application-specific test accounts, endpoint definitions, and a separate engagement-approved plan.

### John the Ripper / Hashcat

1. The user supplies a local hash file and a local dictionary/wordlist.
2. The user explicitly confirms ownership or authorization to audit the hash material.
3. The selected engine runs locally with a bounded time limit and dictionary attack only.
4. Hashcat is restricted to attack mode `-a 0`; no online login, spraying, distributed cracking, masks, or brute-force mode is configured.
5. Pot files stay in the ignored project `.runtime` directory. JSON reports contain counts and metadata only, not plaintext password matches.

The number of matches in one wordlist is a limited audit observation, not a formal entropy or password-strength proof.

## 4. Project-managed dependency bootstrap

No third-party executable is committed in this ZIP. When a workflow is first run, the installer downloads required material into the new integration's ignored `.runtime/` directory, so users do not need to download those tools separately by hand.

- JWT Tool source tag: `v2.3.0`; dependencies are installed into a dedicated virtual environment inside `.runtime/`.
- John the Ripper: official x64 Windows package from the Openwall `john-packages` release. The current GitHub release metadata does not expose a SHA-256 asset digest for this ZIP; the local observed SHA-256 is recorded, but cannot be checked against an upstream digest by this installer.
- Hashcat: latest official Windows `.7z` release obtained from GitHub release metadata. The installer requires the asset's published SHA-256 digest and verifies it before extraction. A 7z extractor is installed into project-local `.runtime/python_packages/` only when no 7-Zip executable is available.
- ZAP: reuses the existing Cerberus ZAP integration and official `ghcr.io/zaproxy/zaproxy:stable` Docker image. Docker Desktop/Engine must be installed and running for the JWT+ZAP workflow.
- On Linux/macOS, existing `john` and `hashcat` executables on PATH are supported; this release does not auto-install native packages on those systems.

First-run bootstrap requires an Internet connection. Hashcat may need the appropriate platform GPU/CPU compute runtime/driver; John can run on CPU.

## 5. How to run in VS Code / PowerShell

From the Cerberus repository root:

```powershell
python tools/integrations/auth_security_audit/cli.py
```

Choose:

- `1` - JWT + OWASP ZAP authenticated passive baseline.
- `2` - John the Ripper offline dictionary audit.
- `3` - Hashcat offline dictionary audit.

Examples:

```powershell
python tools/integrations/auth_security_audit/cli.py --workflow jwt-zap --target https://your-authorized-app.example --authorized
python tools/integrations/auth_security_audit/cli.py --workflow john --hash-file .\audit\hashes.txt --wordlist .\audit\approved-wordlist.txt --authorized
python tools/integrations/auth_security_audit/cli.py --workflow hashcat --hash-file .\audit\hashes.txt --wordlist .\audit\approved-wordlist.txt --hash-mode 1000 --authorized
```

For JWT, use the hidden token prompt or a local `--token-file`. Do not add tokens directly to command-line arguments. For Hashcat, select a numeric mode suitable for the specific hash format. The default runtime is 600 seconds; the CLI permits 30-1800 seconds.

## 6. Reports and local sensitive files

- JWT + ZAP reports: `tools/integrations/auth_security_audit/reports/jwt_zap/`
- Hash audit summaries: `tools/integrations/auth_security_audit/reports/hashes/`
- Downloads, virtual environments, JWT temporary state, John/Hashcat pot files: `tools/integrations/auth_security_audit/.runtime/`

The new `.gitignore` prevents reports and runtime materials from being committed accidentally. Treat token files, JWT terminal output, hash files, wordlists, and pot files as sensitive.

## 7. Verification results

| Verification | Result |
|---|---:|
| New auth/hash integration unit tests | 20 passed |
| Existing OWASP ZAP integration unit tests | 9 passed |
| Existing Nmap integration unit tests | 11 passed |
| Total unit tests | 40 passed |
| Python compile check for new source | Passed |
| CLI help invocation | Passed |
| Original archive files checked by SHA-256 | 1,225 |
| Original files changed | 0 |
| Original files missing | 0 |
| New integration/wrapper files | 17 |

These are local unit/command-construction checks. No external tools were downloaded or executed in this build environment, no live JWT was used, no target application was scanned, and no hash material was cracked. The first live run and upstream dependency bootstrap are for the user to execute in their own authorized environment.

## 8. Upstream references

- JWT Tool: https://github.com/ticarpi/jwt_tool (release `v2.3.0`)
- John the Ripper source: https://github.com/openwall/john
- Official Openwall packages: https://github.com/openwall/john-packages/releases
- Hashcat: https://github.com/hashcat/hashcat (latest release at integration time: `v8.0.0`)
- ZAP Baseline: https://www.zaproxy.org/docs/docker/baseline-scan/
- ZAP Replacer: https://www.zaproxy.org/docs/desktop/addons/replacer/
- ZAP config file options: https://www.zaproxy.org/faq/how-do-you-find-out-what-key-to-use-to-set-a-config-value-on-the-command-line/
