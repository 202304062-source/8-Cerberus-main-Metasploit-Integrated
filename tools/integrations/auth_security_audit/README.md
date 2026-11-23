# Cerberus Authentication & Hash Security Audit

This add-only integration provides three workflows from one VS Code terminal:

1. **JWT Tool + OWASP ZAP**: inspect a compact JWT locally with the pinned `jwt_tool` release, then run the existing Cerberus ZAP Baseline runner with a temporary, target-origin-scoped `Authorization: Bearer ...` Replacer rule.
2. **John the Ripper**: bounded, offline dictionary-only review of a local hash file.
3. **Hashcat**: bounded, offline dictionary-only review of a local hash file.

## Start

From the Cerberus repository root:

```powershell
python tools/integrations/auth_security_audit/cli.py
```

Choose 1, 2, or 3 and follow the prompts. A workflow can also be selected explicitly:

```powershell
python tools/integrations/auth_security_audit/cli.py --workflow jwt-zap --target https://your-authorized-app.example --authorized
python tools/integrations/auth_security_audit/cli.py --workflow john --hash-file .\audit\hashes.txt --wordlist .\audit\approved-wordlist.txt --authorized
python tools/integrations/auth_security_audit/cli.py --workflow hashcat --hash-file .\audit\hashes.txt --wordlist .\audit\approved-wordlist.txt --hash-mode 1000 --authorized
```

For JWT, the token is requested with hidden terminal input unless `--token-file` is supplied. Do not put JWTs directly in command-line arguments. The integration pipes the token to the isolated jwt_tool process through stdin, not its process arguments. A token file is read locally and is not copied to the report. jwt_tool's temporary log/config files are created in a throw-away directory and removed after the local decode.

For Hashcat, specify a numeric mode appropriate for the hash format. For John, optionally pass `--john-format`. Both engines default to a maximum run time of 600 seconds; `--max-runtime` is limited to 30-1800 seconds.

## Project-managed dependencies

The first run downloads tools into this integration's ignored `.runtime/` directory:

- JWT Tool source tag `v2.3.0`, plus its Python requirements in a dedicated virtual environment.
- John the Ripper x64 Windows package from the official Openwall `john-packages` release. The release API currently exposes no asset SHA-256 digest for this archive; the installer records an observed local SHA-256 but cannot compare it to an upstream digest.
- Hashcat's latest Windows binary release from the official GitHub release API. The installer requires and verifies the asset's published SHA-256 digest before extraction.

No third-party binaries are committed to Cerberus and no user-wide PATH changes are made. The integration needs internet access on first bootstrap. On Windows the ZAP workflow additionally requires Docker Desktop/Engine running. Npcap is not required by this JWT/ZAP workflow. Hashcat may require suitable GPU/CPU OpenCL drivers; John can run on CPU.

For Linux/macOS, pre-installed `john` and `hashcat` executables on PATH are supported. This version does not auto-install their native packages on those platforms.

## JWT + ZAP behaviour

- JWT Tool is called only in local token-decode mode by default. If `--public-key` is provided, it also asks JWT Tool to verify the signature against that local PEM key.
- The separate structural inspector reports algorithm, claim names, expiry timing, and a few configuration warnings. It deliberately does not copy claim values or signature data into the report.
- ZAP receives the Bearer token through a temporary Replacer properties file. The rule is restricted to the target's scheme, hostname, and port. The temporary file is removed when the ZAP process exits.
- Existing Cerberus ZAP Baseline behaviour is reused: time-limited spidering plus passive scanning; no active attack scan is started.
- This version reuses an existing JWT. It does **not** automate login forms, refresh-token rotation, logout, server-side revocation, MFA, or role/privilege transitions. Those require application-specific endpoints, test accounts, and an explicitly designed test plan.

## Offline hash-audit behaviour

- Hash files and wordlists must be local regular files. URLs and UNC/network-share paths are rejected.
- John/Hashcat run locally with a user-supplied wordlist and an enforced time limit.
- Hashcat is restricted to attack mode `-a 0` (dictionary only). No mask/brute-force, rule, network, distributed, credential-spraying, or online-login workflow is provided.
- The pot files remain under `.runtime/state/`. Reports store counts and metadata only; plaintext recovered values are not copied to JSON reports.
- A match count measures only the supplied wordlist's coverage. It is not a formal entropy measurement or proof that unmatched passwords are strong.

## Output

Reports are stored under `reports/` in this module. Runtime downloads, virtual environments, pot files, and transient JWT state are ignored by Git. Treat hash inputs, token files, terminal output, and local pot files as sensitive. Do not commit them.

## Safety and licensing

Run JWT/ZAP only against hosts covered by written authorization, and review the target scope before confirming. Hash auditing is offline and limited to hash material you own or are authorized to audit. The downloaded upstream tools remain subject to their own licenses and notices: JWT Tool, John the Ripper, Hashcat, and OWASP ZAP. Review their upstream license files before redistribution or organizational use.

Upstream sources:

- https://github.com/ticarpi/jwt_tool
- https://github.com/openwall/john
- https://github.com/openwall/john-packages/releases
- https://github.com/hashcat/hashcat
- https://www.zaproxy.org/docs/docker/baseline-scan/
- https://www.zaproxy.org/docs/desktop/addons/replacer/
