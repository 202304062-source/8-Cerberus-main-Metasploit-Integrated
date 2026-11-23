"""Interactive terminal entry point for Cerberus authentication and hash audits."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.integrations.auth_security_audit.hash_audit_runner import OfflineHashAuditRunner, HashAuditError
from tools.integrations.auth_security_audit.jwt_zap_runner import JWTZAPAuthRunner, JWTZAPError


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Cerberus authentication/JWT review and offline hash audit. Use only with explicit authorization."
    )
    p.add_argument("--workflow", choices=("jwt-zap", "john", "hashcat"), help="Workflow to run; without it an interactive menu is shown.")
    p.add_argument("--target", help="Owned/authorized HTTP(S) application URL for the jwt-zap workflow.")
    p.add_argument("--token-file", help="Local file containing one JWT. Without this, a hidden prompt is used.")
    p.add_argument("--public-key", help="Optional local PEM public key for jwt_tool signature verification.")
    p.add_argument("--minutes", type=int, default=1, help="ZAP baseline spider duration (1-10 minutes).")
    p.add_argument("--hash-file", help="Local hash file for John/Hashcat.")
    p.add_argument("--wordlist", help="Local dictionary/wordlist file for offline auditing.")
    p.add_argument("--hash-mode", help="Numeric Hashcat hash mode, e.g. 0 (MD5) or 1000 (NTLM).")
    p.add_argument("--john-format", help="Optional John format name, e.g. raw-md5 or bcrypt.")
    p.add_argument("--max-runtime", type=int, default=600, help="Offline hash audit time limit (30-1800 seconds).")
    p.add_argument("--authorized", action="store_true", help="Confirm ownership or written permission for the target/data.")
    return p


def _authorized(flag: bool, message: str) -> bool:
    if flag:
        return True
    print(message)
    try:
        return input("Type YES to confirm and continue: ").strip() == "YES"
    except EOFError:
        return False


def _read_token(token_file: str | None) -> str:
    if token_file:
        candidate = Path(token_file).expanduser()
        if candidate.is_symlink():
            raise ValueError("Token file must not be a symbolic link.")
        path = candidate.resolve(strict=True)
        if not path.is_file():
            raise ValueError("Token file must be a local regular file.")
        token = path.read_text(encoding="utf-8").strip()
    else:
        token = getpass.getpass("Paste JWT (input hidden): ").strip()
    if not token:
        raise ValueError("No JWT was provided.")
    return token


def _run_jwt(args: argparse.Namespace) -> int:
    target = args.target or input("Authorized application URL (http/https): ").strip()
    token = _read_token(args.token_file)
    if not _authorized(args.authorized, "Run only against an application you own or have written permission to assess."):
        print("[CERBERUS] Cancelled: authorization was not confirmed.")
        return 4
    try:
        result = JWTZAPAuthRunner().run(
            target,
            token,
            authorized=True,
            public_key_path=args.public_key,
            minutes=args.minutes,
        )
    except (ValueError, OSError, JWTZAPError) as exc:
        print(f"[CERBERUS][JWT+ZAP] ERROR: {exc}", file=sys.stderr)
        return 3
    print("\n[CERBERUS][JWT+ZAP] Summary:")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(result.get("exit_code", 3)) if result.get("exit_code") in {0, 1, 2} else 3


def _run_hash(args: argparse.Namespace, engine: str) -> int:
    hash_file = args.hash_file or input("Local hash file path: ").strip()
    wordlist = args.wordlist or input("Local wordlist path: ").strip()
    hash_mode = args.hash_mode
    if engine == "hashcat" and not hash_mode:
        hash_mode = input("Hashcat numeric hash mode (e.g. 0=MD5, 1000=NTLM): ").strip()
    if not _authorized(args.authorized, "Use only hashes you own or are explicitly authorized to audit. This mode is local/offline only."):
        print("[CERBERUS][HASH] Cancelled: authorization was not confirmed.")
        return 4
    try:
        result = OfflineHashAuditRunner().run(
            engine,
            hash_file,
            wordlist,
            authorized=True,
            max_runtime=args.max_runtime,
            hash_mode=hash_mode,
            john_format=args.john_format,
        )
    except (ValueError, HashAuditError) as exc:
        print(f"[CERBERUS][HASH] ERROR: {exc}", file=sys.stderr)
        return 3
    print("\n[CERBERUS][HASH] Summary:")
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    workflow = args.workflow
    if workflow is None:
        print("\nCERBERUS - AUTHENTICATION & HASH SECURITY AUDIT")
        print("1) JWT + OWASP ZAP authenticated passive baseline")
        print("2) John the Ripper - offline dictionary audit")
        print("3) Hashcat - offline dictionary audit")
        try:
            choice = input("Choose [1-3]: ").strip()
        except EOFError:
            return 4
        workflow = {"1": "jwt-zap", "2": "john", "3": "hashcat"}.get(choice)
        if workflow is None:
            print("Invalid choice.", file=sys.stderr)
            return 2
    if workflow == "jwt-zap":
        return _run_jwt(args)
    return _run_hash(args, workflow)


if __name__ == "__main__":
    raise SystemExit(main())
