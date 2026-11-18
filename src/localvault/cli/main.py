"""``lgk``: argparse front end. It only talks to the running app over its pipe; secrets are never written to logs."""
from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from typing import Any, TextIO

EXIT_OK, EXIT_USAGE, EXIT_NOT_RUNNING, EXIT_LOCKED, EXIT_DENIED, EXIT_NOT_FOUND = 0, 1, 2, 3, 4, 5

Forward = Callable[[dict[str, Any]], dict[str, Any]]

# Server error codes (cli_service, lgk_refs) and bridge failure codes to exit codes.
_EXIT_FOR_ERROR = {
    "locked": EXIT_LOCKED,
    "denied": EXIT_DENIED, "not_allowed": EXIT_DENIED, "cli_disabled": EXIT_DENIED,
    "client_not_allowed": EXIT_DENIED, "client_pin_unregistered": EXIT_DENIED,
    "client_pin_mismatch": EXIT_DENIED, "client_signer_mismatch": EXIT_DENIED,
    "agent_access_denied": EXIT_DENIED, "caller_not_browser": EXIT_DENIED,
    "not_found": EXIT_NOT_FOUND, "ambiguous": EXIT_NOT_FOUND, "no_field": EXIT_NOT_FOUND,
    "agent_state_missing": EXIT_NOT_RUNNING, "agent_state_invalid": EXIT_NOT_RUNNING,
    "agent_unavailable": EXIT_NOT_RUNNING, "agent_connection_changed": EXIT_NOT_RUNNING,
    "unauthorized": EXIT_NOT_RUNNING,
}

_HINTS = {
    EXIT_NOT_RUNNING: "Is LocalGateKeys running? Start it and unlock your vault.",
    "cli_disabled": "Turn on Command line access in LocalGateKeys, under Developer settings.",
}


class CliError(Exception):
    """``code`` is the exit code; ``error`` the app's error code (``failed`` when the reply was unusable)."""

    def __init__(self, code: int, message: str, error: str = "failed"):
        super().__init__(message)
        self.code = code
        self.message = message
        self.error = error


def default_forward(request: dict[str, Any]) -> dict[str, Any]:
    """Send one request to the running app. Failures come back as ``{"ok": False, "error": code}``."""
    try:
        from ..bridge_status import classify_failure
        from ..pipe_transport import forward_named_pipe
    except Exception:
        return {"ok": False, "error": "bridge_internal_error", "message": "The lgk bridge files are incomplete."}
    try:
        # The timeout covers connecting only; an approval prompt may keep the reply waiting for a while.
        return forward_named_pipe(dict(request, scope_hint="cli"), timeout_ms=5000)
    except Exception as exc:
        return classify_failure(exc, "connect")


def call(forward: Forward, request: dict[str, Any]) -> dict[str, Any]:
    """Run one request; a failed answer raises :class:`CliError` with the mapped exit code."""
    response = forward(request)
    if not isinstance(response, dict):
        raise CliError(EXIT_USAGE, "The app sent an unreadable reply.")
    if response.get("ok") is True:
        return response
    code = str(response.get("error") or "cli_failed")
    message = str(response.get("message") or code)
    exit_code = _EXIT_FOR_ERROR.get(code, EXIT_USAGE)
    hint = _HINTS.get(code) or _HINTS.get(exit_code)
    raise CliError(exit_code, f"{message} {hint}" if hint else message, code)


def resolve_refs(forward: Forward, refs: list[str], *, request: dict[str, Any] | None = None) -> dict[str, str]:
    """Resolve every reference with one request, so the app asks the user once. ``request`` is another action that
    answers the same way (``agent_run_secrets``); the references are added to it."""
    unique = list(dict.fromkeys(refs))
    if not unique:
        return {}
    values = call(forward, dict(request or {"action": "resolve_many"}, refs=unique)).get("values")
    if not isinstance(values, dict) or any(not isinstance(values.get(ref), str) for ref in unique):
        raise CliError(EXIT_USAGE, "The app sent an incomplete reply.")
    return {ref: values[ref] for ref in unique}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lgk", description="Read LocalGateKeys secrets from the command line.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Show whether the app is unlocked and command line access is on")
    listing = commands.add_parser("list", help="List the items command line access may use")
    listing.add_argument("--kind", help="Only items of this kind, for example login or api_key")
    read = commands.add_parser("read", help="Print one value")
    read.add_argument("ref", help="lgk://<item id or title>/<field>")
    totp = commands.add_parser("totp", help="Print the current two-factor code")
    totp.add_argument("ref", help="lgk://<item id or title>/totp, or an item id or title")
    run = commands.add_parser("run", help="Run a command with lgk:// values resolved in its environment")
    run.add_argument("--env-file", help="A .env file whose lgk:// values are resolved too")
    run.add_argument("--no-masking", action="store_true", help="Do not hide values in the command's output (masking matches UTF-8 output only)")
    run.add_argument("argv", nargs=argparse.REMAINDER, help="-- command and arguments")
    inject = commands.add_parser("inject", help="Fill {{ lgk://... }} in a template file")
    inject.add_argument("-i", "--input", required=True, dest="template")
    inject.add_argument("-o", "--output", required=True)
    inject.add_argument("--force", action="store_true", help="Replace an existing output file")
    commands.add_parser("mcp", help="Run the MCP server (stdio) that lets AI agents sign in with your approval")
    proof = commands.add_parser("proof", help="Privacy proof files")
    proof_commands = proof.add_subparsers(dest="proof_command", required=True)
    proof_verify = proof_commands.add_parser("verify", help="Check a privacy proof file's signature (offline)")
    proof_verify.add_argument("file")
    return parser


def _printable(value: object) -> str:
    """A proof file is untrusted: control, format (bidi) and separator characters in a field it carries are shown
    as ``\\uXXXX`` escapes, so they cannot fake extra output lines or move the terminal cursor."""
    import unicodedata

    return "".join(ch if ch == " " or not unicodedata.category(ch).startswith(("C", "Z")) else f"\\u{ord(ch):04x}"
                   for ch in str(value))


def _proof_verify(path: str, out: TextIO) -> int:
    """``lgk proof verify``: pure, never contacts the app."""
    from .. import privacy_proof

    try:
        with open(path, "rb") as handle:
            data = handle.read(privacy_proof.MAX_FILE_BYTES + 1)
    except OSError:
        raise CliError(privacy_proof.EXIT_CODES[privacy_proof.INVALID], "cannot read the file") from None
    result = privacy_proof.verify_bytes(data)
    kind = result["result"]
    if kind == privacy_proof.VALID:
        # The signature proves only which key signed: anyone can sign with their own key and any device id, so the
        # fingerprint must be compared with the device's own (Settings > Sync) before the file is trusted.
        print(f"valid\tsigned by key fingerprint {_printable(result['fingerprint'])}"
              f"\tdevice id {_printable(result['device_id'])}"
              "\tcompare this fingerprint with the one in Settings > Sync on that device", file=out)
    elif kind == privacy_proof.UNSIGNED:
        print("unsigned", file=out)
    else:
        print(f"invalid\t{_printable(result['reason'])}", file=out)
    return privacy_proof.EXIT_CODES[kind]


def main(argv: list[str] | None = None, *, forward: Forward | None = None,
         out: TextIO | None = None, err: TextIO | None = None) -> int:
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    forward = forward or default_forward
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:  # argparse: 0 for --help, 2 for usage errors
        return EXIT_OK if exc.code == 0 else EXIT_USAGE
    try:
        if args.command == "status":
            reply = call(forward, {"action": "status"})
            print(f"unlocked: {'yes' if reply.get('unlocked') else 'no'}", file=out)
            print(f"command line access: {'on' if reply.get('cli_enabled') else 'off'}", file=out)
        elif args.command == "list":
            request: dict[str, Any] = {"action": "list"}
            if args.kind:
                request["kind"] = args.kind
            for item in call(forward, request).get("items") or []:
                print(f"{item.get('id')}\t{item.get('title')}\t{item.get('kind')}", file=out)
        elif args.command == "read":
            print(call(forward, {"action": "read", "ref": args.ref}).get("value", ""), file=out)
        elif args.command == "totp":
            print(call(forward, {"action": "totp", "ref": args.ref}).get("code", ""), file=out)
        elif args.command == "proof":
            return _proof_verify(args.file, out)
        elif args.command == "mcp":
            from .mcp_server import serve_stdio

            return serve_stdio(forward)
        elif args.command == "run":
            from .run import run_command

            command = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
            if not command:
                raise CliError(EXIT_USAGE, "Usage: lgk run [--env-file F] [--no-masking] -- command [args]")
            return run_command(command, forward, env_file=args.env_file, masking=not args.no_masking, out=out, err=err)
        else:
            from .inject import inject_file

            inject_file(args.template, args.output, forward, force=args.force)
    except CliError as exc:
        print(f"lgk: {exc.message}", file=err)
        return exc.code
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # no traceback: it could quote a value
        print(f"lgk: unexpected error ({type(exc).__name__}).", file=err)
        return EXIT_USAGE
    return EXIT_OK
