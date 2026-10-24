"""Act as the desktop for live checks with the Android app on an emulator (Task 15 of the Android plan).

This uses the desktop's own sync modules in-process (``localvault.sync.service``, ``lan_sync``, ``pairing``,
``vault_bridge``, ``folder_transport``, ``phone_backup``, ``phone_restore``) on a SCRATCH vault only:

* ``--data-dir`` must lie inside the system temp folder; ``LOCALGATEKEYS_DATA_DIR`` is set to it before anything
  from ``localvault`` is imported, so the install id and every other file stay there. The user's real vault and
  settings are never opened, and no desktop app is started or contacted.
* The LAN listener binds 127.0.0.1 only. An Android emulator reaches it as 10.0.2.2, which is the address the
  pairing code advertises (``--advertise``). No firewall rule is needed and nothing listens on other adapters.

Usage (two shells; the server keeps the scratch vault unlocked until ``quit``)::

    python scripts/android_live_peer.py serve --data-dir %TEMP%\\lgk-live --port 47931
    python scripts/android_live_peer.py send  --data-dir %TEMP%\\lgk-live status
    python scripts/android_live_peer.py send  --data-dir %TEMP%\\lgk-live pair

Commands (``send <command> [args...]``; the answer is printed as JSON):

    status                               items, sync status, Wi-Fi peers, folder
    pair                                 a new pairing code (``qr`` is the text for ``lgk.debug.pairing``)
    paired <offer id>                    the device id that enrolled with that offer, or null
    pending <offer id>                   the request waiting for Accept (name and verification code), or null
    accept <offer id> [code]             wait up to 60 s for the request, check the phone's code if given, Accept
    decline <offer id>                   Decline the request waiting on that offer (sync v2)
    add-login <label> <url> <user> <pw>  a new website login
    add-note <title> <body>              a new note
    edit-note <title> <body>             change a note's body
    edit-login <label> <password>        change a login's password
    sync                                 one sync run now (LAN serves the phone; the folder, if any, is read)
    add-folder <password>                give the group a cloud folder (<data dir>/Folder) with that sync password
    check-folder <folder>                decode every device file in <folder> with the group key, as the desktop does
    restore <backup> <password> [fresh]  read a phone backup and restore it into this vault, or into a new one
    quit                                 stop the service and exit
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Any

MASTER = "scratch master for android live checks"
TEST_KDF = {"time_cost": 1, "memory_cost_kib": 8192, "parallelism": 1, "hash_len": 32}
LISTEN_HOST = "127.0.0.1"
JOB_TIMEOUT = 120.0


def _scratch_dir(value: str) -> Path:
    path = Path(value).resolve()
    temp = Path(tempfile.gettempdir()).resolve()
    if temp not in path.parents:
        raise SystemExit(f"--data-dir must be inside {temp} (a scratch folder), not {path}")
    return path


def _prepare_env(data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    os.environ["LOCALGATEKEYS_DATA_DIR"] = str(data_dir)
    src = Path(__file__).resolve().parents[1] / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))


# --------------------------------------------------------------------------------------------------- server


class Peer:
    def __init__(self, data_dir: Path, port: int, advertise: str) -> None:
        from localvault.sync import service as svc
        from localvault.sync.install import load_or_create_install_id
        from localvault.sync.transport import LANEndpoint
        from localvault.vault import create_vault, unlock_vault

        self.data_dir = data_dir
        self.port = port
        self.advertise = advertise
        self.vault_path = data_dir / "vault.json"
        if self.vault_path.exists():
            self.session = unlock_vault(self.vault_path, MASTER)
        else:
            self.session = create_vault(self.vault_path, MASTER, kdf_overrides=TEST_KDF)
            self.session.create_web_login(urls=[{"url": "https://desktop.example"}], username="desk.user",
                                          password="desktop-pass-1", label="Desktop login")  # noqa: S106 - scratch test data
            self.session.item_service.create_note("Desktop note", "written on the desktop")
        self.install_id = load_or_create_install_id()
        self.alive = True
        endpoint = LANEndpoint(LISTEN_HOST, port)
        self.service = svc.SyncService(
            self.session, self._check, install_id=self.install_id,
            transports=[svc.FolderAdapter(install_id=self.install_id),
                        svc.LanAdapter(install_id=self.install_id, endpoint=lambda: endpoint)],
            scheduler=svc.ThreadScheduler(), change_marker=lambda: svc.vault_change_marker(self.session))
        self.service.on_unlock()
        self.offers: dict[str, Any] = {}

    def _check(self) -> None:
        if not self.alive:
            from localvault.session_guard import StaleSession

            raise StaleSession("scratch peer stopped")

    # jobs run on the service worker, inside the sync gate (as the desktop app's Sync page does)
    def job(self, fn, *, run_after: bool = False) -> Any:
        done = threading.Event()
        box: dict[str, Any] = {}

        def on_done(result: Any, error: BaseException | None) -> None:
            box["result"], box["error"] = result, error
            done.set()

        if not self.service.submit(fn, on_done, run_after=run_after):
            raise RuntimeError("service stopped")
        if not done.wait(JOB_TIMEOUT):
            raise TimeoutError("job timed out")
        if box["error"] is not None:
            raise box["error"]
        return box["result"]

    def wait_idle(self) -> None:
        self.job(lambda s, lease, gate: None)
        deadline = time.time() + JOB_TIMEOUT
        while self.service.status().running and time.time() < deadline:
            time.sleep(0.1)

    # views
    def items(self, session: Any = None) -> list[dict[str, Any]]:
        session = session or self.session
        rows: list[dict[str, Any]] = []
        for entry in session._payload.get("entries", []):
            rows.append({"id": entry["id"], "ns": "entry", "kind": entry.get("kind"), "label": entry.get("label"),
                         "username": entry.get("username"), "password": entry.get("password"),
                         "origin": (entry.get("scope") or {}).get("origin")})
        for item in session._payload.get("items", []):
            full = session.item_service.get_item(item["id"], include_protected=True) or item
            rows.append({"id": item["id"], "ns": "item", "kind": item.get("kind"), "title": item.get("title"),
                         "body": (full.get("payload") or {}).get("body")})
        return rows

    def status(self) -> dict[str, Any]:
        from localvault.sync.vault_bridge import load_sync_state

        def read(session: Any, lease: Any, gate: Any) -> Any:
            return load_sync_state(session)

        state = self.job(read)
        view = self.service.status()
        endpoint, issue = self.service.lan_listen_state()
        return {
            "items": self.items(),
            "group": None if state is None else {
                "group_id": state.group_id, "epoch": state.epoch, "device_id": state.device_id,
                "folder": state.folder_path, "lan_peers": [p.get("device_id") for p in state.lan_peers],
                "last_seen": dict(state.last_seen)},
            "listening": None if endpoint is None else f"{endpoint.host}:{endpoint.port}",
            "listen_issue": None if issue is None else issue.kind,
            "last_sync": view.last_sync,
            "issues": [{"kind": i.kind, "detail": getattr(i, "detail", "")} for i in view.issues],
            "transports": {t.name: {"last_sync": t.last_sync, "issues": [i.kind for i in t.issues]}
                           for t in view.transports},
            "conflicts": view.conflicts,
        }

    # commands
    def pair(self) -> dict[str, Any]:
        from localvault.app.sync_view import begin_pairing_job
        from localvault.sync.pairing import offer_qr_payload

        offer = self.job(begin_pairing_job(self.advertise, self.port, self.install_id))
        self.service.arm_enrollment(offer)
        self.wait_idle()
        endpoint, issue = self.service.lan_listen_state()
        self.offers[offer.offer_id] = offer
        return {"offer_id": offer.offer_id, "code": offer.code, "qr": offer_qr_payload(offer),
                "expires_at": offer.expires_at, "advertised": f"{self.advertise}:{self.port}",
                "listening": None if endpoint is None else f"{endpoint.host}:{endpoint.port}",
                "listen_issue": None if issue is None else issue.kind}

    def paired(self, offer_id: str) -> dict[str, Any]:
        peer = self.service.enrollment_peer(offer_id)
        return {"device_id": self.service.enrollment_result(offer_id),
                "fingerprint": getattr(peer, "fingerprint", None)}

    # sync v2: the inviting device answers the enrollment only after Accept (or Decline)
    def pending(self, offer_id: str) -> dict[str, Any] | None:
        p = self.service.pending_enrollment(offer_id)
        return None if p is None else {"name": p.name, "code": p.code, "seconds_left": round(p.seconds_left(), 1)}

    def accept(self, offer_id: str, code: str | None = None) -> dict[str, Any]:
        """Wait for the phone's request, show its name and code, check *code* (the phone's screen) if given, Accept."""
        deadline = time.time() + 60
        while (p := self.service.pending_enrollment(offer_id)) is None:
            if time.time() > deadline:
                raise TimeoutError("no enrollment request is waiting for Accept")
            time.sleep(0.1)
        shown = {"name": p.name, "code": p.code}
        print(f"ACCEPT? {shown}", flush=True)
        if code is not None and code.replace(" ", "") != p.code:
            self.service.decide_enrollment(offer_id, False)
            raise ValueError(f"codes differ: phone {code}, desktop {p.code}; declined")
        accepted = self.service.decide_enrollment(offer_id, True)
        deadline = time.time() + 30
        while accepted and self.service.enrollment_result(offer_id) is None and time.time() < deadline:
            time.sleep(0.1)
        return {**shown, "accepted": accepted, "device_id": self.service.enrollment_result(offer_id)}

    def decline(self, offer_id: str) -> dict[str, Any]:
        declined = self.service.decide_enrollment(offer_id, False)
        return {"declined": declined, "recorded": self.service.enrollment_declined(offer_id)}

    def _find(self, session: Any, ns: str, name: str) -> dict[str, Any]:
        key = "label" if ns == "entries" else "title"
        for row in session._payload.get(ns, []):
            if row.get(key) == name:
                return row
        raise KeyError(f"no {ns[:-1]} named {name!r}")

    def add_login(self, label: str, url: str, user: str, password: str) -> str:
        return self.job(lambda s, lease, gate: s.create_web_login(urls=[{"url": url}], username=user,
                                                                   password=password, label=label))

    def add_note(self, title: str, body: str) -> str:
        return self.job(lambda s, lease, gate: s.item_service.create_note(title, body))

    def edit_note(self, title: str, body: str) -> bool:
        return self.job(lambda s, lease, gate: s.item_service.update_item(self._find(s, "items", title)["id"],
                                                                           body=body))

    def edit_login(self, label: str, password: str) -> bool:
        return self.job(lambda s, lease, gate: s.update_entry_fields(self._find(s, "entries", label)["id"],
                                                                      password=password))

    def sync(self) -> dict[str, Any]:
        self.service.run_now()
        self.wait_idle()
        return self.status()

    def add_folder(self, password: str) -> dict[str, Any]:
        from localvault.app.sync_view import add_folder_job, default_device_name

        folder = self.data_dir / "Folder"
        folder.mkdir(exist_ok=True)
        report = self.job(add_folder_job(str(folder), password, default_device_name(), self.install_id),
                          run_after=True)
        self.wait_idle()
        return {"folder": str(folder), "issues": [i.kind for i in getattr(report, "issues", ())],
                "status": self.status()}

    def check_folder(self, folder: str) -> dict[str, Any]:
        from localvault.sync import keyring as kr
        from localvault.sync.folder_transport import FolderSync
        from localvault.sync.group import GroupKey, decode_view
        from localvault.sync.vault_bridge import load_sync_state, normal_form
        from localvault.updates import canonical_json

        state = self.job(lambda s, lease, gate: load_sync_state(s))
        fs = FolderSync(folder, install_id=self.install_id)
        ring = kr.parse_keyring(fs.keyring_path.read_bytes())
        kr.verify_keyring_structure(ring)
        key = GroupKey(state.group_id, state.epoch, state.key)
        devices = []
        for path in sorted(fs.devices_dir.iterdir()):
            device_id = path.name.removesuffix(".lgksync")
            view = decode_view(key, path.read_bytes(), expected_device_id=device_id)
            live = [s for s in view.states if not s.deleted]
            normal = all(canonical_json(normal_form(s.item["ns"], s.item["record"])) == canonical_json(s.item["record"])
                         for s in live)
            devices.append({"device_id": device_id, "own": device_id == state.device_id,
                            "counter": view.header["counter"], "states": len(view.states),
                            "live_titles": sorted(str(s.item["record"].get("label") or s.item["record"].get("title"))
                                                  for s in live),
                            "records_are_normal_form": normal})
        return {"keyring_members": [m["device_id"] for m in ring["members"]], "epoch": ring["epoch"],
                "group_matches": ring["group_id"] == state.group_id, "devices": devices}

    def restore(self, path: str, password: str, fresh: bool) -> dict[str, Any]:
        from localvault.phone_backup import inspect_phone_backup, read_phone_backup
        from localvault.sync.phone_restore import plan_restore, restore
        from localvault.vault import create_vault

        raw = Path(path).read_bytes()
        header = inspect_phone_backup(raw)
        backup = read_phone_backup(raw, password)
        now = int(time.time())
        info = {"platform": header.platform, "created_at": header.created_at, "kdf": dict(header.kdf),
                "device_id": backup.device_id, "app_version": backup.app_version, "pro_hint": backup.pro_hint,
                "states": len(backup.states)}

        def run(session: Any, lease: Any) -> dict[str, Any]:
            plan = plan_restore(session, lease, backup, now=now)
            report = restore(session, lease, plan, now=now)
            return {"plan": {"new": plan.new, "updated": plan.updated, "unchanged": plan.unchanged,
                             "held_back": plan.held_back, "skipped": plan.skipped, "deleted": plan.deleted},
                    "report": {"new": report.new, "updated": report.updated, "held_back": report.held_back,
                               "skipped": report.skipped, "deleted": report.deleted, "issues": list(report.issues)}}

        if fresh:
            target = self.data_dir / f"restore-{uuid.uuid4().hex[:8]}.json"
            other = create_vault(target, MASTER, kdf_overrides=TEST_KDF)

            class Lease:
                @staticmethod
                def check() -> None:
                    return None

            result = run(other, Lease())
            result["items"] = self.items(other)
            result["vault"] = str(target)
        else:
            result = self.job(lambda s, lease, gate: run(s, lease))
            result["items"] = self.items()
        return {"backup": info, **result}

    def stop(self) -> None:
        self.service.stop()
        self.alive = False


def serve(args: argparse.Namespace) -> int:
    data_dir = _scratch_dir(args.data_dir)
    _prepare_env(data_dir)
    control = data_dir / "control"
    control.mkdir(exist_ok=True)
    for old in control.iterdir():
        old.unlink()
    peer = Peer(data_dir, args.port, args.advertise)
    print(f"LIVE_PEER_READY data={data_dir} listen={LISTEN_HOST}:{args.port} advertise={args.advertise}", flush=True)
    handlers = {
        "status": lambda: peer.status(),
        "pair": lambda: peer.pair(),
        "paired": lambda offer_id: peer.paired(offer_id),
        "pending": lambda offer_id: peer.pending(offer_id),
        "accept": lambda offer_id, *code: peer.accept(offer_id, code[0] if code else None),
        "decline": lambda offer_id: peer.decline(offer_id),
        "add-login": lambda *a: peer.add_login(*a),
        "add-note": lambda *a: peer.add_note(*a),
        "edit-note": lambda *a: peer.edit_note(*a),
        "edit-login": lambda *a: peer.edit_login(*a),
        "sync": lambda: peer.sync(),
        "add-folder": lambda password: peer.add_folder(password),
        "check-folder": lambda folder: peer.check_folder(folder),
        "restore": lambda path, password, *rest: peer.restore(path, password, bool(rest and rest[0] == "fresh")),
    }
    try:
        while True:
            for cmd_file in sorted(control.glob("*.cmd")):
                argv = json.loads(cmd_file.read_text(encoding="utf-8"))
                out = cmd_file.with_suffix(".out")
                print(f"> {argv[0]}", flush=True)
                if argv[0] == "quit":
                    out.write_text(json.dumps({"ok": True}), encoding="utf-8")
                    cmd_file.unlink()
                    return 0
                try:
                    answer = {"ok": True, "result": handlers[argv[0]](*argv[1:])}
                except Exception as exc:  # noqa: BLE001 - reported to the client
                    answer = {"ok": False, "error": f"{type(exc).__name__}: {exc}",
                              "trace": traceback.format_exc()}
                tmp = out.with_suffix(".tmp")
                tmp.write_text(json.dumps(answer, indent=2, default=str), encoding="utf-8")
                os.replace(tmp, out)
                cmd_file.unlink()
            time.sleep(0.2)
    finally:
        peer.stop()
        print("LIVE_PEER_STOPPED", flush=True)


def send(args: argparse.Namespace) -> int:
    data_dir = _scratch_dir(args.data_dir)
    control = data_dir / "control"
    name = f"{time.time_ns()}"
    tmp = control / f"{name}.tmp"
    tmp.write_text(json.dumps([args.command, *args.args]), encoding="utf-8")
    os.replace(tmp, control / f"{name}.cmd")
    out = control / f"{name}.out"
    deadline = time.time() + JOB_TIMEOUT + 30
    while not out.exists():
        if time.time() > deadline:
            print("no answer from the peer", file=sys.stderr)
            return 2
        time.sleep(0.1)
    text = out.read_text(encoding="utf-8")
    out.unlink()
    print(text)
    return 0 if json.loads(text).get("ok") else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--data-dir", required=True)
    s.add_argument("--port", type=int, default=47931)
    s.add_argument("--advertise", default="10.0.2.2", help="the address the phone dials (emulator: 10.0.2.2)")
    c = sub.add_parser("send")
    c.add_argument("--data-dir", required=True)
    c.add_argument("command")
    c.add_argument("args", nargs="*")
    args = parser.parse_args()
    return serve(args) if args.mode == "serve" else send(args)


if __name__ == "__main__":
    raise SystemExit(main())
