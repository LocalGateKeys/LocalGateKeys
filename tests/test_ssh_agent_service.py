"""SSH agent service: allow-listed vault keys, approvals, unlock first, deadline (test-only keys in tests/vectors/ssh)."""
from __future__ import annotations

import base64
import copy
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace as NS

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from localvault.local_clients import Approvals, ClientIdentity
from localvault.ssh_agent.service import SshAgentService
from localvault.ssh_keys import load_private_key, ssh_string

VECTORS = Path(__file__).parent / "vectors" / "ssh"
EXPECTED = json.loads((VECTORS / "expected.json").read_text(encoding="utf-8"))
PASS = EXPECTED["passphrase"]
DATA = base64.b64decode(EXPECTED["sign_data_b64"])
CLIENT = ClientIdentity(4242, r"C:\Windows\System32\OpenSSH\ssh.exe", (), None, (10, 100))


def _text(name: str) -> str:
    return (VECTORS / name).read_text(encoding="ascii")


def _blob(name: str) -> bytes:
    return base64.b64decode(EXPECTED["keys"][name]["public_line"].split()[1])


def _item(item_id: str, key_file: str, pub_name: str, passphrase: str = "", kind: str = "ssh_key") -> dict:
    return {"id": item_id, "kind": kind, "title": f"Title {item_id}",
            "payload": {"private_key": _text(key_file), "passphrase": passphrase,
                        "public_key": EXPECTED["keys"][pub_name]["public_line"]}}


class FakeItems:
    def __init__(self, items: list[dict]) -> None:
        self.items = items

    def get_item(self, item_id, *, include_protected=False):
        for item in self.items:
            if item["id"] == item_id:
                result = copy.deepcopy(item)
                if not include_protected:
                    result["payload"].pop("private_key", None)
                    result["payload"].pop("passphrase", None)
                return result
        return None

    def reveal_secret(self, item_id, field, *, intent=None):
        assert intent and field in ("private_key", "passphrase")
        item = next(item for item in self.items if item["id"] == item_id)
        assert item["kind"] == "ssh_key"
        return item["payload"][field]


class FakeHost:
    def __init__(self, *, unlocked=True, allow=("ed", "rsa"), approve=True) -> None:
        self.unlocked = unlocked
        self.vault_lock = threading.RLock()
        self.settings = NS(developer_ssh_keys=list(allow))
        self.items = FakeItems([_item("ed", "ed25519.key", "ed25519"),
                                _item("rsa", "rsa3072_enc.key", "rsa3072", PASS),
                                _item("ec", "ecdsa256.key", "ecdsa256"),
                                _item("note", "ed25519.key", "ed25519", kind="note")])
        self.approve = approve
        self.asked: list = []
        self.unlock_calls = 0
        self.unlock_result = True

    @property
    def session(self):
        return NS(item_service=self.items) if self.unlocked else None

    def run_on_ui(self, fn, timeout=90.0):
        with self.vault_lock:
            return fn()

    def ensure_unlocked(self):
        self.unlock_calls += 1
        if self.unlock_result:
            self.unlocked = True
        return self.unlocked

    def approve_local_client(self, request):
        self.asked.append(request)
        result = self.approve(request) if callable(self.approve) else self.approve
        return result


def _service(host, tmp_path=None, **kw) -> SshAgentService:
    known = (tmp_path / "known_hosts") if tmp_path is not None else Path("Z:/nonexistent/known_hosts")
    return SshAgentService(host, known_hosts=known, **kw)


def test_identities_only_allowlisted():
    host = FakeHost(allow=("ed", "rsa", "note", "missing"))
    identities = _service(host).identities()
    assert [blob for blob, _ in identities] == [_blob("ed25519"), _blob("rsa3072")]
    assert identities[0][1] == "test-only ed25519"  # the public key's own comment, never the item title
    assert host.asked == [] and host.unlock_calls == 0


def test_identities_empty_when_locked():
    host = FakeHost(unlocked=False)
    assert _service(host).identities() == []
    assert host.unlock_calls == 0 and host.asked == []


def test_sign_after_approval():
    host = FakeHost()
    signature = _service(host).sign(_blob("ed25519"), DATA, 0, CLIENT, "github.com")
    assert signature == load_private_key(_text("ed25519.key"), None).sign(DATA)
    request = host.asked[0]
    assert request.kind == "ssh_sign" and request.item_id == "ed" and request.item_title == "Title ed"
    assert request.client is CLIENT and "github.com" in request.detail
    rsa = _service(host).sign(_blob("rsa3072"), DATA, 2, CLIENT, None)
    assert rsa == load_private_key(_text("rsa3072.key"), None).sign(DATA, 2)
    assert host.asked[1].detail == ""


def test_sign_denied_returns_none():
    host = FakeHost(approve=False)
    assert _service(host).sign(_blob("ed25519"), DATA, 0, CLIENT, None) is None
    assert len(host.asked) == 1


def test_sign_unknown_blob_none():
    host = FakeHost()
    service = _service(host)
    assert service.sign(_blob("ecdsa256"), DATA, 0, CLIENT, None) is None  # in the vault but not offered
    assert service.sign(b"\x00\x00\x00\x03abc", DATA, 0, CLIENT, None) is None
    assert host.asked == []


def test_sign_while_locked_unlocks_first():
    host = FakeHost(unlocked=False)
    order = []
    host.approve = lambda req: order.append(("approve", host.unlocked)) or True
    signature = _service(host).sign(_blob("ed25519"), DATA, 0, CLIENT, None)
    assert host.unlock_calls == 1 and order == [("approve", True)]
    assert signature is not None


def test_sign_cancel_returns_failure():
    host = FakeHost(unlocked=False)
    host.unlock_result = False  # the user closed the unlock popup
    assert _service(host).sign(_blob("ed25519"), DATA, 0, CLIENT, None) is None
    assert host.asked == []


def test_sign_deadline_returns_failure():
    host = FakeHost()
    gate = threading.Event()
    host.approve = lambda req: gate.wait(5) or True  # the prompt stays open
    started = time.monotonic()
    try:
        assert _service(host, deadline=0.3).sign(_blob("ed25519"), DATA, 0, CLIENT, None) is None
        assert time.monotonic() - started < 2
    finally:
        gate.set()


def test_sign_refused_when_locked_or_removed_during_prompt():
    host = FakeHost()
    host.approve = lambda req: setattr(host, "unlocked", False) or True
    assert _service(host).sign(_blob("ed25519"), DATA, 0, CLIENT, None) is None
    host = FakeHost()
    host.approve = lambda req: host.settings.developer_ssh_keys.remove("ed") or True
    assert _service(host).sign(_blob("ed25519"), DATA, 0, CLIENT, None) is None


def _two_parallel_signs(remember: bool) -> tuple[int, int, list]:
    """Two signatures at once through a real Approvals queue: (peak prompts open at once, prompts, results)."""
    host = FakeHost()
    approvals = Approvals()
    active, peak, asks = [0], [0], []
    lock = threading.Lock()

    def ask(req):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
            asks.append(req)
        # The vault lock stays free while the user decides.
        assert host.vault_lock.acquire(timeout=1)
        host.vault_lock.release()
        time.sleep(0.15)
        with lock:
            active[0] -= 1
        return True, remember

    host.approve = lambda req: approvals.check_or_ask(req, ask, time.monotonic())
    service = _service(host)
    results: list = []

    def sign():
        results.append(service.sign(_blob("ed25519"), DATA, 0, CLIENT, None))
    threads = [threading.Thread(target=sign) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    return peak[0], len(asks), results


def test_parallel_sign_requests_queue():
    peak, asks, results = _two_parallel_signs(remember=False)
    assert len(results) == 2 and all(results) and peak == 1 and asks == 2  # two prompts, one after the other
    peak, asks, results = _two_parallel_signs(remember=True)
    assert len(results) == 2 and all(results) and peak == 1 and asks == 1  # "remember" covers the second


def test_sha1_flag_refused():
    host = FakeHost()
    assert _service(host).sign(_blob("rsa3072"), DATA, 0, CLIENT, None) is None
    assert host.asked == []  # refused before any prompt


def test_known_hosts_names_bound_host(tmp_path):
    host_key = ed25519.Ed25519PrivateKey.generate()
    raw = host_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    blob = ssh_string(b"ssh-ed25519") + ssh_string(raw)
    line = base64.b64encode(blob).decode()
    other = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    other_blob = ssh_string(b"ssh-ed25519") + ssh_string(other)
    (tmp_path / "known_hosts").write_text(
        "# comment\n"
        f"|1|abc=|def= ssh-ed25519 {base64.b64encode(other_blob).decode()}\n"
        f"@revoked evil.example ssh-ed25519 {line}\n"
        "garbage\n"
        f"github.com,140.82.121.4 ssh-ed25519 {line} some comment\n", encoding="utf-8")
    service = _service(FakeHost(), tmp_path)
    assert service.host_name_for(blob) == "github.com"
    hashed_only = service.host_name_for(other_blob)
    assert hashed_only.startswith("SHA256:")
    (tmp_path / "known_hosts").write_text(f"[git.example.com]:2222 ssh-ed25519 {line}\n", encoding="utf-8")
    assert service.host_name_for(blob) == "git.example.com:2222"
    (tmp_path / "known_hosts").unlink()
    assert service.host_name_for(blob).startswith("SHA256:")


def test_session_bind_signature_verified(tmp_path):
    host_key = ed25519.Ed25519PrivateKey.generate()
    raw = host_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    blob = ssh_string(b"ssh-ed25519") + ssh_string(raw)
    session_id = b"S" * 32
    signature = ssh_string(b"ssh-ed25519") + ssh_string(host_key.sign(session_id))
    service = _service(FakeHost(), tmp_path)
    assert service.verify_bind(blob, session_id, signature) is True
    assert service.verify_bind(blob, b"X" * 32, signature) is False
    assert service.verify_bind(b"junk", session_id, signature) is False
    ec_key = load_private_key(_text("ecdsa256.key"), None)
    assert service.verify_bind(ec_key.public_blob, session_id, ec_key.sign(session_id)) is True
    rsa_key = load_private_key(_text("rsa3072.key"), None)
    assert service.verify_bind(rsa_key.public_blob, session_id, rsa_key.sign(session_id, 4)) is True


def test_session_bind_nistp521_host_key_verified(tmp_path):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    from localvault.ssh_keys import ssh_mpint

    host_key = ec.generate_private_key(ec.SECP521R1())
    point = host_key.public_key().public_bytes(serialization.Encoding.X962,
                                               serialization.PublicFormat.UncompressedPoint)
    blob = ssh_string(b"ecdsa-sha2-nistp521") + ssh_string(b"nistp521") + ssh_string(point)
    session_id = b"S" * 32
    r, s_ = decode_dss_signature(host_key.sign(session_id, ec.ECDSA(hashes.SHA512())))
    signature = ssh_string(b"ecdsa-sha2-nistp521") + ssh_string(ssh_mpint(r) + ssh_mpint(s_))
    service = _service(FakeHost(), tmp_path)
    assert service.verify_bind(blob, session_id, signature) is True
    assert service.verify_bind(blob, b"X" * 32, signature) is False
