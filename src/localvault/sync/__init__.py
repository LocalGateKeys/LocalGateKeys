"""Opt-in, Windows-LAN-only LocalGateKeys sync primitives.

Importing this package has no side effects: it does not discover peers, bind a
socket, read settings, or start a background worker.
"""

from .conflicts import (
    ConflictCopy,
    ConflictError,
    ConflictStore,
    MergeResult,
    deterministic_conflict_id,
    merge_record_pair,
    merge_records,
    resolve_conflict,
)
from .manifest import (
    Acknowledgement,
    AttachmentDelta,
    AttachmentMeta,
    Manifest,
    ManifestError,
    ManifestReplayError,
    Revision,
    SyncDelta,
    SyncRecord,
    apply_delta,
    build_manifest,
    decrypt_catalog_record,
    encrypt_catalog_record,
    make_attachment_delta,
)
from .pairing import (
    DeviceIdentity,
    PairedDevice,
    PairingAuthenticationError,
    PairingCodeError,
    PairingConfirmation,
    PairingError,
    PairingExpired,
    PairingOffer,
    PairingReplayError,
    PairingSession,
    complete_pairing,
    confirm_pairing_offer,
    create_pairing_offer,
)
from .state import PeerRevoked, SyncDisabled, SyncState, SyncStateError
from .transport import (
    AuthenticationError,
    CancellationToken,
    FrameError,
    FrameTooLarge,
    LANEndpoint,
    LANTransport,
    LanTransport,
    ReplayError,
    RetryBackoff,
    SecureChannel,
    SessionHello,
    SyncTransport,
    TransportCancelled,
    TransportError,
    TransportTimeout,
    create_session_hello,
    decode_frame,
    encode_frame,
    establish_channel,
    verify_session_hello,
)

__all__ = [
    "DeviceIdentity", "PairedDevice", "PairingOffer", "PairingConfirmation", "PairingSession",
    "PairingError", "PairingExpired", "PairingCodeError", "PairingAuthenticationError",
    "PairingReplayError", "create_pairing_offer", "confirm_pairing_offer", "complete_pairing",
    "Revision", "SyncRecord", "AttachmentMeta", "AttachmentDelta", "Acknowledgement",
    "Manifest", "SyncDelta", "ManifestError", "ManifestReplayError", "build_manifest",
    "make_attachment_delta", "apply_delta", "encrypt_catalog_record", "decrypt_catalog_record",
    "ConflictCopy", "MergeResult", "ConflictStore", "ConflictError",
    "deterministic_conflict_id", "merge_record_pair", "merge_records", "resolve_conflict",
    "SyncState", "SyncStateError", "SyncDisabled", "PeerRevoked",
    "LANEndpoint", "SyncTransport", "LANTransport", "LanTransport", "SessionHello",
    "SecureChannel", "AuthenticationError", "ReplayError", "FrameError", "FrameTooLarge",
    "TransportError", "TransportTimeout", "TransportCancelled", "CancellationToken", "RetryBackoff",
    "encode_frame", "decode_frame", "create_session_hello", "verify_session_hello",
    "establish_channel",
]
