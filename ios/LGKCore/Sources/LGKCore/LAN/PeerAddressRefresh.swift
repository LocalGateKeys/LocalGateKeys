import Crypto
import Foundation

/// "Find again" (plan 2026-10-29-sync-ip-change, section 4): a fresh pairing QR from the already-paired host
/// only moves its pinned address. Nothing is enrolled: the QR's device id, group, both public keys and the
/// certificate fingerprint must equal the pinned ones (keys compared in constant time), else it is refused. Expiry does not matter here, the address is only a hint and the session
/// hello still checks the pinned keys.
public enum PeerAddressRefresh {
    public enum Refusal: Error, Equatable, Sendable {
        /// Not a LocalGateKeys pairing code.
        case notAPairingCode
        /// A code from another device or group: keys differ from the paired PC.
        case otherDevice
        /// The code's address is not a private LAN address.
        case notLAN
    }

    /// The pinned peer with the QR's address, or a `Refusal`.
    public static func refreshed(_ peer: PinnedPeer, qrText: String) throws -> PinnedPeer {
        let offer: PairingOffer
        do { offer = try PairingOffer.parseQR(qrText.trimmingCharacters(in: .whitespacesAndNewlines)) } catch {
            throw Refusal.notAPairingCode
        }
        let pinnedFingerprint = lowerHex(Array(SHA256.hash(data: peer.signingPublic)))
        // Every key is compared before any is judged, so the time taken does not say which one differed.
        let signing = Keyring.constantTimeEqual(offer.inviterSigningPublic, peer.signingPublic)
        let exchange = Keyring.constantTimeEqual(offer.inviterExchangePublic, peer.exchangePublic)
        let fingerprint = Keyring.constantTimeEqual(Array(offer.certificateFingerprint.utf8), Array(pinnedFingerprint.utf8))
        guard offer.inviterDeviceID == peer.deviceID, offer.groupID == peer.groupID, signing, exchange, fingerprint
        else { throw Refusal.otherDevice }
        guard LanAddress.isLAN(offer.endpoint.host) else { throw Refusal.notLAN }
        return PinnedPeer(deviceID: peer.deviceID, groupID: peer.groupID, signingPublic: peer.signingPublic,
                          exchangePublic: peer.exchangePublic, endpoint: offer.endpoint)
    }
}
