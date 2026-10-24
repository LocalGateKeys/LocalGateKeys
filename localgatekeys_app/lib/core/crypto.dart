import 'dart:convert';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Thrown when a password, recovery code or ciphertext does not authenticate.
class VaultAuthError implements Exception {
  const VaultAuthError([this.message = 'Wrong password or damaged data']);
  final String message;
  @override
  String toString() => message;
}

/// Argon2id parameters stored in the vault header so they can be raised later.
class KdfParams {
  const KdfParams({
    required this.salt,
    this.memory = 65536,
    this.iterations = 3,
    this.parallelism = 1,
  });

  factory KdfParams.fresh() => KdfParams(salt: VaultCrypto.randomBytes(16));

  factory KdfParams.fromJson(Map<String, dynamic> json) {
    if (json['alg'] != 'argon2id') {
      throw const FormatException('Unsupported key derivation');
    }
    return KdfParams(
      salt: base64Decode(json['salt'] as String),
      memory: json['m'] as int,
      iterations: json['t'] as int,
      parallelism: json['p'] as int,
    );
  }

  final List<int> salt;
  final int memory;
  final int iterations;
  final int parallelism;

  Map<String, dynamic> toJson() => {
        'alg': 'argon2id',
        'm': memory,
        't': iterations,
        'p': parallelism,
        'salt': base64Encode(salt),
      };
}

/// All cryptography used by the vault: Argon2id for key derivation and
/// XChaCha20-Poly1305 for authenticated encryption. Sealed blobs are laid out
/// as nonce (24) || ciphertext || tag (16).
class VaultCrypto {
  VaultCrypto._();

  static final Random _rng = Random.secure();
  static const int _nonceLength = 24;
  static const int _tagLength = 16;

  static Uint8List randomBytes(int length) =>
      Uint8List.fromList(List<int>.generate(length, (_) => _rng.nextInt(256)));

  static Future<List<int>> deriveKey(String secret, KdfParams params) async {
    final bytes = utf8.encode(secret);
    // Argon2 is CPU-heavy; keep the UI responsive.
    return Isolate.run(() async {
      final kdf = Argon2id(
        parallelism: params.parallelism,
        memory: params.memory,
        iterations: params.iterations,
        hashLength: 32,
      );
      final key = await kdf.deriveKey(
        secretKey: SecretKey(bytes),
        nonce: params.salt,
      );
      return key.extractBytes();
    });
  }

  static Future<Uint8List> seal(List<int> key, List<int> plaintext, String aad) =>
      _sealSync(key, plaintext, aad);

  static Future<Uint8List> open(List<int> key, List<int> sealed, String aad) =>
      _openSync(key, sealed, aad);

  /// Same as [seal] but on a background isolate, for large documents.
  static Future<Uint8List> sealLarge(List<int> key, Uint8List plaintext, String aad) =>
      plaintext.length < 256 * 1024
          ? _sealSync(key, plaintext, aad)
          : Isolate.run(() => _sealSync(key, plaintext, aad));

  static Future<Uint8List> openLarge(List<int> key, Uint8List sealed, String aad) =>
      sealed.length < 256 * 1024
          ? _openSync(key, sealed, aad)
          : Isolate.run(() => _openSync(key, sealed, aad));

  static Future<Uint8List> _sealSync(List<int> key, List<int> plaintext, String aad) async {
    final algorithm = Xchacha20.poly1305Aead();
    final nonce = randomBytes(_nonceLength);
    final box = await algorithm.encrypt(
      plaintext,
      secretKey: SecretKey(key),
      nonce: nonce,
      aad: utf8.encode(aad),
    );
    final out = BytesBuilder(copy: false)
      ..add(box.nonce)
      ..add(box.cipherText)
      ..add(box.mac.bytes);
    return out.toBytes();
  }

  static Future<Uint8List> _openSync(List<int> key, List<int> sealed, String aad) async {
    if (sealed.length < _nonceLength + _tagLength) throw const VaultAuthError();
    final algorithm = Xchacha20.poly1305Aead();
    final box = SecretBox(
      sealed.sublist(_nonceLength, sealed.length - _tagLength),
      nonce: sealed.sublist(0, _nonceLength),
      mac: Mac(sealed.sublist(sealed.length - _tagLength)),
    );
    try {
      final clear = await algorithm.decrypt(
        box,
        secretKey: SecretKey(key),
        aad: utf8.encode(aad),
      );
      return Uint8List.fromList(clear);
    } on SecretBoxAuthenticationError {
      throw const VaultAuthError();
    }
  }

  /// 25 characters of Crockford base32 (125 bits), grouped for reading aloud.
  static String newRecoveryCode() {
    const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    final chars = List.generate(25, (_) => alphabet[_rng.nextInt(alphabet.length)]);
    final groups = <String>[];
    for (var i = 0; i < chars.length; i += 5) {
      groups.add(chars.sublist(i, i + 5).join());
    }
    return groups.join('-');
  }

  /// Canonical form so users can type the code with or without dashes,
  /// in lower case, or with the easily confused letters I/L/O.
  static String normalizeRecoveryCode(String input) => input
      .toUpperCase()
      .replaceAll(RegExp(r'[\s-]'), '')
      .replaceAll('O', '0')
      .replaceAll(RegExp('[IL]'), '1');
}
