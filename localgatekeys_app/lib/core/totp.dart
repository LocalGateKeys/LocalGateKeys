import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

class TotpConfig {
  const TotpConfig({
    required this.secret,
    this.digits = 6,
    this.period = 30,
    this.algorithm = 'SHA1',
    this.issuer = '',
    this.account = '',
  });

  final List<int> secret;
  final int digits;
  final int period;
  final String algorithm;
  final String issuer;
  final String account;

  /// Accepts a bare base32 secret or an `otpauth://totp/...` link.
  /// Returns null when the input cannot be used.
  static TotpConfig? parse(String input) {
    final text = input.trim();
    if (text.isEmpty) return null;
    if (text.toLowerCase().startsWith('otpauth://')) {
      final uri = Uri.tryParse(text);
      if (uri == null || uri.host.toLowerCase() != 'totp') return null;
      final secret = base32Decode(uri.queryParameters['secret'] ?? '');
      if (secret == null || secret.isEmpty) return null;
      final label = Uri.decodeComponent(uri.path.replaceFirst('/', ''));
      final parts = label.split(':');
      final digits = int.tryParse(uri.queryParameters['digits'] ?? '') ?? 6;
      final period = int.tryParse(uri.queryParameters['period'] ?? '') ?? 30;
      final algorithm = (uri.queryParameters['algorithm'] ?? 'SHA1').toUpperCase();
      if (!const {6, 7, 8}.contains(digits) || period < 1 || period > 300) return null;
      if (!const {'SHA1', 'SHA256', 'SHA512'}.contains(algorithm)) return null;
      return TotpConfig(
        secret: secret,
        digits: digits,
        period: period,
        algorithm: algorithm,
        issuer: uri.queryParameters['issuer'] ?? (parts.length > 1 ? parts.first : ''),
        account: parts.last,
      );
    }
    final secret = base32Decode(text);
    if (secret == null || secret.length < 10) return null;
    return TotpConfig(secret: secret);
  }

  Future<String> codeAt(DateTime time) async {
    final counter = time.millisecondsSinceEpoch ~/ 1000 ~/ period;
    return generateHotp(secret, counter, digits: digits, algorithm: algorithm);
  }

  int secondsRemaining(DateTime time) => period - (time.millisecondsSinceEpoch ~/ 1000) % period;
}

Future<String> generateHotp(List<int> secret, int counter,
    {int digits = 6, String algorithm = 'SHA1'}) async {
  final message = ByteData(8)..setInt64(0, counter);
  final hmac = switch (algorithm) {
    'SHA256' => Hmac.sha256(),
    'SHA512' => Hmac.sha512(),
    _ => Hmac.sha1(),
  };
  final mac = await hmac.calculateMac(message.buffer.asUint8List(), secretKey: SecretKey(secret));
  final hash = mac.bytes;
  final offset = hash.last & 0x0f;
  final binary = ((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff);
  var modulus = 1;
  for (var i = 0; i < digits; i++) {
    modulus *= 10;
  }
  return (binary % modulus).toString().padLeft(digits, '0');
}

List<int>? base32Decode(String input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  final clean = input.toUpperCase().replaceAll(RegExp(r'[\s=-]'), '');
  if (clean.isEmpty) return null;
  var buffer = 0;
  var bits = 0;
  final out = <int>[];
  for (final ch in clean.split('')) {
    final value = alphabet.indexOf(ch);
    if (value < 0) return null;
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.add((buffer >> bits) & 0xff);
    }
  }
  return out;
}
