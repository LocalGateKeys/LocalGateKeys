import 'dart:math';

class GeneratorOptions {
  const GeneratorOptions({
    this.length = 20,
    this.upper = true,
    this.lower = true,
    this.digits = true,
    this.symbols = true,
    this.avoidAmbiguous = true,
  });

  final int length;
  final bool upper;
  final bool lower;
  final bool digits;
  final bool symbols;
  final bool avoidAmbiguous;

  GeneratorOptions copyWith({
    int? length,
    bool? upper,
    bool? lower,
    bool? digits,
    bool? symbols,
    bool? avoidAmbiguous,
  }) =>
      GeneratorOptions(
        length: length ?? this.length,
        upper: upper ?? this.upper,
        lower: lower ?? this.lower,
        digits: digits ?? this.digits,
        symbols: symbols ?? this.symbols,
        avoidAmbiguous: avoidAmbiguous ?? this.avoidAmbiguous,
      );
}

final Random _rng = Random.secure();

String generatePassword(GeneratorOptions o) {
  const ambiguous = 'Il1O0o';
  String filter(String s) =>
      o.avoidAmbiguous ? s.split('').where((c) => !ambiguous.contains(c)).join() : s;
  final sets = <String>[
    if (o.lower) filter('abcdefghijklmnopqrstuvwxyz'),
    if (o.upper) filter('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
    if (o.digits) filter('0123456789'),
    if (o.symbols) '!@#\$%^&*()-_=+[]{};:,.?',
  ];
  if (sets.isEmpty) sets.add(filter('abcdefghijklmnopqrstuvwxyz'));
  final all = sets.join();
  final length = max(o.length, sets.length);
  // One character from each chosen set, the rest from the full pool, then shuffle.
  final chars = <String>[
    for (final s in sets) s[_rng.nextInt(s.length)],
    for (var i = sets.length; i < length; i++) all[_rng.nextInt(all.length)],
  ]..shuffle(_rng);
  return chars.join();
}

enum Strength { veryWeak, weak, fair, strong, veryStrong }

extension StrengthInfo on Strength {
  String get label => switch (this) {
        Strength.veryWeak => 'Very weak',
        Strength.weak => 'Weak',
        Strength.fair => 'Fair',
        Strength.strong => 'Strong',
        Strength.veryStrong => 'Very strong',
      };

  double get fraction => (index + 1) / Strength.values.length;
  bool get isWeak => index <= Strength.weak.index;
}

const _common = {
  'password', 'passw0rd', '123456', '12345678', '123456789', 'qwerty', 'qwertyuiop',
  'letmein', 'welcome', 'admin', 'iloveyou', 'monkey', 'dragon', 'football', 'abc123',
  'sunshine', 'princess', 'baseball', 'master', 'shadow', 'trustno1', '111111', '000000',
};

/// Estimated entropy in bits, with penalties for common patterns.
double estimateEntropy(String password) {
  if (password.isEmpty) return 0;
  final lower = password.toLowerCase();
  if (_common.contains(lower) || _common.any((w) => lower.startsWith(w) && lower.length <= w.length + 2)) {
    return 10;
  }
  var pool = 0;
  if (password.contains(RegExp('[a-z]'))) pool += 26;
  if (password.contains(RegExp('[A-Z]'))) pool += 26;
  if (password.contains(RegExp('[0-9]'))) pool += 10;
  if (password.contains(RegExp('[^a-zA-Z0-9]'))) pool += 32;
  // Count characters that are not simple repeats or sequences of the previous one.
  var effective = 1.0;
  for (var i = 1; i < password.length; i++) {
    final a = password.codeUnitAt(i - 1);
    final b = password.codeUnitAt(i);
    effective += (a == b || (b - a).abs() == 1) ? 0.3 : 1.0;
  }
  final unique = password.split('').toSet().length;
  effective = min(effective, unique * 2.0);
  return effective * (log(pool) / ln2);
}

Strength strengthOf(String password) {
  final bits = estimateEntropy(password);
  if (bits < 28) return Strength.veryWeak;
  if (bits < 45) return Strength.weak;
  if (bits < 60) return Strength.fair;
  if (bits < 80) return Strength.strong;
  return Strength.veryStrong;
}
