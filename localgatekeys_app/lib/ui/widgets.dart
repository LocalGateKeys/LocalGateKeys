import 'dart:async';
import 'dart:math';

import 'package:flutter/material.dart';

import '../core/models.dart';
import '../core/password_tools.dart';
import '../core/totp.dart';
import 'theme.dart';

class AppLogo extends StatelessWidget {
  const AppLogo({super.key, this.size = 28});
  final double size;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(color: c.accent, borderRadius: BorderRadius.circular(size * 0.3)),
      child: Icon(Icons.shield_outlined, size: size * 0.6, color: c.onAccent),
    );
  }
}

const _avatarPalette = [
  Color(0xFF171A21), Color(0xFF24292F), Color(0xFF0B7A5B), Color(0xFF1A73E8), Color(0xFF6D4AFF),
  Color(0xFFC2410C), Color(0xFF0E7490), Color(0xFFBE185D), Color(0xFF4D7C0F), Color(0xFF7C2D12),
];

class ItemAvatar extends StatelessWidget {
  const ItemAvatar({super.key, required this.item, this.size = 38});
  final VaultItem item;
  final double size;

  @override
  Widget build(BuildContext context) {
    final IconData? icon = switch (item.type) {
      ItemType.login => null,
      ItemType.note => Icons.sticky_note_2_outlined,
      ItemType.card => Icons.credit_card,
      ItemType.identity => Icons.badge_outlined,
      ItemType.document => Icons.description_outlined,
    };
    final Color color = switch (item.type) {
      ItemType.note => const Color(0xFFE9A23B),
      ItemType.card => const Color(0xFF334155),
      ItemType.identity => const Color(0xFF6D4AFF),
      ItemType.document => const Color(0xFF0E7490),
      ItemType.login => _avatarPalette[item.title.codeUnits.fold(0, (a, b) => a + b) % _avatarPalette.length],
    };
    final letter = item.title.trim().isEmpty ? '?' : item.title.trim().characters.first.toUpperCase();
    return Container(
      width: size,
      height: size,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: color,
        borderRadius: BorderRadius.circular(size * 0.27),
        boxShadow: size > 50
            ? [BoxShadow(color: color.withValues(alpha: 0.3), blurRadius: 20, offset: const Offset(0, 8))]
            : null,
      ),
      child: icon != null
          ? Icon(icon, color: Colors.white, size: size * 0.5)
          : Text(letter,
              style: TextStyle(color: Colors.white, fontWeight: FontWeight.w800, fontSize: size * 0.42)),
    );
  }
}

enum PillTone { neutral, accent, success, warning, danger }

class Pill extends StatelessWidget {
  const Pill(this.label, {super.key, this.tone = PillTone.neutral, this.icon});
  final String label;
  final PillTone tone;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final (bg, fg) = switch (tone) {
      PillTone.neutral => (c.subtle, c.muted),
      PillTone.accent => (c.accentSoft, c.accent),
      PillTone.success => (c.successSoft, c.success),
      PillTone.warning => (c.warningSoft, c.warning),
      PillTone.danger => (c.dangerSoft, c.danger),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
      decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.circular(99)),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        if (icon != null) ...[Icon(icon, size: 13, color: fg), const SizedBox(width: 4)],
        Text(label, style: TextStyle(color: fg, fontSize: 11.5, fontWeight: FontWeight.w700)),
      ]),
    );
  }
}

class SectionLabel extends StatelessWidget {
  const SectionLabel(this.text, {super.key, this.padding = const EdgeInsets.fromLTRB(18, 14, 18, 6)});
  final String text;
  final EdgeInsetsGeometry padding;

  @override
  Widget build(BuildContext context) =>
      Padding(padding: padding, child: Text(text.toUpperCase(), style: Theme.of(context).textTheme.labelSmall));
}

class StrengthMeter extends StatelessWidget {
  const StrengthMeter({super.key, required this.password, this.showLabel = true});
  final String password;
  final bool showLabel;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final s = strengthOf(password);
    final color = switch (s) {
      Strength.veryWeak || Strength.weak => c.danger,
      Strength.fair => c.warning,
      _ => c.success,
    };
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      ClipRRect(
        borderRadius: BorderRadius.circular(3),
        child: LinearProgressIndicator(
          value: password.isEmpty ? 0 : s.fraction,
          minHeight: 5,
          color: color,
          backgroundColor: c.subtleStrong,
        ),
      ),
      if (showLabel && password.isNotEmpty) ...[
        const SizedBox(height: 6),
        Text('${s.label} · ${password.length} characters',
            style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w700)),
      ],
    ]);
  }
}

/// Live one-time code with a countdown ring.
class TotpView extends StatefulWidget {
  const TotpView({super.key, required this.config, required this.onCopy});
  final TotpConfig config;
  final void Function(String code) onCopy;

  @override
  State<TotpView> createState() => _TotpViewState();
}

class _TotpViewState extends State<TotpView> {
  Timer? _timer;
  String _code = '';
  int _remaining = 30;
  int _counter = -1;

  @override
  void initState() {
    super.initState();
    _tick();
    _timer = Timer.periodic(const Duration(milliseconds: 500), (_) => _tick());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _tick() async {
    final now = DateTime.now();
    final counter = now.millisecondsSinceEpoch ~/ 1000 ~/ widget.config.period;
    if (counter != _counter) {
      _counter = counter;
      final code = await widget.config.codeAt(now);
      if (mounted) setState(() => _code = code);
    }
    final remaining = widget.config.secondsRemaining(now);
    if (mounted && remaining != _remaining) setState(() => _remaining = remaining);
  }

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final half = _code.length ~/ 2;
    final display = _code.isEmpty ? '······' : '${_code.substring(0, half)} ${_code.substring(half)}';
    final urgent = _remaining <= 5;
    return Row(children: [
      Expanded(
        child: SelectableText(display,
            style: TextStyle(
                fontFamily: 'Consolas',
                fontFamilyFallback: const ['Menlo', 'monospace'],
                fontSize: 24,
                fontWeight: FontWeight.w600,
                letterSpacing: 2,
                color: urgent ? c.danger : c.text)),
      ),
      SizedBox(
        width: 32,
        height: 32,
        child: Stack(alignment: Alignment.center, children: [
          CircularProgressIndicator(
            value: _remaining / widget.config.period,
            strokeWidth: 3,
            color: urgent ? c.danger : c.accent,
            backgroundColor: c.subtleStrong,
          ),
          Text('$_remaining', style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w800)),
        ]),
      ),
      const SizedBox(width: 8),
      SmallButton(label: 'Copy', accent: true, onPressed: _code.isEmpty ? null : () => widget.onCopy(_code)),
    ]);
  }
}

class SmallButton extends StatelessWidget {
  const SmallButton({super.key, required this.label, this.onPressed, this.accent = false, this.icon});
  final String label;
  final VoidCallback? onPressed;
  final bool accent;
  final IconData? icon;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return TextButton(
      onPressed: onPressed,
      style: TextButton.styleFrom(
        foregroundColor: accent ? c.accent : c.muted,
        backgroundColor: c.panel,
        minimumSize: const Size(0, 34),
        padding: const EdgeInsets.symmetric(horizontal: 11),
        textStyle: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w700),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8), side: BorderSide(color: c.border)),
      ),
      child: icon == null
          ? Text(label)
          : Row(mainAxisSize: MainAxisSize.min, children: [Icon(icon, size: 15), const SizedBox(width: 5), Text(label)]),
    );
  }
}

class EmptyState extends StatelessWidget {
  const EmptyState({super.key, required this.icon, required this.title, required this.message, this.action});
  final IconData icon;
  final String title;
  final String message;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Container(
            width: 64,
            height: 64,
            decoration: BoxDecoration(color: c.accentSoft, borderRadius: BorderRadius.circular(20)),
            child: Icon(icon, color: c.accent, size: 30),
          ),
          const SizedBox(height: 18),
          Text(title, style: Theme.of(context).textTheme.titleLarge, textAlign: TextAlign.center),
          const SizedBox(height: 6),
          ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 340),
            child: Text(message, textAlign: TextAlign.center, style: TextStyle(color: c.muted)),
          ),
          if (action != null) ...[const SizedBox(height: 20), action!],
        ]),
      ),
    );
  }
}

class KeyCap extends StatelessWidget {
  const KeyCap(this.label, {super.key});
  final String label;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
      decoration: BoxDecoration(
        color: c.panel,
        borderRadius: BorderRadius.circular(6),
        border: Border(
          top: BorderSide(color: c.border),
          left: BorderSide(color: c.border),
          right: BorderSide(color: c.border),
          bottom: BorderSide(color: c.border, width: 2),
        ),
      ),
      child: Text(label, style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: c.muted)),
    );
  }
}

void showToast(BuildContext context, String message, {String? actionLabel, VoidCallback? onAction}) {
  final messenger = ScaffoldMessenger.maybeOf(context);
  if (messenger == null) return;
  messenger
    ..hideCurrentSnackBar()
    ..showSnackBar(SnackBar(
      content: Text(message),
      duration: const Duration(seconds: 4),
      action: actionLabel == null ? null : SnackBarAction(label: actionLabel, onPressed: onAction ?? () {}),
    ));
}

Future<bool> confirm(
  BuildContext context, {
  required String title,
  required String message,
  required String confirmLabel,
  bool destructive = false,
}) async {
  final c = context.colors;
  final result = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: Text(title),
      content: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 400), child: Text(message)),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
        FilledButton(
          style: destructive ? FilledButton.styleFrom(backgroundColor: c.danger, foregroundColor: Colors.white) : null,
          onPressed: () => Navigator.pop(context, true),
          child: Text(confirmLabel),
        ),
      ],
    ),
  );
  return result ?? false;
}

String formatBytes(int bytes) {
  if (bytes < 1024) return '$bytes B';
  const units = ['KB', 'MB', 'GB'];
  var value = bytes / 1024;
  var i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return '${value.toStringAsFixed(value < 10 ? 1 : 0)} ${units[i]}';
}

String formatDate(DateTime d) {
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  final now = DateTime.now();
  return d.year == now.year ? '${d.day} ${months[d.month - 1]}' : '${d.day} ${months[d.month - 1]} ${d.year}';
}

String relativeTime(DateTime d) {
  final diff = DateTime.now().difference(d);
  if (diff.inMinutes < 1) return 'Now';
  if (diff.inHours < 1) return '${diff.inMinutes}m';
  if (diff.inDays < 1) return '${diff.inHours}h';
  if (diff.inDays < 7) return '${diff.inDays}d';
  if (diff.inDays < 60) return '${max(1, diff.inDays ~/ 7)}w';
  return formatDate(d);
}
