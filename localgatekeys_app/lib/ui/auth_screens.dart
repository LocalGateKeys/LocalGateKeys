import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../core/password_tools.dart';
import '../state/vault_controller.dart';
import 'file_actions.dart';
import 'theme.dart';
import 'widgets.dart';

/// Two-column frame for the unlock and setup screens: a brand pane on wide
/// windows, the form alone on phones.
class AuthFrame extends StatelessWidget {
  const AuthFrame({super.key, required this.child});
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Scaffold(
      body: LayoutBuilder(builder: (context, box) {
        final wide = box.maxWidth >= 900;
        final form = Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
            child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 420), child: child),
          ),
        );
        if (!wide) return SafeArea(child: ColoredBox(color: c.panel, child: form));
        return Row(children: [
          Expanded(flex: 5, child: _BrandPane()),
          Expanded(flex: 6, child: ColoredBox(color: c.panel, child: form)),
        ]);
      }),
    );
  }
}

class _BrandPane extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    const ink = Color(0xFF0B1220);
    const soft = Color(0xFF9FB0C8);
    Widget feature(IconData icon, String title, String body) => Padding(
          padding: const EdgeInsets.only(bottom: 22),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.08), borderRadius: BorderRadius.circular(12)),
              child: Icon(icon, color: Colors.white, size: 20),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(title, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w700, fontSize: 15)),
                const SizedBox(height: 3),
                Text(body, style: const TextStyle(color: soft, fontSize: 13.5, height: 1.45)),
              ]),
            ),
          ]),
        );
    return Container(
      color: ink,
      padding: const EdgeInsets.fromLTRB(56, 48, 56, 40),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Row(children: [
          AppLogo(size: 32),
          SizedBox(width: 12),
          Text('LocalGateKeys', style: TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.w700)),
        ]),
        const Spacer(),
        const Text('Your passwords and\ndocuments, on your\ndevice only.',
            style: TextStyle(
                color: Colors.white, fontSize: 38, height: 1.15, fontWeight: FontWeight.w700, letterSpacing: -1)),
        const SizedBox(height: 36),
        feature(Icons.wifi_off_rounded, 'Works fully offline',
            'No account, no cloud, no telemetry. Nothing leaves this device unless you export it.'),
        feature(Icons.lock_outline_rounded, 'Encrypted end to end',
            'Argon2id and XChaCha20-Poly1305 protect every item and every file.'),
        feature(Icons.folder_copy_outlined, 'Documents included',
            'Keep passport scans, insurance papers and recovery codes next to your logins.'),
        const Spacer(),
        const Text('Version 1.0.0', style: TextStyle(color: soft, fontSize: 12)),
      ]),
    );
  }
}

class PasswordField extends StatefulWidget {
  const PasswordField({
    super.key,
    required this.controller,
    this.label,
    this.hint = 'Master password',
    this.autofocus = false,
    this.onSubmitted,
    this.onChanged,
    this.errorText,
  });

  final TextEditingController controller;
  final String? label;
  final String hint;
  final bool autofocus;
  final ValueChanged<String>? onSubmitted;
  final ValueChanged<String>? onChanged;
  final String? errorText;

  @override
  State<PasswordField> createState() => _PasswordFieldState();
}

class _PasswordFieldState extends State<PasswordField> {
  bool _visible = false;

  @override
  Widget build(BuildContext context) => TextField(
        controller: widget.controller,
        autofocus: widget.autofocus,
        obscureText: !_visible,
        enableSuggestions: false,
        autocorrect: false,
        onSubmitted: widget.onSubmitted,
        onChanged: widget.onChanged,
        style: const TextStyle(fontSize: 15),
        decoration: InputDecoration(
          labelText: widget.label,
          hintText: widget.hint,
          errorText: widget.errorText,
          prefixIcon: const Icon(Icons.key_outlined, size: 19),
          suffixIcon: IconButton(
            tooltip: _visible ? 'Hide' : 'Show',
            icon: Icon(_visible ? Icons.visibility_off_outlined : Icons.visibility_outlined, size: 19),
            onPressed: () => setState(() => _visible = !_visible),
          ),
        ),
      );
}

// --------------------------------------------------------------------- unlock

class UnlockScreen extends StatefulWidget {
  const UnlockScreen({super.key, required this.vault});
  final VaultController vault;

  @override
  State<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends State<UnlockScreen> {
  final _password = TextEditingController();
  String? _error;
  bool _busy = false;

  Future<void> _unlock() async {
    if (_password.text.isEmpty || _busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    final error = await widget.vault.unlock(_password.text);
    if (!mounted) return;
    setState(() {
      _busy = false;
      _error = error;
    });
    if (error != null) _password.selection = TextSelection(baseOffset: 0, extentOffset: _password.text.length);
  }

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return AuthFrame(
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Container(
          width: 56,
          height: 56,
          alignment: Alignment.center,
          decoration: BoxDecoration(color: c.accentSoft, borderRadius: BorderRadius.circular(18)),
          child: Icon(Icons.lock_outline_rounded, color: c.accent, size: 28),
        ).alignLeft(),
        const SizedBox(height: 24),
        Text('Welcome back', style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 6),
        Text('Enter your master password to unlock your vault.', style: TextStyle(color: c.muted, fontSize: 15)),
        const SizedBox(height: 28),
        PasswordField(
          controller: _password,
          autofocus: true,
          errorText: _error,
          onSubmitted: (_) => _unlock(),
        ),
        const SizedBox(height: 16),
        FilledButton(
          onPressed: _busy ? null : _unlock,
          style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(50)),
          child: _busy
              ? SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2.4, color: c.onAccent))
              : const Text('Unlock'),
        ),
        const SizedBox(height: 20),
        Row(children: [
          TextButton(onPressed: () => _recover(context), child: const Text('Forgot password?')),
          const Spacer(),
          TextButton(
            onPressed: () => restoreBackupFlow(context, widget.vault),
            style: TextButton.styleFrom(foregroundColor: c.muted),
            child: const Text('Restore a backup'),
          ),
        ]),
      ]),
    );
  }

  Future<void> _recover(BuildContext context) async {
    await showDialog<void>(context: context, builder: (_) => _RecoveryDialog(vault: widget.vault));
  }
}

class _RecoveryDialog extends StatefulWidget {
  const _RecoveryDialog({required this.vault});
  final VaultController vault;

  @override
  State<_RecoveryDialog> createState() => _RecoveryDialogState();
}

class _RecoveryDialogState extends State<_RecoveryDialog> {
  final _code = TextEditingController();
  final _password = TextEditingController();
  final _confirm = TextEditingController();
  String? _error;
  bool _busy = false;

  Future<void> _submit() async {
    final problem = newPasswordProblem(_password.text, _confirm.text);
    if (_code.text.trim().isEmpty) {
      setState(() => _error = 'Enter your recovery code.');
      return;
    }
    if (problem != null) {
      setState(() => _error = problem);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    final error = await widget.vault.recover(_code.text, _password.text);
    if (!mounted) return;
    if (error == null) {
      Navigator.pop(context);
    } else {
      setState(() {
        _busy = false;
        _error = error;
      });
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
        title: const Text('Reset with recovery code'),
        content: SizedBox(
          width: 420,
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Enter the recovery code you saved when you created this vault, then choose a new master password.'),
            const SizedBox(height: 18),
            TextField(
              controller: _code,
              autofocus: true,
              textCapitalization: TextCapitalization.characters,
              decoration: const InputDecoration(labelText: 'Recovery code', hintText: 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'),
            ),
            const SizedBox(height: 14),
            PasswordField(controller: _password, label: 'New master password', hint: 'At least 10 characters'),
            const SizedBox(height: 14),
            PasswordField(controller: _confirm, label: 'Confirm', hint: 'Type it again', onSubmitted: (_) => _submit()),
            if (_error != null) ...[
              const SizedBox(height: 12),
              Text(_error!, style: TextStyle(color: context.colors.danger, fontWeight: FontWeight.w600)),
            ],
          ]),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          FilledButton(onPressed: _busy ? null : _submit, child: const Text('Reset and unlock')),
        ],
      );
}

String? newPasswordProblem(String password, String confirm) {
  if (password.length < 10) return 'Use at least 10 characters.';
  if (strengthOf(password).isWeak) return 'That password is too easy to guess. Try a longer phrase.';
  if (password != confirm) return 'The passwords do not match.';
  return null;
}

// ---------------------------------------------------------------------- setup

class SetupScreen extends StatefulWidget {
  const SetupScreen({super.key, required this.vault});
  final VaultController vault;

  @override
  State<SetupScreen> createState() => _SetupScreenState();
}

class _SetupScreenState extends State<SetupScreen> {
  final _password = TextEditingController();
  final _confirm = TextEditingController();
  bool _understood = false;
  bool _busy = false;
  String? _error;

  Future<void> _create() async {
    final problem = newPasswordProblem(_password.text, _confirm.text);
    if (problem != null) {
      setState(() => _error = problem);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    await widget.vault.createVault(_password.text);
  }

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return AuthFrame(
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        const Pill('Step 1 of 2', tone: PillTone.accent).alignLeft(),
        const SizedBox(height: 16),
        Text('Create your vault', style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 6),
        Text('Choose one strong master password. It is the only key to your vault.',
            style: TextStyle(color: c.muted, fontSize: 15)),
        const SizedBox(height: 28),
        PasswordField(
          controller: _password,
          label: 'Master password',
          hint: 'A long phrase is easiest to remember',
          autofocus: true,
          onChanged: (_) => setState(() {}),
        ),
        const SizedBox(height: 10),
        StrengthMeter(password: _password.text),
        const SizedBox(height: 16),
        PasswordField(
          controller: _confirm,
          label: 'Confirm master password',
          hint: 'Type it again',
          onSubmitted: (_) => _understood ? _create() : null,
        ),
        const SizedBox(height: 18),
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(color: c.warningSoft, borderRadius: BorderRadius.circular(12)),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Checkbox(
              value: _understood,
              onChanged: (v) => setState(() => _understood = v ?? false),
              visualDensity: VisualDensity.compact,
            ),
            const SizedBox(width: 6),
            Expanded(
              child: Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text(
                  'I understand nobody can reset this password for me. Only the recovery code on the next step can.',
                  style: TextStyle(color: c.warning, fontWeight: FontWeight.w600, fontSize: 13),
                ),
              ),
            ),
          ]),
        ),
        if (_error != null) ...[
          const SizedBox(height: 12),
          Text(_error!, style: TextStyle(color: c.danger, fontWeight: FontWeight.w600)),
        ],
        const SizedBox(height: 18),
        FilledButton(
          onPressed: _understood && !_busy ? _create : null,
          style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(50)),
          child: _busy
              ? SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2.4, color: c.onAccent))
              : const Text('Create vault'),
        ),
        const SizedBox(height: 12),
        TextButton(
          onPressed: () => restoreBackupFlow(context, widget.vault),
          style: TextButton.styleFrom(foregroundColor: c.muted),
          child: const Text('I have a backup from another device'),
        ),
      ]),
    );
  }
}

class RecoveryCodeScreen extends StatefulWidget {
  const RecoveryCodeScreen({super.key, required this.vault, required this.code});
  final VaultController vault;
  final String code;

  @override
  State<RecoveryCodeScreen> createState() => _RecoveryCodeScreenState();
}

class _RecoveryCodeScreenState extends State<RecoveryCodeScreen> {
  bool _saved = false;

  @override
  Widget build(BuildContext context) => AuthFrame(
        child: RecoveryCodeBody(
          code: widget.code,
          stepLabel: 'Step 2 of 2',
          saved: _saved,
          onSavedChanged: (v) => setState(() => _saved = v),
          onDone: widget.vault.finishOnboarding,
          doneLabel: 'Open my vault',
        ),
      );
}

/// Shows a recovery code with copy and save actions, used at setup and when
/// generating a new code from Settings.
class RecoveryCodeBody extends StatelessWidget {
  const RecoveryCodeBody({
    super.key,
    required this.code,
    required this.saved,
    required this.onSavedChanged,
    required this.onDone,
    required this.doneLabel,
    this.stepLabel,
  });

  final String code;
  final bool saved;
  final ValueChanged<bool> onSavedChanged;
  final VoidCallback onDone;
  final String doneLabel;
  final String? stepLabel;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      if (stepLabel != null) ...[Pill(stepLabel!, tone: PillTone.accent).alignLeft(), const SizedBox(height: 16)],
      Text('Save your recovery code', style: Theme.of(context).textTheme.headlineMedium),
      const SizedBox(height: 6),
      Text(
        'If you forget your master password, this code is the only way back in. '
        'Write it down or print it and keep it somewhere safe, away from this device.',
        style: TextStyle(color: c.muted, fontSize: 15),
      ),
      const SizedBox(height: 24),
      Container(
        padding: const EdgeInsets.symmetric(vertical: 22, horizontal: 16),
        decoration: BoxDecoration(
          color: c.subtle,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: c.border),
        ),
        child: SelectableText(
          code,
          textAlign: TextAlign.center,
          style: const TextStyle(
              fontFamily: 'Consolas',
              fontFamilyFallback: ['Menlo', 'monospace'],
              fontSize: 20,
              fontWeight: FontWeight.w700,
              letterSpacing: 1.5),
        ),
      ),
      const SizedBox(height: 12),
      Row(children: [
        Expanded(
          child: OutlinedButton.icon(
            icon: const Icon(Icons.copy_rounded, size: 17),
            label: const Text('Copy'),
            onPressed: () async {
              await Clipboard.setData(ClipboardData(text: code));
              if (context.mounted) showToast(context, 'Recovery code copied. Paste it somewhere safe, then clear it.');
            },
          ),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: OutlinedButton.icon(
            icon: const Icon(Icons.download_rounded, size: 17),
            label: const Text('Save as file'),
            onPressed: () async {
              final text = 'LocalGateKeys recovery code\n\n$code\n\n'
                  'Created ${DateTime.now().toIso8601String().substring(0, 10)}.\n'
                  'Anyone with this code and your vault file can open your vault. Keep it offline.\n';
              await saveBytesAs('LocalGateKeys-recovery-code.txt', Uint8List.fromList(text.codeUnits),
                  dialogTitle: 'Save recovery code');
            },
          ),
        ),
      ]),
      const SizedBox(height: 18),
      CheckboxListTile(
        value: saved,
        onChanged: (v) => onSavedChanged(v ?? false),
        contentPadding: EdgeInsets.zero,
        controlAffinity: ListTileControlAffinity.leading,
        title: const Text('I have stored my recovery code safely',
            style: TextStyle(fontWeight: FontWeight.w600, fontSize: 14)),
      ),
      const SizedBox(height: 12),
      FilledButton(
        onPressed: saved ? onDone : null,
        style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(50)),
        child: Text(doneLabel),
      ),
    ]);
  }
}

extension on Widget {
  Widget alignLeft() => Align(alignment: Alignment.centerLeft, child: this);
}
