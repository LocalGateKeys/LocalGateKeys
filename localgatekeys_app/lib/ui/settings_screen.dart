import 'dart:convert';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../state/app_prefs.dart';
import '../state/vault_controller.dart';
import 'auth_screens.dart';
import 'file_actions.dart';
import 'theme.dart';
import 'widgets.dart';

const appVersion = '1.0.0';

class SettingsScreen extends StatelessWidget {
  const SettingsScreen({super.key, required this.vault, required this.prefs});
  final VaultController vault;
  final AppPrefs prefs;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final s = vault.settings;
    return LayoutBuilder(builder: (context, box) {
      final pad = box.maxWidth >= 760 ? 40.0 : 18.0;
      return ListView(padding: EdgeInsets.fromLTRB(pad, box.maxWidth >= 760 ? 32 : 16, pad, 40), children: [
        Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 760),
            child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              Text('Settings', style: Theme.of(context).textTheme.headlineMedium),
              const SizedBox(height: 24),
              _Section(title: 'Security', children: [
                _Row(
                  title: 'Lock automatically',
                  subtitle: 'After this long without activity',
                  trailing: _Dropdown<int>(
                    value: s.autoLockMinutes,
                    items: const {1: '1 minute', 5: '5 minutes', 15: '15 minutes', 30: '30 minutes', 60: '1 hour', 0: 'Never'},
                    onChanged: (v) => vault.updateSettings((s) => s.autoLockMinutes = v),
                  ),
                ),
                _Row(
                  title: 'Clear copied passwords',
                  subtitle: 'Removes them from the clipboard',
                  trailing: _Dropdown<int>(
                    value: s.clipboardSeconds,
                    items: const {10: 'After 10 s', 30: 'After 30 s', 60: 'After 1 min', 120: 'After 2 min', 0: 'Never'},
                    onChanged: (v) => vault.updateSettings((s) => s.clipboardSeconds = v),
                  ),
                ),
                _Row(
                  title: isDesktop ? 'Lock when minimised' : 'Lock when leaving the app',
                  trailing: Switch(
                    value: s.lockOnBackground,
                    onChanged: (v) => vault.updateSettings((s) => s.lockOnBackground = v),
                  ),
                ),
                _Row(
                  title: 'Master password',
                  subtitle: 'Change the password that unlocks this vault',
                  trailing: OutlinedButton(onPressed: () => _changePassword(context), child: const Text('Change')),
                ),
                _Row(
                  title: 'Recovery code',
                  subtitle: vault.hasRecoveryCode
                      ? 'Replaces your current code. The old one stops working.'
                      : 'You have no recovery code yet',
                  trailing: OutlinedButton(
                    onPressed: () => newRecoveryCodeFlow(context, vault),
                    child: Text(vault.hasRecoveryCode ? 'Create new' : 'Create'),
                  ),
                ),
              ]),
              _Section(title: 'Appearance', children: [
                _Row(
                  title: 'Theme',
                  trailing: ValueListenableBuilder(
                    valueListenable: prefs.themeMode,
                    builder: (context, mode, _) => SegmentedButton<ThemeMode>(
                      showSelectedIcon: false,
                      segments: const [
                        ButtonSegment(value: ThemeMode.system, label: Text('Auto')),
                        ButtonSegment(value: ThemeMode.light, label: Text('Light')),
                        ButtonSegment(value: ThemeMode.dark, label: Text('Dark')),
                      ],
                      selected: {mode},
                      onSelectionChanged: (v) => prefs.setThemeMode(v.first),
                    ),
                  ),
                ),
              ]),
              _Section(title: 'Backup and import', children: [
                _Row(
                  title: 'Encrypted backup',
                  subtitle: s.lastBackupAt == null
                      ? 'Never backed up. Save a copy to a USB drive or another disk.'
                      : 'Last backup ${formatDate(s.lastBackupAt!)}',
                  trailing: FilledButton(onPressed: () => exportBackupFlow(context, vault), child: const Text('Back up now')),
                ),
                _Row(
                  title: 'Restore from backup',
                  subtitle: 'Replaces everything on this device',
                  trailing: OutlinedButton(onPressed: () => restoreBackupFlow(context, vault), child: const Text('Restore')),
                ),
                _Row(
                  title: 'Import passwords',
                  subtitle: 'CSV export from Chrome, Edge, Firefox, Bitwarden, 1Password or KeePass',
                  trailing: OutlinedButton(onPressed: () => _importCsv(context), child: const Text('Import CSV')),
                ),
              ]),
              _Section(title: 'About', children: [
                _Row(title: 'LocalGateKeys', subtitle: 'Version $appVersion · works fully offline'),
                _Row(
                  title: 'Vault location',
                  subtitle: vault.store.location,
                  trailing: SmallButton(label: 'Copy', onPressed: () => vault.copy(vault.store.location, secret: false)),
                ),
                _Row(
                  title: 'Encryption',
                  subtitle: 'Argon2id (64 MiB, 3 passes) and XChaCha20-Poly1305',
                ),
                _Row(
                  title: 'Open-source licences',
                  trailing: OutlinedButton(
                    onPressed: () => showLicensePage(context: context, applicationName: 'LocalGateKeys', applicationVersion: appVersion),
                    child: const Text('View'),
                  ),
                ),
              ]),
              Text('Lock the vault any time with Ctrl L.', style: TextStyle(color: c.faint, fontSize: 12.5)),
            ]),
          ),
        ),
      ]);
    });
  }

  Future<void> _changePassword(BuildContext context) =>
      showDialog<void>(context: context, builder: (_) => _ChangePasswordDialog(vault: vault));

  Future<void> _importCsv(BuildContext context) async {
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Choose a password export (CSV)',
      type: isDesktop ? FileType.custom : FileType.any,
      allowedExtensions: isDesktop ? const ['csv'] : null,
      withData: true,
    );
    final bytes = result?.files.single.bytes;
    if (bytes == null || !context.mounted) return;
    try {
      var text = utf8.decode(bytes, allowMalformed: true);
      // Exports from older tools can be Windows-1252; fall back rather than mangle them.
      if (text.contains('�')) text = latin1.decode(bytes);
      final count = await vault.importCsv(text);
      if (context.mounted) {
        showToast(context, 'Imported $count logins. Delete the CSV file now; it is not encrypted.');
      }
    } on FormatException catch (e) {
      if (context.mounted) showToast(context, e.message);
    }
  }
}

Future<void> newRecoveryCodeFlow(BuildContext context, VaultController vault) async {
  final password = await askPassword(context,
      title: 'Confirm it is you', message: 'Enter your master password to create a new recovery code.', action: 'Continue');
  if (password == null || !context.mounted) return;
  if (!await vault.verifyPassword(password)) {
    if (context.mounted) showToast(context, 'That password is not correct.');
    return;
  }
  final code = await vault.regenerateRecoveryCode();
  if (!context.mounted) return;
  var saved = false;
  await showDialog<void>(
    context: context,
    barrierDismissible: false,
    builder: (context) => StatefulBuilder(
      builder: (context, setState) => Dialog(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 440),
            child: RecoveryCodeBody(
              code: code,
              saved: saved,
              onSavedChanged: (v) => setState(() => saved = v),
              onDone: () => Navigator.pop(context),
              doneLabel: 'Done',
            ),
          ),
        ),
      ),
    ),
  );
}

class _ChangePasswordDialog extends StatefulWidget {
  const _ChangePasswordDialog({required this.vault});
  final VaultController vault;

  @override
  State<_ChangePasswordDialog> createState() => _ChangePasswordDialogState();
}

class _ChangePasswordDialogState extends State<_ChangePasswordDialog> {
  final _current = TextEditingController();
  final _next = TextEditingController();
  final _confirm = TextEditingController();
  String? _error;
  bool _busy = false;

  Future<void> _submit() async {
    final problem = newPasswordProblem(_next.text, _confirm.text);
    if (problem != null) {
      setState(() => _error = problem);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    final ok = await widget.vault.changePassword(_current.text, _next.text);
    if (!mounted) return;
    if (ok) {
      Navigator.pop(context);
      showToast(context, 'Master password changed');
    } else {
      setState(() {
        _busy = false;
        _error = 'Your current password is not correct.';
      });
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
        title: const Text('Change master password'),
        content: SizedBox(
          width: 420,
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            PasswordField(controller: _current, label: 'Current password', hint: 'Current master password', autofocus: true),
            const SizedBox(height: 14),
            PasswordField(controller: _next, label: 'New password', hint: 'At least 10 characters', onChanged: (_) => setState(() {})),
            const SizedBox(height: 8),
            StrengthMeter(password: _next.text),
            const SizedBox(height: 14),
            PasswordField(controller: _confirm, label: 'Confirm new password', hint: 'Type it again', onSubmitted: (_) => _submit()),
            if (_error != null) ...[
              const SizedBox(height: 12),
              Text(_error!, style: TextStyle(color: context.colors.danger, fontWeight: FontWeight.w600)),
            ],
          ]),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          FilledButton(onPressed: _busy ? null : _submit, child: const Text('Change password')),
        ],
      );
}

class _Section extends StatelessWidget {
  const _Section({required this.title, required this.children});
  final String title;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Padding(
      padding: const EdgeInsets.only(bottom: 26),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        SectionLabel(title, padding: const EdgeInsets.only(left: 4, bottom: 8)),
        Panel(
          child: Column(children: [
            for (var i = 0; i < children.length; i++) ...[if (i > 0) Divider(height: 1, color: c.border), children[i]],
          ]),
        ),
      ]),
    );
  }
}

class _Row extends StatelessWidget {
  const _Row({required this.title, this.subtitle, this.trailing});
  final String title;
  final String? subtitle;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
      child: Row(children: [
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(title, style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14.5)),
            if (subtitle != null) ...[
              const SizedBox(height: 2),
              Text(subtitle!, style: TextStyle(color: c.faint, fontSize: 13)),
            ],
          ]),
        ),
        if (trailing != null) ...[const SizedBox(width: 16), trailing!],
      ]),
    );
  }
}

class _Dropdown<T> extends StatelessWidget {
  const _Dropdown({required this.value, required this.items, required this.onChanged});
  final T value;
  final Map<T, String> items;
  final ValueChanged<T> onChanged;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12),
      decoration: BoxDecoration(color: c.subtle, borderRadius: BorderRadius.circular(10)),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<T>(
          value: items.containsKey(value) ? value : items.keys.first,
          borderRadius: BorderRadius.circular(12),
          dropdownColor: c.panel,
          style: TextStyle(color: c.text, fontWeight: FontWeight.w600, fontSize: 14),
          items: [for (final e in items.entries) DropdownMenuItem(value: e.key, child: Text(e.value))],
          onChanged: (v) => v == null ? null : onChanged(v),
        ),
      ),
    );
  }
}
