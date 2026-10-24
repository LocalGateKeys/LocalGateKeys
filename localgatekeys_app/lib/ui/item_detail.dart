import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import '../core/models.dart';
import '../core/totp.dart';
import '../state/vault_controller.dart';
import 'file_actions.dart';
import 'theme.dart';
import 'widgets.dart';

class ItemDetail extends StatelessWidget {
  const ItemDetail({super.key, required this.vault, required this.item, required this.onEdit});

  final VaultController vault;
  final VaultItem item;
  final VoidCallback onEdit;

  Future<void> _copy(BuildContext context, String label, String value, {bool secret = true}) async {
    await vault.copy(value, secret: secret, item: item);
    if (!context.mounted) return;
    final seconds = vault.settings.clipboardSeconds;
    showToast(context, secret && seconds > 0 ? '$label copied · clears in $seconds s' : '$label copied');
  }

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final specs = item.type.fields.where((f) => item.field(f.key).isNotEmpty).toList();
    return LayoutBuilder(builder: (context, box) {
      final wide = box.maxWidth >= 640;
      final hPad = wide ? 48.0 : 20.0;
      final cards = <Widget>[
        for (final spec in specs) _fieldCard(context, spec),
      ];
      return ListView(
        padding: EdgeInsets.fromLTRB(hPad, wide ? 12 : 8, hPad, 40),
        children: [
          if (item.inTrash) ...[_trashBanner(context), const SizedBox(height: 20)],
          Row(children: [
            ItemAvatar(item: item, size: wide ? 68 : 56),
            SizedBox(width: wide ? 20 : 14),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(item.title,
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontSize: wide ? 30 : 24)),
                const SizedBox(height: 4),
                Text(_subtitle, style: TextStyle(color: c.faint, fontSize: 14)),
              ]),
            ),
          ]),
          const SizedBox(height: 26),
          if (cards.isNotEmpty) _grid(cards, wide),
          if (item.notes.isNotEmpty) ...[
            const SizedBox(height: 14),
            _FieldShell(
              label: 'Notes',
              trailing: SmallButton(
                  label: 'Copy', onPressed: () => _copy(context, 'Notes', item.notes, secret: false)),
              child: SelectableText(item.notes, style: const TextStyle(fontSize: 14.5, height: 1.5)),
            ),
          ],
          if (item.attachments.isNotEmpty) ...[
            const SizedBox(height: 14),
            _attachments(context),
          ],
          if (item.type == ItemType.login && !item.inTrash) ...[
            const SizedBox(height: 22),
            _primaryActions(context),
          ],
          if (item.passwordHistory.isNotEmpty) ...[
            const SizedBox(height: 22),
            _PasswordHistory(item: item, onCopy: (v) => _copy(context, 'Old password', v)),
          ],
          const SizedBox(height: 24),
          Text('Edited ${formatDate(item.updatedAt)} · Created ${formatDate(item.createdAt)}',
              style: TextStyle(color: c.faint, fontSize: 12.5)),
        ],
      );
    });
  }

  String get _subtitle {
    final parts = <String>[item.type.label];
    final host = hostOf(item.field('url'));
    if (host.isNotEmpty) parts.add(host);
    if (item.lastUsedAt != null) parts.add('Used ${relativeTime(item.lastUsedAt!).toLowerCase()} ago');
    return parts.join(' · ').replaceAll('now ago', 'just now');
  }

  Widget _grid(List<Widget> cards, bool wide) {
    if (!wide) {
      return Column(children: [
        for (final card in cards) Padding(padding: const EdgeInsets.only(bottom: 12), child: card),
      ]);
    }
    final rows = <Widget>[];
    for (var i = 0; i < cards.length; i += 2) {
      rows.add(Padding(
        padding: const EdgeInsets.only(bottom: 14),
        child: IntrinsicHeight(
          child: Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Expanded(child: cards[i]),
            const SizedBox(width: 14),
            Expanded(child: i + 1 < cards.length ? cards[i + 1] : const SizedBox()),
          ]),
        ),
      ));
    }
    return Column(children: rows);
  }

  Widget _fieldCard(BuildContext context, FieldSpec spec) {
    final value = item.field(spec.key);
    switch (spec.kind) {
      case FieldKind.password:
        return _SecretField(
          spec: spec,
          value: value,
          showStrength: spec.key == 'password',
          onCopy: () => _copy(context, spec.label, value),
        );
      case FieldKind.totp:
        final config = TotpConfig.parse(value);
        return _FieldShell(
          label: 'One-time code',
          child: config == null
              ? Text('This secret is not valid.', style: TextStyle(color: context.colors.danger))
              : TotpView(config: config, onCopy: (code) => _copy(context, 'Code', code)),
        );
      case FieldKind.url:
        final uri = Uri.tryParse(value.contains('://') ? value : 'https://$value');
        return _FieldShell(
          label: spec.label,
          trailing: Row(mainAxisSize: MainAxisSize.min, children: [
            if (uri != null && (uri.scheme == 'https' || uri.scheme == 'http'))
              SmallButton(label: 'Open', icon: Icons.open_in_new_rounded, onPressed: () => launchUrl(uri)),
            const SizedBox(width: 6),
            SmallButton(label: 'Copy', accent: true, onPressed: () => _copy(context, 'Link', value, secret: false)),
          ]),
          child: Text(value,
              maxLines: 2, overflow: TextOverflow.ellipsis, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
        );
      default:
        return _FieldShell(
          label: spec.label,
          trailing: SmallButton(
              label: 'Copy', accent: true, onPressed: () => _copy(context, spec.label, value, secret: false)),
          child: SelectableText(value,
              style: TextStyle(fontSize: spec.multiline ? 15 : 16.5, fontWeight: FontWeight.w600)),
        );
    }
  }

  Widget _primaryActions(BuildContext context) {
    final password = item.field('password');
    final username = item.field('username');
    return Wrap(spacing: 10, runSpacing: 10, crossAxisAlignment: WrapCrossAlignment.center, children: [
      if (password.isNotEmpty)
        FilledButton(
          onPressed: () => _copy(context, 'Password', password),
          style: FilledButton.styleFrom(minimumSize: const Size(0, 48)),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            const Icon(Icons.copy_rounded, size: 18),
            const SizedBox(width: 10),
            const Text('Copy password'),
            if (isDesktop) ...[
              const SizedBox(width: 10),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.2), borderRadius: BorderRadius.circular(5)),
                child: const Text('Ctrl ⇧ C', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700)),
              ),
            ],
          ]),
        ),
      if (username.isNotEmpty)
        OutlinedButton(
          onPressed: () => _copy(context, 'Username', username, secret: false),
          style: OutlinedButton.styleFrom(minimumSize: const Size(0, 48)),
          child: const Text('Copy username'),
        ),
    ]);
  }

  Widget _attachments(BuildContext context) {
    final c = context.colors;
    return _FieldShell(
      label: item.attachments.length == 1 ? 'File' : '${item.attachments.length} files',
      child: Column(children: [
        for (final a in item.attachments)
          Padding(
            padding: const EdgeInsets.only(top: 6),
            child: Row(children: [
              Container(
                width: 38,
                height: 38,
                decoration: BoxDecoration(color: c.panel, borderRadius: BorderRadius.circular(9), border: Border.all(color: c.border)),
                child: Icon(a.isImage ? Icons.image_outlined : Icons.insert_drive_file_outlined, size: 19, color: c.muted),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(a.name, maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(fontWeight: FontWeight.w600)),
                  Text('${formatBytes(a.size)} · added ${formatDate(a.addedAt)}',
                      style: TextStyle(fontSize: 12, color: c.faint)),
                ]),
              ),
              if (a.isImage || a.isText) ...[
                SmallButton(label: 'View', onPressed: () => _preview(context, a)),
                const SizedBox(width: 6),
              ],
              SmallButton(label: 'Save copy', accent: true, onPressed: () => _saveCopy(context, a)),
            ]),
          ),
      ]),
    );
  }

  Future<void> _saveCopy(BuildContext context, Attachment a) async {
    try {
      final bytes = await vault.readAttachment(a);
      final saved = await saveBytesAs(a.name, bytes);
      if (saved && context.mounted) {
        showToast(context, 'Saved an unencrypted copy of ${a.name}');
      }
    } on Object catch (e) {
      if (context.mounted) showToast(context, 'Could not open this file: $e');
    }
  }

  Future<void> _preview(BuildContext context, Attachment a) async {
    await showDialog<void>(
      context: context,
      builder: (context) => Dialog(
        insetPadding: const EdgeInsets.all(32),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 900, maxHeight: 760),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 12, 8, 8),
              child: Row(children: [
                Expanded(child: Text(a.name, style: Theme.of(context).textTheme.titleMedium, overflow: TextOverflow.ellipsis)),
                IconButton(tooltip: 'Close', onPressed: () => Navigator.pop(context), icon: const Icon(Icons.close_rounded)),
              ]),
            ),
            Flexible(
              child: FutureBuilder<Uint8List>(
                future: vault.readAttachment(a),
                builder: (context, snap) {
                  if (snap.hasError) return const Padding(padding: EdgeInsets.all(40), child: Text('This file could not be decrypted.'));
                  if (!snap.hasData) return const Padding(padding: EdgeInsets.all(60), child: Center(child: CircularProgressIndicator()));
                  if (a.isImage) {
                    return InteractiveViewer(
                      maxScale: 6,
                      child: Padding(padding: const EdgeInsets.fromLTRB(20, 0, 20, 20), child: Image.memory(snap.data!, fit: BoxFit.contain)),
                    );
                  }
                  return SingleChildScrollView(
                    padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
                    child: SelectableText(utf8.decode(snap.data!, allowMalformed: true),
                        style: const TextStyle(fontFamily: 'Consolas', fontFamilyFallback: ['Menlo', 'monospace'], fontSize: 13)),
                  );
                },
              ),
            ),
          ]),
        ),
      ),
    );
  }

  Widget _trashBanner(BuildContext context) {
    final c = context.colors;
    return Container(
      padding: const EdgeInsets.fromLTRB(16, 12, 12, 12),
      decoration: BoxDecoration(color: c.warningSoft, borderRadius: BorderRadius.circular(12)),
      child: Row(children: [
        Icon(Icons.delete_outline_rounded, color: c.warning, size: 20),
        const SizedBox(width: 10),
        Expanded(child: Text('This item is in the trash.', style: TextStyle(color: c.warning, fontWeight: FontWeight.w700))),
        TextButton(onPressed: () => vault.restore(item), child: const Text('Restore')),
        TextButton(
          style: TextButton.styleFrom(foregroundColor: c.danger),
          onPressed: () async {
            final ok = await confirm(context,
                title: 'Delete permanently?',
                message: '“${item.title}” and its files will be erased from this device. This cannot be undone.',
                confirmLabel: 'Delete',
                destructive: true);
            if (ok) await vault.deleteForever(item);
          },
          child: const Text('Delete forever'),
        ),
      ]),
    );
  }
}

/// Header actions for the detail view (favourite, edit, more).
class ItemDetailActions extends StatelessWidget {
  const ItemDetailActions({super.key, required this.vault, required this.item, required this.onEdit, this.onTrashed});
  final VaultController vault;
  final VaultItem item;
  final VoidCallback onEdit;
  final VoidCallback? onTrashed;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    if (item.inTrash) return const SizedBox();
    return Row(mainAxisSize: MainAxisSize.min, children: [
      IconButton(
        tooltip: item.favorite ? 'Remove from favourites' : 'Add to favourites',
        onPressed: () => vault.toggleFavorite(item),
        icon: Icon(item.favorite ? Icons.star_rounded : Icons.star_outline_rounded,
            color: item.favorite ? const Color(0xFFF2A10F) : c.muted),
      ),
      const SizedBox(width: 4),
      OutlinedButton(onPressed: onEdit, style: OutlinedButton.styleFrom(minimumSize: const Size(0, 38)), child: const Text('Edit')),
      PopupMenuButton<String>(
        tooltip: 'More',
        icon: const Icon(Icons.more_horiz_rounded),
        onSelected: (v) async {
          if (v == 'trash') {
            await vault.moveToTrash(item);
            onTrashed?.call();
            if (context.mounted) {
              showToast(context, '“${item.title}” moved to trash', actionLabel: 'Undo', onAction: () => vault.restore(item));
            }
          }
        },
        itemBuilder: (_) => [
          PopupMenuItem(
            value: 'trash',
            child: Row(children: [
              Icon(Icons.delete_outline_rounded, size: 19, color: c.danger),
              const SizedBox(width: 12),
              Text('Move to trash', style: TextStyle(color: c.danger)),
            ]),
          ),
        ],
      ),
    ]);
  }
}

class _FieldShell extends StatelessWidget {
  const _FieldShell({required this.label, required this.child, this.trailing, this.labelTrailing});
  final String label;
  final Widget child;
  final Widget? trailing;
  final Widget? labelTrailing;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Container(
      padding: const EdgeInsets.fromLTRB(18, 14, 14, 16),
      decoration: BoxDecoration(color: c.subtle, borderRadius: BorderRadius.circular(14)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Expanded(child: Text(label, style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700, color: c.faint))),
          if (labelTrailing != null) labelTrailing!,
        ]),
        const SizedBox(height: 8),
        if (trailing == null)
          child
        else
          Row(children: [Expanded(child: child), const SizedBox(width: 10), trailing!]),
      ]),
    );
  }
}

class _SecretField extends StatefulWidget {
  const _SecretField({required this.spec, required this.value, required this.onCopy, this.showStrength = false});
  final FieldSpec spec;
  final String value;
  final VoidCallback onCopy;
  final bool showStrength;

  @override
  State<_SecretField> createState() => _SecretFieldState();
}

class _SecretFieldState extends State<_SecretField> {
  bool _visible = false;

  @override
  void didUpdateWidget(covariant _SecretField old) {
    super.didUpdateWidget(old);
    if (old.value != widget.value) _visible = false;
  }

  @override
  Widget build(BuildContext context) {
    return _FieldShell(
      label: widget.spec.label,
      trailing: Row(mainAxisSize: MainAxisSize.min, children: [
        SmallButton(label: _visible ? 'Hide' : 'Show', onPressed: () => setState(() => _visible = !_visible)),
        const SizedBox(width: 6),
        SmallButton(label: 'Copy', accent: true, onPressed: widget.onCopy),
      ]),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        _visible
            ? SelectableText(widget.value, style: _mono)
            : Text('•' * widget.value.length.clamp(8, 16), style: _mono.copyWith(letterSpacing: 2.5)),
        if (widget.showStrength) ...[const SizedBox(height: 10), StrengthMeter(password: widget.value)],
      ]),
    );
  }

  static const _mono = TextStyle(
      fontFamily: 'Consolas', fontFamilyFallback: ['Menlo', 'monospace'], fontSize: 16.5, fontWeight: FontWeight.w600);
}

class _PasswordHistory extends StatelessWidget {
  const _PasswordHistory({required this.item, required this.onCopy});
  final VaultItem item;
  final ValueChanged<String> onCopy;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Theme(
      data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
      child: ExpansionTile(
        tilePadding: EdgeInsets.zero,
        title: Text('Password history (${item.passwordHistory.length})',
            style: TextStyle(fontWeight: FontWeight.w700, fontSize: 14, color: c.muted)),
        children: [
          for (final h in item.passwordHistory)
            ListTile(
              contentPadding: EdgeInsets.zero,
              dense: true,
              title: Text('•' * 12, style: const TextStyle(letterSpacing: 2)),
              subtitle: Text('Replaced ${formatDate(h.changedAt)}'),
              trailing: SmallButton(label: 'Copy', onPressed: () => onCopy(h.value)),
            ),
        ],
      ),
    );
  }
}
