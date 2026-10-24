import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../core/models.dart';
import '../core/password_tools.dart';
import '../core/totp.dart';
import '../state/vault_controller.dart';
import 'theme.dart';
import 'widgets.dart';

/// Opens the editor as a dialog on wide windows and a full page on phones.
Future<void> openEditor(BuildContext context, VaultController vault, VaultItem item, {required bool isNew}) {
  final wide = MediaQuery.sizeOf(context).width >= 900;
  final editor = ItemEditor(vault: vault, item: item, isNew: isNew);
  if (wide) {
    return showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => Dialog(
        insetPadding: const EdgeInsets.all(32),
        child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 640, maxHeight: 820), child: editor),
      ),
    );
  }
  return Navigator.of(context).push(MaterialPageRoute(fullscreenDialog: true, builder: (_) => editor));
}

class ItemEditor extends StatefulWidget {
  const ItemEditor({super.key, required this.vault, required this.item, required this.isNew});
  final VaultController vault;
  final VaultItem item;
  final bool isNew;

  @override
  State<ItemEditor> createState() => _ItemEditorState();
}

class _ItemEditorState extends State<ItemEditor> {
  late final VaultItem _draft = widget.item.copy();
  late final TextEditingController _title = TextEditingController(text: _draft.title);
  late final TextEditingController _notes = TextEditingController(text: _draft.notes);
  late final Map<String, TextEditingController> _fields = {
    for (final f in _draft.type.fields) f.key: TextEditingController(text: _draft.field(f.key)),
  };
  final Set<String> _revealed = {};
  bool _dirty = false;
  bool _busy = false;
  String? _titleError;

  @override
  void initState() {
    super.initState();
    for (final c in [_title, _notes, ..._fields.values]) {
      c.addListener(_markDirty);
    }
  }

  void _markDirty() {
    if (!_dirty) setState(() => _dirty = true);
  }

  @override
  void dispose() {
    for (final c in [_title, _notes, ..._fields.values]) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> _save() async {
    if (_title.text.trim().isEmpty) {
      setState(() => _titleError = 'Give this item a name.');
      return;
    }
    final totp = _fields['totp']?.text.trim() ?? '';
    if (totp.isNotEmpty && TotpConfig.parse(totp) == null) {
      showToast(context, 'The one-time code secret is not valid.');
      return;
    }
    setState(() => _busy = true);
    _draft.title = _title.text;
    _draft.notes = _notes.text.trimRight();
    for (final e in _fields.entries) {
      final v = e.value.text.trim();
      if (v.isEmpty) {
        _draft.fields.remove(e.key);
      } else {
        _draft.fields[e.key] = v;
      }
    }
    try {
      await widget.vault.saveItem(_draft);
      if (mounted) Navigator.pop(context);
    } on Object catch (e) {
      if (mounted) {
        setState(() => _busy = false);
        showToast(context, 'Could not save: $e');
      }
    }
  }

  Future<void> _cancel() async {
    if (_dirty) {
      final discard = await confirm(context,
          title: 'Discard changes?', message: 'Your edits to this item will be lost.', confirmLabel: 'Discard', destructive: true);
      if (!discard) return;
    }
    if (mounted) Navigator.pop(context);
  }

  Future<void> _addFiles() async {
    final result = await FilePicker.platform.pickFiles(allowMultiple: true, withData: true, dialogTitle: 'Add files');
    if (result == null) return;
    setState(() => _busy = true);
    try {
      for (final f in result.files) {
        final bytes = f.bytes;
        if (bytes == null) continue;
        final attachment = await widget.vault.storeAttachment(f.name, bytes);
        _draft.attachments.add(attachment);
        if (_title.text.trim().isEmpty && _draft.type == ItemType.document) {
          _title.text = f.name.contains('.') ? f.name.substring(0, f.name.lastIndexOf('.')) : f.name;
        }
      }
      _dirty = true;
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _generate(String key) async {
    final value = await showGeneratorDialog(context, forField: true);
    if (value != null) {
      _fields[key]!.text = value;
      setState(() => _revealed.add(key));
    }
  }

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final typeLabel = _draft.type.label.toLowerCase();
    return CallbackShortcuts(
      bindings: {
        const SingleActivator(LogicalKeyboardKey.keyS, control: true): _save,
        const SingleActivator(LogicalKeyboardKey.escape): _cancel,
      },
      child: Scaffold(
        backgroundColor: c.panel,
        appBar: AppBar(
          backgroundColor: c.panel,
          surfaceTintColor: Colors.transparent,
          automaticallyImplyLeading: false,
          titleSpacing: 24,
          toolbarHeight: 64,
          title: Text(widget.isNew ? 'New $typeLabel' : 'Edit $typeLabel', style: Theme.of(context).textTheme.titleLarge),
          actions: [
            TextButton(onPressed: _busy ? null : _cancel, child: const Text('Cancel')),
            const SizedBox(width: 6),
            FilledButton(onPressed: _busy ? null : _save, child: const Text('Save')),
            const SizedBox(width: 18),
          ],
        ),
        body: ListView(
          padding: const EdgeInsets.fromLTRB(24, 8, 24, 32),
          children: [
            TextField(
              controller: _title,
              autofocus: widget.isNew,
              textCapitalization: TextCapitalization.sentences,
              style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w700),
              decoration: InputDecoration(labelText: 'Name', hintText: _titleHint, errorText: _titleError),
              onChanged: (_) => _titleError == null ? null : setState(() => _titleError = null),
            ),
            for (final spec in _draft.type.fields) ...[
              const SizedBox(height: 16),
              _fieldEditor(spec),
            ],
            const SizedBox(height: 16),
            TextField(
              controller: _notes,
              minLines: _draft.type == ItemType.note ? 8 : 3,
              maxLines: null,
              keyboardType: TextInputType.multiline,
              decoration: const InputDecoration(labelText: 'Notes', hintText: 'Anything else worth keeping'),
            ),
            const SizedBox(height: 22),
            _attachmentEditor(),
          ],
        ),
      ),
    );
  }

  String get _titleHint => switch (_draft.type) {
        ItemType.login => 'Steam, Bank, Work email…',
        ItemType.note => 'Wi-Fi password, alarm code…',
        ItemType.card => 'Everyday Visa',
        ItemType.identity => 'Passport',
        ItemType.document => 'Home insurance policy',
      };

  Widget _fieldEditor(FieldSpec spec) {
    final controller = _fields[spec.key]!;
    if (spec.kind == FieldKind.password) {
      final visible = _revealed.contains(spec.key);
      return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        TextField(
          controller: controller,
          obscureText: !visible,
          enableSuggestions: false,
          autocorrect: false,
          style: const TextStyle(fontFamily: 'Consolas', fontFamilyFallback: ['Menlo', 'monospace'], fontSize: 15),
          onChanged: (_) => setState(() {}),
          decoration: InputDecoration(
            labelText: spec.label,
            hintText: spec.hint,
            suffixIcon: Row(mainAxisSize: MainAxisSize.min, children: [
              IconButton(
                tooltip: visible ? 'Hide' : 'Show',
                icon: Icon(visible ? Icons.visibility_off_outlined : Icons.visibility_outlined, size: 19),
                onPressed: () => setState(() => visible ? _revealed.remove(spec.key) : _revealed.add(spec.key)),
              ),
              if (spec.key == 'password')
                IconButton(
                  tooltip: 'Generate a strong password',
                  icon: const Icon(Icons.auto_awesome_outlined, size: 19),
                  onPressed: () => _generate(spec.key),
                ),
              const SizedBox(width: 4),
            ]),
          ),
        ),
        if (spec.key == 'password' && controller.text.isNotEmpty) ...[
          const SizedBox(height: 8),
          StrengthMeter(password: controller.text),
        ],
      ]);
    }
    return TextField(
      controller: controller,
      maxLines: spec.multiline ? null : 1,
      minLines: spec.multiline ? 2 : 1,
      autocorrect: false,
      keyboardType: switch (spec.kind) {
        FieldKind.email => TextInputType.emailAddress,
        FieldKind.phone => TextInputType.phone,
        FieldKind.url => TextInputType.url,
        FieldKind.number => TextInputType.number,
        FieldKind.date => TextInputType.datetime,
        _ => spec.multiline ? TextInputType.multiline : TextInputType.text,
      },
      decoration: InputDecoration(labelText: spec.label, hintText: spec.hint),
    );
  }

  Widget _attachmentEditor() {
    final c = context.colors;
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Row(children: [
        Expanded(child: Text('Files', style: TextStyle(fontWeight: FontWeight.w700, color: c.muted))),
        TextButton.icon(
          onPressed: _busy ? null : _addFiles,
          icon: const Icon(Icons.attach_file_rounded, size: 18),
          label: const Text('Add files'),
        ),
      ]),
      if (_draft.attachments.isEmpty)
        InkWell(
          onTap: _busy ? null : _addFiles,
          borderRadius: BorderRadius.circular(12),
          child: Container(
            padding: const EdgeInsets.symmetric(vertical: 22),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: c.border, width: 1.4),
            ),
            child: Column(children: [
              Icon(Icons.upload_file_outlined, color: c.faint),
              const SizedBox(height: 6),
              Text('Scans, PDFs, photos. Files are encrypted before they are stored.',
                  textAlign: TextAlign.center, style: TextStyle(color: c.faint, fontSize: 13)),
            ]),
          ),
        ),
      for (final a in List.of(_draft.attachments))
        ListTile(
          contentPadding: EdgeInsets.zero,
          leading: Icon(a.isImage ? Icons.image_outlined : Icons.insert_drive_file_outlined, color: c.muted),
          title: Text(a.name, maxLines: 1, overflow: TextOverflow.ellipsis),
          subtitle: Text(formatBytes(a.size)),
          trailing: IconButton(
            tooltip: 'Remove',
            icon: Icon(Icons.close_rounded, color: c.danger, size: 19),
            onPressed: () => setState(() {
              _draft.attachments.remove(a);
              _dirty = true;
            }),
          ),
        ),
      if (_busy) const Padding(padding: EdgeInsets.only(top: 8), child: LinearProgressIndicator()),
    ]);
  }
}

/// Password generator. With [forField] it returns the chosen password;
/// otherwise it offers a Copy button.
Future<String?> showGeneratorDialog(BuildContext context, {bool forField = false, VaultController? vault}) =>
    showDialog<String>(context: context, builder: (_) => _GeneratorDialog(forField: forField, vault: vault));

class _GeneratorDialog extends StatefulWidget {
  const _GeneratorDialog({required this.forField, this.vault});
  final bool forField;
  final VaultController? vault;

  @override
  State<_GeneratorDialog> createState() => _GeneratorDialogState();
}

class _GeneratorDialogState extends State<_GeneratorDialog> {
  GeneratorOptions _options = const GeneratorOptions();
  late String _value = generatePassword(_options);

  void _update(GeneratorOptions o) => setState(() {
        _options = o;
        _value = generatePassword(o);
      });

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    Widget toggle(String label, bool value, GeneratorOptions Function(bool) change) => SwitchListTile(
          contentPadding: EdgeInsets.zero,
          dense: true,
          title: Text(label, style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14)),
          value: value,
          onChanged: (v) => _update(change(v)),
        );
    return AlertDialog(
      title: const Text('Password generator'),
      content: SizedBox(
        width: 440,
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(18),
            decoration: BoxDecoration(color: c.subtle, borderRadius: BorderRadius.circular(12)),
            child: Row(children: [
              Expanded(
                child: SelectableText(_value,
                    style: const TextStyle(
                        fontFamily: 'Consolas', fontFamilyFallback: ['Menlo', 'monospace'], fontSize: 17, fontWeight: FontWeight.w600)),
              ),
              IconButton(tooltip: 'Generate another', onPressed: () => _update(_options), icon: const Icon(Icons.refresh_rounded)),
            ]),
          ),
          const SizedBox(height: 10),
          StrengthMeter(password: _value),
          const SizedBox(height: 14),
          Row(children: [
            const Text('Length', style: TextStyle(fontWeight: FontWeight.w600)),
            Expanded(
              child: Slider(
                min: 8,
                max: 64,
                divisions: 56,
                value: _options.length.toDouble(),
                label: '${_options.length}',
                onChanged: (v) => _update(_options.copyWith(length: v.round())),
              ),
            ),
            SizedBox(width: 28, child: Text('${_options.length}', style: const TextStyle(fontWeight: FontWeight.w700))),
          ]),
          toggle('Uppercase A–Z', _options.upper, (v) => _options.copyWith(upper: v)),
          toggle('Lowercase a–z', _options.lower, (v) => _options.copyWith(lower: v)),
          toggle('Digits 0–9', _options.digits, (v) => _options.copyWith(digits: v)),
          toggle('Symbols !@#', _options.symbols, (v) => _options.copyWith(symbols: v)),
          toggle('Avoid look-alikes (l, 1, O, 0)', _options.avoidAmbiguous, (v) => _options.copyWith(avoidAmbiguous: v)),
        ]),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close')),
        FilledButton(
          onPressed: () async {
            if (widget.forField) {
              Navigator.pop(context, _value);
            } else {
              await widget.vault?.copy(_value);
              if (context.mounted) {
                Navigator.pop(context);
                showToast(context, 'Password copied');
              }
            }
          },
          child: Text(widget.forField ? 'Use password' : 'Copy'),
        ),
      ],
    );
  }
}
