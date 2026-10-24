import 'dart:io';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../state/vault_controller.dart';
import 'widgets.dart';

bool get isDesktop => Platform.isWindows || Platform.isMacOS || Platform.isLinux;

/// Asks where to save [bytes] and writes them. Returns false if cancelled.
Future<bool> saveBytesAs(String fileName, Uint8List bytes, {String? dialogTitle}) async {
  final path = await FilePicker.platform.saveFile(
    dialogTitle: dialogTitle ?? 'Save a copy',
    fileName: fileName,
    bytes: isDesktop ? null : bytes,
  );
  if (path == null) return false;
  if (isDesktop) await File(path).writeAsBytes(bytes, flush: true);
  return true;
}

Future<void> exportBackupFlow(BuildContext context, VaultController vault) async {
  final stamp = DateTime.now().toIso8601String().substring(0, 10);
  final name = 'LocalGateKeys-backup-$stamp.lgkbackup';
  try {
    if (isDesktop) {
      final path = await FilePicker.platform.saveFile(
        dialogTitle: 'Save encrypted backup',
        fileName: name,
        type: FileType.custom,
        allowedExtensions: const ['lgkbackup'],
      );
      if (path == null) return;
      await vault.exportBackup(File(path));
    } else {
      final tmp = File('${Directory.systemTemp.path}/$name');
      await vault.exportBackup(tmp);
      final saved = await FilePicker.platform.saveFile(fileName: name, bytes: await tmp.readAsBytes());
      await tmp.delete();
      if (saved == null) return;
    }
    if (context.mounted) showToast(context, 'Encrypted backup saved');
  } on Object catch (e) {
    if (context.mounted) showToast(context, 'Could not save the backup: $e');
  }
}

Future<void> restoreBackupFlow(BuildContext context, VaultController vault) async {
  final result = await FilePicker.platform.pickFiles(
    dialogTitle: 'Choose a LocalGateKeys backup',
    type: isDesktop ? FileType.custom : FileType.any,
    allowedExtensions: isDesktop ? const ['lgkbackup'] : null,
  );
  final path = result?.files.single.path;
  if (path == null || !context.mounted) return;
  final ok = await confirm(
    context,
    title: 'Replace this vault?',
    message: 'Everything in the vault on this device will be replaced by the backup. '
        'The current vault file is kept next to it as vault.lgk.before-restore.',
    confirmLabel: 'Continue',
    destructive: true,
  );
  if (!ok || !context.mounted) return;
  final password = await askPassword(
    context,
    title: 'Backup password',
    message: 'Enter the master password that was in use when this backup was made.',
    action: 'Restore',
  );
  if (password == null) return;
  final error = await vault.restoreBackup(File(path), password);
  if (context.mounted) showToast(context, error ?? 'Backup restored');
}

Future<String?> askPassword(BuildContext context,
    {required String title, required String message, required String action}) {
  final controller = TextEditingController();
  return showDialog<String>(
    context: context,
    builder: (context) => AlertDialog(
      title: Text(title),
      content: SizedBox(
        width: 380,
        child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(message),
          const SizedBox(height: 16),
          TextField(
            controller: controller,
            autofocus: true,
            obscureText: true,
            decoration: const InputDecoration(hintText: 'Master password'),
            onSubmitted: (v) => Navigator.pop(context, v),
          ),
        ]),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(context, controller.text), child: Text(action)),
      ],
    ),
  );
}
