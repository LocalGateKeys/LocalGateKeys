import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

/// Non-secret preferences needed before the vault is unlocked (appearance).
/// Everything else lives inside the encrypted vault.
class AppPrefs {
  AppPrefs(this._file);

  final File _file;
  final ValueNotifier<ThemeMode> themeMode = ValueNotifier(ThemeMode.system);

  Future<void> load() async {
    try {
      final json = jsonDecode(await _file.readAsString()) as Map<String, dynamic>;
      themeMode.value = ThemeMode.values.byName(json['theme'] as String? ?? 'system');
    } on Object {
      // Missing or unreadable preferences fall back to defaults.
    }
  }

  Future<void> setThemeMode(ThemeMode mode) async {
    themeMode.value = mode;
    await _file.parent.create(recursive: true);
    await _file.writeAsString(jsonEncode({'theme': mode.name}));
  }
}
