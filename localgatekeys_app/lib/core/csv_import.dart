import 'models.dart';

/// Parses RFC 4180 CSV (quoted fields, escaped quotes, CRLF or LF).
List<List<String>> parseCsv(String text) {
  final rows = <List<String>>[];
  var row = <String>[];
  final field = StringBuffer();
  var inQuotes = false;
  var i = 0;
  if (text.startsWith('﻿')) i = 1;
  for (; i < text.length; i++) {
    final c = text[i];
    if (inQuotes) {
      if (c == '"') {
        if (i + 1 < text.length && text[i + 1] == '"') {
          field.write('"');
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field.write(c);
      }
    } else if (c == '"') {
      inQuotes = true;
    } else if (c == ',') {
      row.add(field.toString());
      field.clear();
    } else if (c == '\n' || c == '\r') {
      if (c == '\r' && i + 1 < text.length && text[i + 1] == '\n') i++;
      row.add(field.toString());
      field.clear();
      if (row.any((f) => f.isNotEmpty)) rows.add(row);
      row = <String>[];
    } else {
      field.write(c);
    }
  }
  if (field.isNotEmpty || row.isNotEmpty) {
    row.add(field.toString());
    if (row.any((f) => f.isNotEmpty)) rows.add(row);
  }
  return rows;
}

/// Converts a password export from Chrome, Edge, Firefox, Bitwarden,
/// 1Password or KeePass (CSV) into login items. Unknown columns are ignored.
List<VaultItem> loginsFromCsv(String text) {
  final rows = parseCsv(text);
  if (rows.length < 2) return [];
  final header = [for (final h in rows.first) h.trim().toLowerCase()];
  int col(List<String> names) {
    for (final n in names) {
      final i = header.indexOf(n);
      if (i >= 0) return i;
    }
    return -1;
  }

  final title = col(['name', 'title', 'account']);
  final url = col(['url', 'login_uri', 'website', 'web site', 'origin']);
  final username = col(['username', 'login_username', 'user name', 'login name', 'email']);
  final password = col(['password', 'login_password']);
  final notes = col(['note', 'notes', 'comments', 'extra']);
  final totp = col(['totp', 'login_totp', 'otpauth', 'one-time password']);
  if (password < 0 && username < 0) {
    throw const FormatException('No username or password column found in this CSV file');
  }
  String at(List<String> row, int i) => i >= 0 && i < row.length ? row[i].trim() : '';

  final items = <VaultItem>[];
  for (final row in rows.skip(1)) {
    final item = VaultItem.create(ItemType.login);
    item.fields['username'] = at(row, username);
    item.fields['password'] = at(row, password);
    item.fields['url'] = at(row, url);
    item.fields['totp'] = at(row, totp);
    item.fields.removeWhere((_, v) => v.isEmpty);
    item.notes = at(row, notes);
    item.title = at(row, title).isNotEmpty ? at(row, title) : hostOf(at(row, url));
    if (item.title.isEmpty) item.title = item.fields['username'] ?? 'Imported login';
    if (item.fields.isEmpty && item.notes.isEmpty) continue;
    items.add(item);
  }
  return items;
}
