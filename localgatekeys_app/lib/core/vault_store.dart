import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'crypto.dart';

/// The encrypted vault header and payload as stored on disk.
///
/// A random 256-bit vault key encrypts the item data and every attachment.
/// That key is itself wrapped twice: once under a key derived from the master
/// password and once under a key derived from the recovery code, so either can
/// open the vault and changing the password does not re-encrypt any data.
class VaultEnvelope {
  VaultEnvelope({
    required this.passwordKdf,
    required this.passwordWrappedKey,
    required this.recoveryKdf,
    required this.recoveryWrappedKey,
    required this.data,
    required this.savedAt,
  });

  factory VaultEnvelope.fromJson(Map<String, dynamic> json) {
    if (json['format'] != formatName) throw const FormatException('Not a LocalGateKeys vault');
    final version = json['version'] as int? ?? 0;
    if (version > formatVersion) {
      throw const FormatException('This vault was created by a newer version of LocalGateKeys');
    }
    final keys = json['keys'] as Map<String, dynamic>;
    final password = keys['password'] as Map<String, dynamic>;
    final recovery = keys['recovery'] as Map<String, dynamic>?;
    return VaultEnvelope(
      passwordKdf: KdfParams.fromJson(password['kdf'] as Map<String, dynamic>),
      passwordWrappedKey: base64Decode(password['wrapped'] as String),
      recoveryKdf:
          recovery == null ? null : KdfParams.fromJson(recovery['kdf'] as Map<String, dynamic>),
      recoveryWrappedKey: recovery == null ? null : base64Decode(recovery['wrapped'] as String),
      data: base64Decode(json['data'] as String),
      savedAt: DateTime.parse(json['savedAt'] as String),
    );
  }

  static const formatName = 'localgatekeys-vault';
  static const formatVersion = 1;
  static const aadPasswordKey = 'lgk:v1:key:password';
  static const aadRecoveryKey = 'lgk:v1:key:recovery';
  static const aadData = 'lgk:v1:data';
  static String aadBlob(String id) => 'lgk:v1:blob:$id';

  KdfParams passwordKdf;
  Uint8List passwordWrappedKey;
  KdfParams? recoveryKdf;
  Uint8List? recoveryWrappedKey;
  Uint8List data;
  DateTime savedAt;

  Map<String, dynamic> toJson() => {
        'format': formatName,
        'version': formatVersion,
        'keys': {
          'password': {'kdf': passwordKdf.toJson(), 'wrapped': base64Encode(passwordWrappedKey)},
          if (recoveryKdf != null && recoveryWrappedKey != null)
            'recovery': {'kdf': recoveryKdf!.toJson(), 'wrapped': base64Encode(recoveryWrappedKey!)},
        },
        'data': base64Encode(data),
        'savedAt': savedAt.toUtc().toIso8601String(),
      };
}

class BackupContents {
  BackupContents(this.envelope, this.blobs);
  final VaultEnvelope envelope;
  final Map<String, Uint8List> blobs;
}

/// File-system layout of a vault folder:
///   vault.lgk        encrypted header + item data (JSON envelope)
///   vault.lgk.bak    the previous successful save
///   blobs/<id>.bin   encrypted attachments
class VaultStore {
  VaultStore(this.dir);

  final Directory dir;

  File get _vaultFile => File('${dir.path}${Platform.pathSeparator}vault.lgk');
  File get _previousFile => File('${_vaultFile.path}.bak');
  Directory get _blobDir => Directory('${dir.path}${Platform.pathSeparator}blobs');
  File _blobFile(String id) => File('${_blobDir.path}${Platform.pathSeparator}$id.bin');

  String get location => dir.path;

  Future<bool> exists() => _vaultFile.exists();

  Future<VaultEnvelope> read() async {
    try {
      return _parse(await _vaultFile.readAsString());
    } on Object {
      // A damaged main file falls back to the previous save.
      if (await _previousFile.exists()) {
        return _parse(await _previousFile.readAsString());
      }
      rethrow;
    }
  }

  VaultEnvelope _parse(String text) =>
      VaultEnvelope.fromJson(jsonDecode(text) as Map<String, dynamic>);

  Future<void> write(VaultEnvelope envelope) async {
    await dir.create(recursive: true);
    if (await _vaultFile.exists()) {
      await _vaultFile.copy(_previousFile.path);
    }
    await _atomicWrite(_vaultFile, utf8.encode(jsonEncode(envelope.toJson())));
  }

  Future<void> writeBlob(String id, Uint8List sealed) async {
    await _blobDir.create(recursive: true);
    await _atomicWrite(_blobFile(id), sealed);
  }

  Future<Uint8List> readBlob(String id) => _blobFile(id).readAsBytes();

  Future<void> deleteBlob(String id) async {
    final f = _blobFile(id);
    if (await f.exists()) await f.delete();
  }

  Future<Set<String>> blobIds() async {
    if (!await _blobDir.exists()) return {};
    return {
      await for (final e in _blobDir.list())
        if (e is File && e.path.endsWith('.bin'))
          e.uri.pathSegments.last.replaceAll('.bin', '')
    };
  }

  /// Removes attachment files no item refers to (left behind by a crash
  /// between saving a blob and saving the item list).
  Future<void> removeOrphanBlobs(Set<String> referenced) async {
    for (final id in await blobIds()) {
      if (!referenced.contains(id)) await deleteBlob(id);
    }
  }

  Future<void> exportBackup(File target, Set<String> blobIdsToInclude) async {
    final envelope = await read();
    final blobs = <String, String>{};
    for (final id in blobIdsToInclude) {
      blobs[id] = base64Encode(await readBlob(id));
    }
    final json = {
      'format': 'localgatekeys-backup',
      'version': 1,
      'createdAt': DateTime.now().toUtc().toIso8601String(),
      'vault': envelope.toJson(),
      'blobs': blobs,
    };
    await _atomicWrite(target, utf8.encode(jsonEncode(json)));
  }

  static Future<BackupContents> readBackup(File source) async {
    final json = jsonDecode(await source.readAsString()) as Map<String, dynamic>;
    if (json['format'] != 'localgatekeys-backup') {
      throw const FormatException('This file is not a LocalGateKeys backup');
    }
    return BackupContents(
      VaultEnvelope.fromJson(json['vault'] as Map<String, dynamic>),
      {
        for (final e in (json['blobs'] as Map<String, dynamic>).entries)
          e.key: base64Decode(e.value as String)
      },
    );
  }

  /// Replaces this vault with a backup. The current vault is kept as
  /// `vault.lgk.before-restore` until the next restore.
  Future<void> replaceWith(BackupContents backup) async {
    await dir.create(recursive: true);
    if (await _vaultFile.exists()) {
      await _vaultFile.copy('${_vaultFile.path}.before-restore');
    }
    for (final e in backup.blobs.entries) {
      if (!RegExp(r'^[0-9a-f]{24}$').hasMatch(e.key)) continue;
      await writeBlob(e.key, e.value);
    }
    await _atomicWrite(_vaultFile, utf8.encode(jsonEncode(backup.envelope.toJson())));
    if (await _previousFile.exists()) await _previousFile.delete();
  }

  static Future<void> _atomicWrite(File file, List<int> bytes) async {
    final tmp = File('${file.path}.tmp');
    await tmp.writeAsBytes(bytes, flush: true);
    await tmp.rename(file.path);
  }
}
