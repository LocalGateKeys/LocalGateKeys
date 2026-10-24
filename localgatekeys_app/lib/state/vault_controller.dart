import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

import '../core/crypto.dart';
import '../core/csv_import.dart';
import '../core/models.dart';
import '../core/security_report.dart';
import '../core/vault_store.dart';

enum VaultStatus { loading, noVault, locked, unlocked }

enum ItemFilter { all, favorites, login, note, card, identity, document, trash }

enum SortOrder { recent, name, updated }

class VaultController extends ChangeNotifier with WidgetsBindingObserver {
  VaultController(this.store);

  final VaultStore store;

  VaultStatus status = VaultStatus.loading;
  List<VaultItem> _items = [];
  VaultSettings settings = VaultSettings();
  String? selectedId;
  String query = '';
  ItemFilter filter = ItemFilter.all;
  SortOrder sort = SortOrder.recent;

  /// Set while the app is in the background on mobile, to hide content from
  /// the app switcher snapshot.
  bool obscured = false;

  /// Shown once after a vault is created, until the user confirms saving it.
  String? pendingRecoveryCode;

  List<int>? _vaultKey;
  VaultEnvelope? _envelope;
  DateTime _lastActivity = DateTime.now();
  Timer? _autoLockTimer;
  Timer? _clipboardTimer;
  String? _clipboardValue;
  int _failedAttempts = 0;
  DateTime? _retryAfter;

  /// Broadcast when the vault locks so open dialogs and pages can close.
  final ValueNotifier<int> lockEvents = ValueNotifier(0);

  bool get hasRecoveryCode => _envelope?.recoveryWrappedKey != null;
  DateTime? get retryAfter => _retryAfter;
  List<VaultItem> get allItems => List.unmodifiable(_items);

  Future<void> init() async {
    WidgetsBinding.instance.addObserver(this);
    status = await store.exists() ? VaultStatus.locked : VaultStatus.noVault;
    notifyListeners();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _autoLockTimer?.cancel();
    _clipboardTimer?.cancel();
    super.dispose();
  }

  // ---------------------------------------------------------------- lifecycle

  bool get _isMobile => Platform.isIOS || Platform.isAndroid;

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (!_isMobile) {
      if (state == AppLifecycleState.hidden && settings.lockOnBackground) lock();
      return;
    }
    final background = state != AppLifecycleState.resumed;
    if (obscured != background) {
      obscured = background;
      notifyListeners();
    }
    if ((state == AppLifecycleState.paused || state == AppLifecycleState.hidden) &&
        settings.lockOnBackground) {
      lock();
    }
  }

  void recordActivity() => _lastActivity = DateTime.now();

  void _startAutoLock() {
    _autoLockTimer?.cancel();
    _lastActivity = DateTime.now();
    _autoLockTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      if (status != VaultStatus.unlocked || settings.autoLockMinutes == 0) return;
      if (DateTime.now().difference(_lastActivity).inSeconds >= settings.autoLockMinutes * 60) {
        lock();
      }
    });
  }

  Duration get timeUntilAutoLock {
    if (settings.autoLockMinutes == 0) return Duration.zero;
    final left = Duration(minutes: settings.autoLockMinutes) - DateTime.now().difference(_lastActivity);
    return left.isNegative ? Duration.zero : left;
  }

  // ----------------------------------------------------------- create / unlock

  /// Creates a new vault and returns its recovery code, which is shown once.
  Future<String> createVault(String password) async {
    final vaultKey = VaultCrypto.randomBytes(32);
    final recoveryCode = VaultCrypto.newRecoveryCode();
    final passwordKdf = KdfParams.fresh();
    final recoveryKdf = KdfParams.fresh();
    final passwordKek = await VaultCrypto.deriveKey(password, passwordKdf);
    final recoveryKek =
        await VaultCrypto.deriveKey(VaultCrypto.normalizeRecoveryCode(recoveryCode), recoveryKdf);
    _envelope = VaultEnvelope(
      passwordKdf: passwordKdf,
      passwordWrappedKey:
          await VaultCrypto.seal(passwordKek, vaultKey, VaultEnvelope.aadPasswordKey),
      recoveryKdf: recoveryKdf,
      recoveryWrappedKey:
          await VaultCrypto.seal(recoveryKek, vaultKey, VaultEnvelope.aadRecoveryKey),
      data: Uint8List(0),
      savedAt: DateTime.now(),
    );
    _vaultKey = vaultKey;
    _items = [];
    settings = VaultSettings(lockOnBackground: _isMobile);
    await _save();
    status = VaultStatus.unlocked;
    pendingRecoveryCode = recoveryCode;
    _startAutoLock();
    notifyListeners();
    return recoveryCode;
  }

  void finishOnboarding() {
    pendingRecoveryCode = null;
    recordActivity();
    notifyListeners();
  }

  /// Returns null on success, or a message to show.
  Future<String?> unlock(String password) async {
    if (_retryAfter != null && DateTime.now().isBefore(_retryAfter!)) {
      final wait = _retryAfter!.difference(DateTime.now()).inSeconds + 1;
      return 'Too many attempts. Try again in $wait s.';
    }
    try {
      final envelope = await store.read();
      final kek = await VaultCrypto.deriveKey(password, envelope.passwordKdf);
      final key =
          await VaultCrypto.open(kek, envelope.passwordWrappedKey, VaultEnvelope.aadPasswordKey);
      await _openWith(envelope, key);
      return null;
    } on VaultAuthError {
      return _failed('That password is not correct.');
    } on FormatException catch (e) {
      return e.message;
    }
  }

  /// Unlocks with the recovery code and sets a new master password.
  Future<String?> recover(String code, String newPassword) async {
    try {
      final envelope = await store.read();
      if (envelope.recoveryKdf == null || envelope.recoveryWrappedKey == null) {
        return 'This vault has no recovery code.';
      }
      final kek = await VaultCrypto.deriveKey(
          VaultCrypto.normalizeRecoveryCode(code), envelope.recoveryKdf!);
      final key =
          await VaultCrypto.open(kek, envelope.recoveryWrappedKey!, VaultEnvelope.aadRecoveryKey);
      await _openWith(envelope, key);
      await _rewrapPassword(newPassword);
      return null;
    } on VaultAuthError {
      return _failed('That recovery code is not correct.');
    }
  }

  String _failed(String message) {
    _failedAttempts++;
    if (_failedAttempts >= 3) {
      final seconds = 1 << (_failedAttempts - 2).clamp(0, 5);
      _retryAfter = DateTime.now().add(Duration(seconds: seconds));
    }
    return message;
  }

  Future<void> _openWith(VaultEnvelope envelope, List<int> key) async {
    final payload = envelope.data.isEmpty
        ? <String, dynamic>{}
        : jsonDecode(utf8.decode(await VaultCrypto.open(key, envelope.data, VaultEnvelope.aadData)))
            as Map<String, dynamic>;
    _envelope = envelope;
    _vaultKey = key;
    _items = [
      for (final i in payload['items'] as List? ?? const [])
        VaultItem.fromJson(Map<String, dynamic>.from(i as Map))
    ];
    settings = VaultSettings.fromJson(payload['settings'] as Map<String, dynamic>?);
    _failedAttempts = 0;
    _retryAfter = null;
    status = VaultStatus.unlocked;
    _startAutoLock();
    notifyListeners();
    unawaited(store.removeOrphanBlobs(_referencedBlobIds()));
  }

  void lock() {
    if (status != VaultStatus.unlocked) return;
    _autoLockTimer?.cancel();
    _clearClipboardNow();
    _vaultKey = null;
    pendingRecoveryCode = null;
    _items = [];
    selectedId = null;
    query = '';
    filter = ItemFilter.all;
    status = VaultStatus.locked;
    lockEvents.value++;
    notifyListeners();
  }

  // ------------------------------------------------------------------- saving

  Future<void> _save() async {
    final key = _vaultKey;
    final envelope = _envelope;
    if (key == null || envelope == null) throw StateError('Vault is locked');
    final payload = utf8.encode(jsonEncode({
      'items': [for (final i in _items) i.toJson()],
      'settings': settings.toJson(),
    }));
    envelope
      ..data = await VaultCrypto.seal(key, payload, VaultEnvelope.aadData)
      ..savedAt = DateTime.now();
    await store.write(envelope);
  }

  Set<String> _referencedBlobIds() =>
      {for (final i in _items) for (final a in i.attachments) a.id};

  Future<void> _rewrapPassword(String password) async {
    final kdf = KdfParams.fresh();
    final kek = await VaultCrypto.deriveKey(password, kdf);
    _envelope!
      ..passwordKdf = kdf
      ..passwordWrappedKey =
          await VaultCrypto.seal(kek, _vaultKey!, VaultEnvelope.aadPasswordKey);
    await _save();
  }

  Future<bool> verifyPassword(String password) async {
    final envelope = _envelope;
    if (envelope == null) return false;
    try {
      final kek = await VaultCrypto.deriveKey(password, envelope.passwordKdf);
      await VaultCrypto.open(kek, envelope.passwordWrappedKey, VaultEnvelope.aadPasswordKey);
      return true;
    } on VaultAuthError {
      return false;
    }
  }

  Future<bool> changePassword(String current, String next) async {
    if (!await verifyPassword(current)) return false;
    await _rewrapPassword(next);
    return true;
  }

  Future<String> regenerateRecoveryCode() async {
    final code = VaultCrypto.newRecoveryCode();
    final kdf = KdfParams.fresh();
    final kek = await VaultCrypto.deriveKey(VaultCrypto.normalizeRecoveryCode(code), kdf);
    _envelope!
      ..recoveryKdf = kdf
      ..recoveryWrappedKey = await VaultCrypto.seal(kek, _vaultKey!, VaultEnvelope.aadRecoveryKey);
    await _save();
    notifyListeners();
    return code;
  }

  Future<void> updateSettings(void Function(VaultSettings s) change) async {
    change(settings);
    await _save();
    notifyListeners();
  }

  // -------------------------------------------------------------------- items

  VaultItem? byId(String? id) {
    if (id == null) return null;
    for (final i in _items) {
      if (i.id == id) return i;
    }
    return null;
  }

  VaultItem? get selected => byId(selectedId);

  void select(String? id) {
    selectedId = id;
    notifyListeners();
  }

  void setQuery(String value) {
    query = value;
    notifyListeners();
  }

  void setFilter(ItemFilter value) {
    filter = value;
    notifyListeners();
  }

  void setSort(SortOrder value) {
    sort = value;
    notifyListeners();
  }

  int countFor(ItemFilter f) => _items.where((i) => _matchesFilter(i, f)).length;

  bool _matchesFilter(VaultItem i, ItemFilter f) => switch (f) {
        ItemFilter.trash => i.inTrash,
        ItemFilter.all => !i.inTrash,
        ItemFilter.favorites => !i.inTrash && i.favorite,
        ItemFilter.login => !i.inTrash && i.type == ItemType.login,
        ItemFilter.note => !i.inTrash && i.type == ItemType.note,
        ItemFilter.card => !i.inTrash && i.type == ItemType.card,
        ItemFilter.identity => !i.inTrash && i.type == ItemType.identity,
        ItemFilter.document => !i.inTrash && i.type == ItemType.document,
      };

  List<VaultItem> get visibleItems {
    final q = query.trim().toLowerCase();
    final list = _items.where((i) {
      if (!_matchesFilter(i, filter)) return false;
      if (q.isEmpty) return true;
      return i.title.toLowerCase().contains(q) ||
          i.field('username').toLowerCase().contains(q) ||
          i.field('url').toLowerCase().contains(q) ||
          i.notes.toLowerCase().contains(q) ||
          i.attachments.any((a) => a.name.toLowerCase().contains(q));
    }).toList();
    int base(VaultItem a, VaultItem b) => switch (sort) {
          SortOrder.name => a.title.toLowerCase().compareTo(b.title.toLowerCase()),
          SortOrder.updated => b.updatedAt.compareTo(a.updatedAt),
          SortOrder.recent =>
            (b.lastUsedAt ?? b.updatedAt).compareTo(a.lastUsedAt ?? a.updatedAt),
        };
    // Favourites first unless searching or sorting alphabetically.
    final favouritesFirst = q.isEmpty && filter != ItemFilter.trash && sort != SortOrder.name;
    list.sort((a, b) {
      if (favouritesFirst && a.favorite != b.favorite) return a.favorite ? -1 : 1;
      return base(a, b);
    });
    return list;
  }

  Future<void> saveItem(VaultItem item) async {
    item.title = item.title.trim().isEmpty ? 'Untitled' : item.title.trim();
    item.updatedAt = DateTime.now();
    final index = _items.indexWhere((i) => i.id == item.id);
    if (index >= 0) {
      final previous = _items[index];
      final oldPassword = previous.field('password');
      if (oldPassword.isNotEmpty && oldPassword != item.field('password')) {
        item.passwordHistory.insert(0, HistoryEntry(oldPassword, DateTime.now()));
        if (item.passwordHistory.length > 20) item.passwordHistory.removeRange(20, item.passwordHistory.length);
      }
      final kept = {for (final a in item.attachments) a.id};
      final removed = previous.attachments.where((a) => !kept.contains(a.id)).toList();
      _items[index] = item;
      await _save();
      for (final a in removed) {
        await store.deleteBlob(a.id);
      }
    } else {
      _items.add(item);
      await _save();
    }
    selectedId = item.id;
    notifyListeners();
  }

  Future<void> toggleFavorite(VaultItem item) async {
    item.favorite = !item.favorite;
    await _save();
    notifyListeners();
  }

  Future<void> moveToTrash(VaultItem item) async {
    item.trashedAt = DateTime.now();
    if (selectedId == item.id) selectedId = null;
    await _save();
    notifyListeners();
  }

  Future<void> restore(VaultItem item) async {
    item.trashedAt = null;
    await _save();
    notifyListeners();
  }

  Future<void> deleteForever(VaultItem item) async {
    _items.removeWhere((i) => i.id == item.id);
    if (selectedId == item.id) selectedId = null;
    await _save();
    for (final a in item.attachments) {
      await store.deleteBlob(a.id);
    }
    notifyListeners();
  }

  Future<void> emptyTrash() async {
    final trashed = _items.where((i) => i.inTrash).toList();
    for (final i in trashed) {
      _items.remove(i);
    }
    if (trashed.any((i) => i.id == selectedId)) selectedId = null;
    await _save();
    for (final i in trashed) {
      for (final a in i.attachments) {
        await store.deleteBlob(a.id);
      }
    }
    notifyListeners();
  }

  Future<void> markUsed(VaultItem item) async {
    item.lastUsedAt = DateTime.now();
    await _save();
  }

  // -------------------------------------------------------------- attachments

  /// Encrypts and stores a file. The caller adds the returned attachment to
  /// an item and saves it; unreferenced files are cleaned up on next unlock.
  Future<Attachment> storeAttachment(String name, Uint8List bytes) async {
    final id = newId();
    final sealed = await VaultCrypto.sealLarge(_vaultKey!, bytes, VaultEnvelope.aadBlob(id));
    await store.writeBlob(id, sealed);
    return Attachment(id: id, name: name, size: bytes.length, addedAt: DateTime.now());
  }

  Future<Uint8List> readAttachment(Attachment attachment) async {
    final sealed = await store.readBlob(attachment.id);
    return VaultCrypto.openLarge(_vaultKey!, sealed, VaultEnvelope.aadBlob(attachment.id));
  }

  // ---------------------------------------------------------------- clipboard

  Future<void> copy(String value, {bool secret = true, VaultItem? item}) async {
    await Clipboard.setData(ClipboardData(text: value));
    _clipboardTimer?.cancel();
    if (item != null) unawaited(markUsed(item));
    if (!secret || settings.clipboardSeconds == 0) {
      _clipboardValue = null;
      return;
    }
    _clipboardValue = value;
    _clipboardTimer = Timer(Duration(seconds: settings.clipboardSeconds), _clearClipboardNow);
  }

  Future<void> _clearClipboardNow() async {
    _clipboardTimer?.cancel();
    final value = _clipboardValue;
    _clipboardValue = null;
    if (value == null) return;
    final current = await Clipboard.getData(Clipboard.kTextPlain);
    // Only clear if the user has not copied something else since.
    if (current?.text == value) await Clipboard.setData(const ClipboardData(text: ''));
  }

  // ------------------------------------------------------------ import/export

  SecurityReport get report =>
      SecurityReport.build(_items, settings, hasRecoveryCode: hasRecoveryCode);

  Future<void> exportBackup(File target) async {
    await _save();
    await store.exportBackup(target, _referencedBlobIds());
    await updateSettings((s) => s.lastBackupAt = DateTime.now());
  }

  /// Checks the backup's password, then replaces the current vault with it
  /// and leaves it unlocked.
  Future<String?> restoreBackup(File source, String password) async {
    final BackupContents backup;
    try {
      backup = await VaultStore.readBackup(source);
    } on FormatException catch (e) {
      return e.message;
    }
    try {
      final kek = await VaultCrypto.deriveKey(password, backup.envelope.passwordKdf);
      await VaultCrypto.open(kek, backup.envelope.passwordWrappedKey, VaultEnvelope.aadPasswordKey);
    } on VaultAuthError {
      return 'That is not the password for this backup.';
    }
    lock();
    await store.replaceWith(backup);
    status = VaultStatus.locked;
    notifyListeners();
    return unlock(password);
  }

  Future<int> importCsv(String text) async {
    final imported = loginsFromCsv(text);
    _items.addAll(imported);
    await _save();
    notifyListeners();
    return imported.length;
  }
}
