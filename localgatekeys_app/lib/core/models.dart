import 'dart:math';

enum ItemType { login, note, card, identity, document }

enum FieldKind { text, password, url, totp, email, phone, date, number }

class FieldSpec {
  const FieldSpec(this.key, this.label,
      {this.kind = FieldKind.text, this.hint = '', this.multiline = false});

  final String key;
  final String label;
  final FieldKind kind;
  final String hint;
  final bool multiline;

  bool get secret => kind == FieldKind.password;
}

extension ItemTypeInfo on ItemType {
  String get label => switch (this) {
        ItemType.login => 'Login',
        ItemType.note => 'Secure note',
        ItemType.card => 'Payment card',
        ItemType.identity => 'Identity',
        ItemType.document => 'Document',
      };

  String get pluralLabel => switch (this) {
        ItemType.login => 'Logins',
        ItemType.note => 'Notes',
        ItemType.card => 'Cards',
        ItemType.identity => 'Identities',
        ItemType.document => 'Documents',
      };

  List<FieldSpec> get fields => switch (this) {
        ItemType.login => const [
            FieldSpec('username', 'Username or email', hint: 'name@example.com'),
            FieldSpec('password', 'Password', kind: FieldKind.password),
            FieldSpec('url', 'Website or app', kind: FieldKind.url, hint: 'https://example.com'),
            FieldSpec('totp', 'One-time code secret',
                kind: FieldKind.totp, hint: 'Base32 secret or otpauth:// link'),
          ],
        ItemType.card => const [
            FieldSpec('cardholder', 'Name on card'),
            FieldSpec('number', 'Card number', kind: FieldKind.password, hint: '1234 5678 9012 3456'),
            FieldSpec('expiry', 'Expiry', hint: 'MM/YY'),
            FieldSpec('cvv', 'Security code', kind: FieldKind.password),
            FieldSpec('pin', 'PIN', kind: FieldKind.password),
          ],
        ItemType.identity => const [
            FieldSpec('fullName', 'Full name'),
            FieldSpec('email', 'Email', kind: FieldKind.email),
            FieldSpec('phone', 'Phone', kind: FieldKind.phone),
            FieldSpec('address', 'Address', multiline: true),
            FieldSpec('documentNumber', 'Passport or ID number', kind: FieldKind.password),
            FieldSpec('expires', 'Document expires', kind: FieldKind.date, hint: 'YYYY-MM-DD'),
          ],
        ItemType.note => const [],
        ItemType.document => const [
            FieldSpec('issuer', 'Issued by'),
            FieldSpec('expires', 'Expires', kind: FieldKind.date, hint: 'YYYY-MM-DD'),
          ],
      };
}

class Attachment {
  Attachment({
    required this.id,
    required this.name,
    required this.size,
    required this.addedAt,
  });

  factory Attachment.fromJson(Map<String, dynamic> json) => Attachment(
        id: json['id'] as String,
        name: json['name'] as String,
        size: json['size'] as int,
        addedAt: DateTime.parse(json['addedAt'] as String),
      );

  final String id;
  final String name;
  final int size;
  final DateTime addedAt;

  String get extension {
    final dot = name.lastIndexOf('.');
    return dot < 0 ? '' : name.substring(dot + 1).toLowerCase();
  }

  bool get isImage => const {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}.contains(extension);
  bool get isText => const {'txt', 'md', 'csv', 'json', 'log', 'xml'}.contains(extension);

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'size': size,
        'addedAt': addedAt.toIso8601String(),
      };
}

class HistoryEntry {
  HistoryEntry(this.value, this.changedAt);

  factory HistoryEntry.fromJson(Map<String, dynamic> json) =>
      HistoryEntry(json['value'] as String, DateTime.parse(json['changedAt'] as String));

  final String value;
  final DateTime changedAt;

  Map<String, dynamic> toJson() => {'value': value, 'changedAt': changedAt.toIso8601String()};
}

class VaultItem {
  VaultItem({
    required this.id,
    required this.type,
    required this.title,
    Map<String, String>? fields,
    this.notes = '',
    this.favorite = false,
    List<Attachment>? attachments,
    List<HistoryEntry>? passwordHistory,
    required this.createdAt,
    required this.updatedAt,
    this.lastUsedAt,
    this.trashedAt,
  })  : fields = fields ?? {},
        attachments = attachments ?? [],
        passwordHistory = passwordHistory ?? [];

  factory VaultItem.create(ItemType type) {
    final now = DateTime.now();
    return VaultItem(id: newId(), type: type, title: '', createdAt: now, updatedAt: now);
  }

  factory VaultItem.fromJson(Map<String, dynamic> json) => VaultItem(
        id: json['id'] as String,
        type: ItemType.values.byName(json['type'] as String),
        title: json['title'] as String,
        fields: Map<String, String>.from(json['fields'] as Map? ?? const {}),
        notes: json['notes'] as String? ?? '',
        favorite: json['favorite'] as bool? ?? false,
        attachments: [
          for (final a in json['attachments'] as List? ?? const [])
            Attachment.fromJson(Map<String, dynamic>.from(a as Map))
        ],
        passwordHistory: [
          for (final h in json['passwordHistory'] as List? ?? const [])
            HistoryEntry.fromJson(Map<String, dynamic>.from(h as Map))
        ],
        createdAt: DateTime.parse(json['createdAt'] as String),
        updatedAt: DateTime.parse(json['updatedAt'] as String),
        lastUsedAt: _date(json['lastUsedAt']),
        trashedAt: _date(json['trashedAt']),
      );

  final String id;
  final ItemType type;
  String title;
  final Map<String, String> fields;
  String notes;
  bool favorite;
  final List<Attachment> attachments;
  final List<HistoryEntry> passwordHistory;
  final DateTime createdAt;
  DateTime updatedAt;
  DateTime? lastUsedAt;
  DateTime? trashedAt;

  bool get inTrash => trashedAt != null;
  String field(String key) => fields[key] ?? '';

  String get subtitle => switch (type) {
        ItemType.login => field('username').isNotEmpty ? field('username') : hostOf(field('url')),
        ItemType.card => field('number').length >= 4
            ? '•••• ${field('number').replaceAll(' ', '').substring(max(0, field('number').replaceAll(' ', '').length - 4))}'
            : 'Payment card',
        ItemType.identity => field('fullName').isNotEmpty ? field('fullName') : 'Identity',
        ItemType.note => notes.split('\n').first.trim().isEmpty
            ? 'Secure note'
            : notes.split('\n').first.trim(),
        ItemType.document => attachments.isEmpty
            ? 'No files'
            : attachments.length == 1
                ? attachments.first.name
                : '${attachments.length} files',
      };

  VaultItem copy() => VaultItem.fromJson(toJson());

  Map<String, dynamic> toJson() => {
        'id': id,
        'type': type.name,
        'title': title,
        'fields': fields,
        'notes': notes,
        'favorite': favorite,
        'attachments': [for (final a in attachments) a.toJson()],
        'passwordHistory': [for (final h in passwordHistory) h.toJson()],
        'createdAt': createdAt.toIso8601String(),
        'updatedAt': updatedAt.toIso8601String(),
        if (lastUsedAt != null) 'lastUsedAt': lastUsedAt!.toIso8601String(),
        if (trashedAt != null) 'trashedAt': trashedAt!.toIso8601String(),
      };

  static DateTime? _date(Object? v) => v is String ? DateTime.tryParse(v) : null;
}

class VaultSettings {
  VaultSettings({
    this.autoLockMinutes = 5,
    this.clipboardSeconds = 30,
    this.lockOnBackground = true,
    this.lastBackupAt,
  });

  factory VaultSettings.fromJson(Map<String, dynamic>? json) {
    if (json == null) return VaultSettings();
    return VaultSettings(
      autoLockMinutes: json['autoLockMinutes'] as int? ?? 5,
      clipboardSeconds: json['clipboardSeconds'] as int? ?? 30,
      lockOnBackground: json['lockOnBackground'] as bool? ?? true,
      lastBackupAt: json['lastBackupAt'] is String
          ? DateTime.tryParse(json['lastBackupAt'] as String)
          : null,
    );
  }

  /// 0 means never.
  int autoLockMinutes;

  /// 0 means never clear.
  int clipboardSeconds;
  bool lockOnBackground;
  DateTime? lastBackupAt;

  Map<String, dynamic> toJson() => {
        'autoLockMinutes': autoLockMinutes,
        'clipboardSeconds': clipboardSeconds,
        'lockOnBackground': lockOnBackground,
        if (lastBackupAt != null) 'lastBackupAt': lastBackupAt!.toIso8601String(),
      };
}

final Random _idRng = Random.secure();

String newId() {
  const hex = '0123456789abcdef';
  return List.generate(24, (_) => hex[_idRng.nextInt(16)]).join();
}

String hostOf(String url) {
  final trimmed = url.trim();
  if (trimmed.isEmpty) return '';
  final uri = Uri.tryParse(trimmed.contains('://') ? trimmed : 'https://$trimmed');
  final host = uri?.host ?? '';
  return host.startsWith('www.') ? host.substring(4) : (host.isEmpty ? trimmed : host);
}
