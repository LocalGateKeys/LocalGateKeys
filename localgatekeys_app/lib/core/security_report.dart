import 'models.dart';
import 'password_tools.dart';

class ExpiringItem {
  ExpiringItem(this.item, this.date);
  final VaultItem item;
  final DateTime date;
  int get daysLeft => date.difference(DateTime.now()).inDays;
}

class SecurityReport {
  SecurityReport._({
    required this.weak,
    required this.reusedGroups,
    required this.old,
    required this.expiring,
    required this.backupOverdue,
    required this.hasRecoveryCode,
    required this.score,
    required this.loginCount,
  });

  factory SecurityReport.build(
    List<VaultItem> items,
    VaultSettings settings, {
    required bool hasRecoveryCode,
    DateTime? now,
  }) {
    final today = now ?? DateTime.now();
    final active = items.where((i) => !i.inTrash).toList();
    final logins = active.where((i) => i.type == ItemType.login && i.field('password').isNotEmpty).toList();

    final weak = logins.where((i) => strengthOf(i.field('password')).isWeak).toList();

    final byPassword = <String, List<VaultItem>>{};
    for (final i in logins) {
      byPassword.putIfAbsent(i.field('password'), () => []).add(i);
    }
    final reusedGroups = byPassword.values.where((g) => g.length > 1).toList();

    final old = logins.where((i) {
      final changed = i.passwordHistory.isEmpty ? i.createdAt : i.passwordHistory.last.changedAt;
      return today.difference(changed).inDays > 365;
    }).toList();

    final expiring = <ExpiringItem>[];
    for (final i in active) {
      final date = DateTime.tryParse(i.field('expires'));
      if (date != null && date.difference(today).inDays <= 60) {
        expiring.add(ExpiringItem(i, date));
      }
    }
    expiring.sort((a, b) => a.date.compareTo(b.date));

    final backupOverdue =
        settings.lastBackupAt == null || today.difference(settings.lastBackupAt!).inDays > 30;

    final flagged = {...weak.map((i) => i.id), ...reusedGroups.expand((g) => g).map((i) => i.id)};
    var score = logins.isEmpty ? 100.0 : 100.0 * (logins.length - flagged.length) / logins.length;
    score -= old.length * 2;
    if (backupOverdue) score -= 10;
    if (!hasRecoveryCode) score -= 15;

    return SecurityReport._(
      weak: weak,
      reusedGroups: reusedGroups,
      old: old,
      expiring: expiring,
      backupOverdue: backupOverdue,
      hasRecoveryCode: hasRecoveryCode,
      score: score.clamp(0, 100).round(),
      loginCount: logins.length,
    );
  }

  final List<VaultItem> weak;
  final List<List<VaultItem>> reusedGroups;
  final List<VaultItem> old;
  final List<ExpiringItem> expiring;
  final bool backupOverdue;
  final bool hasRecoveryCode;
  final int score;
  final int loginCount;

  int get reusedCount => reusedGroups.fold(0, (n, g) => n + g.length);
  int get issueCount =>
      weak.length + reusedCount + old.length + expiring.length + (backupOverdue ? 1 : 0) + (hasRecoveryCode ? 0 : 1);

  Set<String> get weakIds => {for (final i in weak) i.id};
  Set<String> get reusedIds => {for (final g in reusedGroups) for (final i in g) i.id};
}
