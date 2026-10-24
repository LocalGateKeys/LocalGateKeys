import 'package:flutter/material.dart';

import '../core/models.dart';
import '../core/security_report.dart';
import '../state/vault_controller.dart';
import 'file_actions.dart';
import 'settings_screen.dart';
import 'theme.dart';
import 'widgets.dart';

class SecurityScreen extends StatelessWidget {
  const SecurityScreen({super.key, required this.vault, required this.onOpenItem});
  final VaultController vault;
  final ValueChanged<VaultItem> onOpenItem;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final r = vault.report;
    return LayoutBuilder(builder: (context, box) {
      final wide = box.maxWidth >= 760;
      final pad = wide ? 40.0 : 18.0;
      final stats = [
        _Stat(label: 'Weak passwords', value: '${r.weak.length}', tone: r.weak.isEmpty ? c.success : c.danger),
        _Stat(label: 'Reused passwords', value: '${r.reusedCount}', tone: r.reusedCount == 0 ? c.success : c.warning),
        _Stat(label: 'Older than a year', value: '${r.old.length}', tone: r.old.isEmpty ? c.success : c.warning),
        _Stat(
          label: 'Last backup',
          value: vault.settings.lastBackupAt == null ? 'Never' : relativeTime(vault.settings.lastBackupAt!),
          tone: r.backupOverdue ? c.warning : c.success,
        ),
      ];
      return ListView(padding: EdgeInsets.fromLTRB(pad, wide ? 32 : 16, pad, 40), children: [
        Text('Security', style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 4),
        Text('Checks run on this device. Nothing is sent anywhere.', style: TextStyle(color: c.muted)),
        const SizedBox(height: 24),
        if (wide)
          IntrinsicHeight(
            child: Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              Expanded(flex: 5, child: _ScoreCard(report: r)),
              for (final s in stats) ...[const SizedBox(width: 14), Expanded(flex: 3, child: s)],
            ]),
          )
        else ...[
          _ScoreCard(report: r),
          const SizedBox(height: 12),
          GridView.count(
            crossAxisCount: 2,
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            mainAxisSpacing: 12,
            crossAxisSpacing: 12,
            childAspectRatio: 1.7,
            children: stats,
          ),
        ],
        const SizedBox(height: 28),
        Text('Needs your attention', style: Theme.of(context).textTheme.titleLarge),
        const SizedBox(height: 12),
        ..._issues(context, r),
      ]);
    });
  }

  List<Widget> _issues(BuildContext context, SecurityReport r) {
    final c = context.colors;
    final rows = <Widget>[];
    if (!r.hasRecoveryCode) {
      rows.add(_IssueRow(
        color: c.danger,
        title: 'No recovery code',
        detail: 'If you forget your master password, your vault cannot be opened.',
        action: 'Create one',
        onTap: () => newRecoveryCodeFlow(context, vault),
      ));
    }
    if (r.backupOverdue) {
      rows.add(_IssueRow(
        color: c.warning,
        title: vault.settings.lastBackupAt == null ? 'You have never made a backup' : 'Your last backup is over a month old',
        detail: 'If this device is lost or damaged, a backup is the only copy of your vault.',
        action: 'Back up now',
        onTap: () => exportBackupFlow(context, vault),
      ));
    }
    for (final i in r.weak) {
      rows.add(_IssueRow(
        color: c.danger,
        title: '${i.title} has a weak password',
        detail: 'Change it on the website, then generate a strong one here.',
        action: 'Open',
        onTap: () => onOpenItem(i),
      ));
    }
    for (final g in r.reusedGroups) {
      rows.add(_IssueRow(
        color: c.warning,
        title: '${g.length} items share one password',
        detail: g.map((i) => i.title).join(', '),
        action: 'Open ${g.first.title}',
        onTap: () => onOpenItem(g.first),
      ));
    }
    for (final e in r.expiring) {
      rows.add(_IssueRow(
        color: c.accent,
        title: e.daysLeft < 0 ? '${e.item.title} has expired' : '${e.item.title} expires in ${e.daysLeft} days',
        detail: 'Expiry date ${formatDate(e.date)}',
        action: 'Open',
        onTap: () => onOpenItem(e.item),
      ));
    }
    for (final i in r.old) {
      rows.add(_IssueRow(
        color: c.faint,
        title: '${i.title}: password not changed in over a year',
        detail: 'Consider rotating it, especially for important accounts.',
        action: 'Open',
        onTap: () => onOpenItem(i),
      ));
    }
    if (rows.isEmpty) {
      return [
        Panel(
          padding: const EdgeInsets.all(24),
          child: Row(children: [
            Icon(Icons.verified_user_outlined, color: c.success, size: 28),
            const SizedBox(width: 16),
            const Expanded(child: Text('Everything looks good. No weak or reused passwords found.', style: TextStyle(fontWeight: FontWeight.w600))),
          ]),
        ),
      ];
    }
    return [Panel(child: Column(children: _divided(rows, c)))];
  }

  List<Widget> _divided(List<Widget> rows, AppColors c) => [
        for (var i = 0; i < rows.length; i++) ...[if (i > 0) Divider(height: 1, color: c.border), rows[i]],
      ];
}

class _ScoreCard extends StatelessWidget {
  const _ScoreCard({required this.report});
  final SecurityReport report;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final color = report.score >= 80 ? c.success : report.score >= 50 ? c.warning : c.danger;
    final verdict = report.score >= 80 ? 'Looking good' : report.score >= 50 ? 'Room to improve' : 'Needs attention';
    return Panel(
      padding: const EdgeInsets.all(22),
      child: Row(children: [
        SizedBox(
          width: 88,
          height: 88,
          child: Stack(alignment: Alignment.center, children: [
            SizedBox.expand(
              child: CircularProgressIndicator(
                value: report.score / 100,
                strokeWidth: 8,
                strokeCap: StrokeCap.round,
                color: color,
                backgroundColor: c.subtleStrong,
              ),
            ),
            Text('${report.score}', style: const TextStyle(fontSize: 28, fontWeight: FontWeight.w800)),
          ]),
        ),
        const SizedBox(width: 20),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('Vault health', style: TextStyle(color: c.faint, fontWeight: FontWeight.w700, fontSize: 12.5)),
            const SizedBox(height: 4),
            Text(verdict, style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 4),
            Text('${report.loginCount} logins checked', style: TextStyle(color: c.muted, fontSize: 13)),
          ]),
        ),
      ]),
    );
  }
}

class _Stat extends StatelessWidget {
  const _Stat({required this.label, required this.value, required this.tone});
  final String label;
  final String value;
  final Color tone;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Panel(
      padding: const EdgeInsets.all(18),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisAlignment: MainAxisAlignment.center, children: [
        Text(label, style: TextStyle(color: c.faint, fontWeight: FontWeight.w700, fontSize: 12.5)),
        const SizedBox(height: 6),
        Text(value, style: TextStyle(fontSize: 28, fontWeight: FontWeight.w800, color: tone, letterSpacing: -0.5)),
      ]),
    );
  }
}

class _IssueRow extends StatelessWidget {
  const _IssueRow({required this.color, required this.title, required this.detail, required this.action, required this.onTap});
  final Color color;
  final String title;
  final String detail;
  final String action;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
      child: Row(children: [
        Container(width: 10, height: 10, decoration: BoxDecoration(color: color, shape: BoxShape.circle)),
        const SizedBox(width: 16),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(title, style: const TextStyle(fontWeight: FontWeight.w700)),
            const SizedBox(height: 2),
            Text(detail, maxLines: 2, overflow: TextOverflow.ellipsis, style: TextStyle(color: c.faint, fontSize: 13)),
          ]),
        ),
        const SizedBox(width: 12),
        OutlinedButton(onPressed: onTap, style: OutlinedButton.styleFrom(minimumSize: const Size(0, 38)), child: Text(action)),
      ]),
    );
  }
}
