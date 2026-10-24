import 'package:flutter/material.dart';

import '../core/models.dart';
import '../state/vault_controller.dart';
import 'theme.dart';
import 'widgets.dart';

class ItemListPanel extends StatelessWidget {
  const ItemListPanel({
    super.key,
    required this.vault,
    required this.searchFocus,
    required this.searchController,
    required this.onOpen,
    required this.onCreate,
    this.highlightSelection = true,
  });

  final VaultController vault;
  final FocusNode searchFocus;
  final TextEditingController searchController;
  final ValueChanged<VaultItem> onOpen;
  final ValueChanged<ItemType> onCreate;
  final bool highlightSelection;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    final items = vault.visibleItems;
    final report = vault.report;
    final weak = report.weakIds;
    final reused = report.reusedIds;
    final showSections = vault.filter == ItemFilter.all && vault.query.isEmpty && vault.sort != SortOrder.name;
    final favourites = showSections ? items.where((i) => i.favorite).toList() : <VaultItem>[];
    final rest = showSections ? items.where((i) => !i.favorite).toList() : items;

    Widget tile(VaultItem item) => _ItemTile(
          item: item,
          selected: highlightSelection && item.id == vault.selectedId,
          badge: weak.contains(item.id)
              ? const Pill('Weak', tone: PillTone.danger)
              : reused.contains(item.id)
                  ? const Pill('Reused', tone: PillTone.warning)
                  : null,
          onTap: () => onOpen(item),
        );

    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(18, 18, 14, 12),
        child: Row(children: [
          Expanded(child: Text(_title, style: Theme.of(context).textTheme.titleLarge)),
          _SortMenu(vault: vault),
          const SizedBox(width: 4),
          NewItemButton(onCreate: onCreate),
        ]),
      ),
      Padding(
        padding: const EdgeInsets.symmetric(horizontal: 18),
        child: TextField(
          focusNode: searchFocus,
          onChanged: vault.setQuery,
          controller: searchController,
          decoration: InputDecoration(
            hintText: 'Search ${vault.countFor(ItemFilter.all)} items',
            prefixIcon: const Icon(Icons.search_rounded, size: 20),
            suffixIcon: vault.query.isNotEmpty
                ? IconButton(
                    tooltip: 'Clear search',
                    icon: const Icon(Icons.close_rounded, size: 18),
                    onPressed: () {
                      searchController.clear();
                      vault.setQuery('');
                    },
                  )
                : const Padding(padding: EdgeInsets.all(12), child: KeyCap('Ctrl K')),
            suffixIconConstraints: const BoxConstraints(minHeight: 40),
            contentPadding: const EdgeInsets.symmetric(vertical: 12),
          ),
        ),
      ),
      const SizedBox(height: 12),
      SizedBox(
        height: 34,
        child: ListView(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 18),
          children: [
            for (final f in ItemFilter.values)
              if (f == ItemFilter.all || vault.countFor(f) > 0 || vault.filter == f)
                Padding(
                  padding: const EdgeInsets.only(right: 6),
                  child: _FilterChip(
                    label: _filterLabel(f),
                    count: f == ItemFilter.all ? null : vault.countFor(f),
                    selected: vault.filter == f,
                    onTap: () => vault.setFilter(f),
                  ),
                ),
          ],
        ),
      ),
      const SizedBox(height: 6),
      Expanded(
        child: items.isEmpty
            ? _emptyList(context)
            : ListView(
                padding: const EdgeInsets.fromLTRB(8, 0, 8, 12),
                children: [
                  if (favourites.isNotEmpty) ...[
                    const SectionLabel('Favourites', padding: EdgeInsets.fromLTRB(10, 12, 10, 6)),
                    for (final i in favourites) tile(i),
                    if (rest.isNotEmpty) const SectionLabel('All items', padding: EdgeInsets.fromLTRB(10, 14, 10, 6)),
                  ] else
                    const SizedBox(height: 6),
                  for (final i in rest) tile(i),
                  if (vault.filter == ItemFilter.trash && items.isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.all(10),
                      child: TextButton.icon(
                        style: TextButton.styleFrom(foregroundColor: c.danger),
                        icon: const Icon(Icons.delete_forever_outlined, size: 18),
                        label: const Text('Empty trash'),
                        onPressed: () async {
                          final ok = await confirm(context,
                              title: 'Empty trash?',
                              message: '${items.length} items and their files will be deleted permanently.',
                              confirmLabel: 'Delete permanently',
                              destructive: true);
                          if (ok) await vault.emptyTrash();
                        },
                      ),
                    ),
                ],
              ),
      ),
    ]);
  }

  String get _title => vault.filter == ItemFilter.all ? 'My vault' : _filterLabel(vault.filter);

  Widget _emptyList(BuildContext context) {
    if (vault.query.isNotEmpty) {
      return EmptyState(
        icon: Icons.search_off_rounded,
        title: 'No matches',
        message: 'Nothing matches “${vault.query}”. Try a website, username or file name.',
      );
    }
    if (vault.filter == ItemFilter.trash) {
      return const EmptyState(icon: Icons.delete_outline_rounded, title: 'Trash is empty', message: 'Deleted items stay here until you empty the trash.');
    }
    return EmptyState(
      icon: Icons.add_moderator_outlined,
      title: 'Add your first item',
      message: 'Save a login, a secure note, or scan in an important document.',
      action: FilledButton.icon(
        icon: const Icon(Icons.add_rounded, size: 18),
        label: const Text('New login'),
        onPressed: () => onCreate(ItemType.login),
      ),
    );
  }
}

String _filterLabel(ItemFilter f) => switch (f) {
      ItemFilter.all => 'All',
      ItemFilter.favorites => 'Favourites',
      ItemFilter.login => 'Logins',
      ItemFilter.note => 'Notes',
      ItemFilter.card => 'Cards',
      ItemFilter.identity => 'Identities',
      ItemFilter.document => 'Documents',
      ItemFilter.trash => 'Trash',
    };

class _FilterChip extends StatelessWidget {
  const _FilterChip({required this.label, required this.selected, required this.onTap, this.count});
  final String label;
  final bool selected;
  final VoidCallback onTap;
  final int? count;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Material(
      color: selected ? c.text : c.subtle,
      borderRadius: BorderRadius.circular(99),
      child: InkWell(
        borderRadius: BorderRadius.circular(99),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 13, vertical: 7),
          child: Text.rich(
            TextSpan(children: [
              TextSpan(text: label),
              if (count != null)
                TextSpan(
                    text: '  $count',
                    style: TextStyle(color: selected ? c.panel.withValues(alpha: 0.6) : c.faint)),
            ]),
            style: TextStyle(
                fontSize: 12.5, fontWeight: FontWeight.w700, color: selected ? c.panel : c.muted),
          ),
        ),
      ),
    );
  }
}

class _ItemTile extends StatelessWidget {
  const _ItemTile({required this.item, required this.selected, required this.onTap, this.badge});
  final VaultItem item;
  final bool selected;
  final VoidCallback onTap;
  final Widget? badge;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Padding(
      padding: const EdgeInsets.only(bottom: 2),
      child: Material(
        color: selected ? c.accentSoft : Colors.transparent,
        borderRadius: BorderRadius.circular(12),
        child: InkWell(
          borderRadius: BorderRadius.circular(12),
          hoverColor: c.subtle,
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.all(10),
            child: Row(children: [
              ItemAvatar(item: item),
              const SizedBox(width: 12),
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(item.title,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14)),
                  const SizedBox(height: 2),
                  Text(item.subtitle,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(fontSize: 12.5, color: c.faint)),
                ]),
              ),
              const SizedBox(width: 8),
              badge ??
                  Text(relativeTime(item.lastUsedAt ?? item.updatedAt),
                      style: TextStyle(fontSize: 11.5, color: c.faint)),
            ]),
          ),
        ),
      ),
    );
  }
}

class _SortMenu extends StatelessWidget {
  const _SortMenu({required this.vault});
  final VaultController vault;

  @override
  Widget build(BuildContext context) => PopupMenuButton<SortOrder>(
        tooltip: 'Sort',
        icon: const Icon(Icons.swap_vert_rounded, size: 20),
        initialValue: vault.sort,
        onSelected: vault.setSort,
        itemBuilder: (_) => const [
          PopupMenuItem(value: SortOrder.recent, child: Text('Recently used')),
          PopupMenuItem(value: SortOrder.updated, child: Text('Recently edited')),
          PopupMenuItem(value: SortOrder.name, child: Text('Name')),
        ],
      );
}

class NewItemButton extends StatelessWidget {
  const NewItemButton({super.key, required this.onCreate});
  final ValueChanged<ItemType> onCreate;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return PopupMenuButton<ItemType>(
      tooltip: 'New item (Ctrl N)',
      onSelected: onCreate,
      offset: const Offset(0, 42),
      itemBuilder: (_) => [
        for (final t in ItemType.values)
          PopupMenuItem(
            value: t,
            child: Row(children: [
              Icon(_typeIcon(t), size: 19, color: c.muted),
              const SizedBox(width: 12),
              Text(t.label),
            ]),
          ),
      ],
      child: Container(
        width: 36,
        height: 36,
        decoration: BoxDecoration(color: c.accent, borderRadius: BorderRadius.circular(10)),
        child: Icon(Icons.add_rounded, color: c.onAccent, size: 21),
      ),
    );
  }
}

IconData _typeIcon(ItemType t) => switch (t) {
      ItemType.login => Icons.key_outlined,
      ItemType.note => Icons.sticky_note_2_outlined,
      ItemType.card => Icons.credit_card,
      ItemType.identity => Icons.badge_outlined,
      ItemType.document => Icons.description_outlined,
    };
