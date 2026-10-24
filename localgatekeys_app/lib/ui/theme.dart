import 'dart:io';

import 'package:flutter/material.dart';

/// Colours for the "Porcelain" look (split view, floating panels).
@immutable
class AppColors extends ThemeExtension<AppColors> {
  const AppColors({
    required this.canvas,
    required this.panel,
    required this.subtle,
    required this.subtleStrong,
    required this.border,
    required this.text,
    required this.muted,
    required this.faint,
    required this.accent,
    required this.accentSoft,
    required this.onAccent,
    required this.success,
    required this.successSoft,
    required this.warning,
    required this.warningSoft,
    required this.danger,
    required this.dangerSoft,
  });

  static const light = AppColors(
    canvas: Color(0xFFEEF1F6),
    panel: Color(0xFFFFFFFF),
    subtle: Color(0xFFF3F5F9),
    subtleStrong: Color(0xFFE6EAF1),
    border: Color(0xFFE3E7EE),
    text: Color(0xFF0E1726),
    muted: Color(0xFF5B6679),
    faint: Color(0xFF6B7588),
    accent: Color(0xFF005FCC),
    accentSoft: Color(0xFFE6F0FF),
    onAccent: Color(0xFFFFFFFF),
    success: Color(0xFF0B7A5B),
    successSoft: Color(0xFFE3F6EE),
    warning: Color(0xFF8A5300),
    warningSoft: Color(0xFFFFF1D6),
    danger: Color(0xFFB42318),
    dangerSoft: Color(0xFFFDECEA),
  );

  static const dark = AppColors(
    canvas: Color(0xFF0A0D12),
    panel: Color(0xFF131820),
    subtle: Color(0xFF1B212B),
    subtleStrong: Color(0xFF252C38),
    border: Color(0xFF262D39),
    text: Color(0xFFE8ECF2),
    muted: Color(0xFFA3ADBD),
    faint: Color(0xFF8D97A8),
    accent: Color(0xFF5EA1FF),
    accentSoft: Color(0xFF16263D),
    onAccent: Color(0xFF06121F),
    success: Color(0xFF4ACB9A),
    successSoft: Color(0xFF0E2A21),
    warning: Color(0xFFF2B84B),
    warningSoft: Color(0xFF2E230E),
    danger: Color(0xFFF47A70),
    dangerSoft: Color(0xFF331614),
  );

  final Color canvas, panel, subtle, subtleStrong, border, text, muted, faint;
  final Color accent, accentSoft, onAccent;
  final Color success, successSoft, warning, warningSoft, danger, dangerSoft;

  @override
  AppColors copyWith() => this;

  @override
  AppColors lerp(AppColors? other, double t) => t < 0.5 ? this : (other ?? this);
}

extension AppColorsContext on BuildContext {
  AppColors get colors => Theme.of(this).extension<AppColors>()!;
}

String? get _platformFont => Platform.isWindows ? 'Segoe UI Variable Text' : null;
List<String>? get _fallbackFonts => Platform.isWindows ? const ['Segoe UI', 'Segoe UI Emoji'] : null;

ThemeData buildTheme(Brightness brightness) {
  final c = brightness == Brightness.light ? AppColors.light : AppColors.dark;
  final scheme = ColorScheme.fromSeed(
    seedColor: c.accent,
    brightness: brightness,
  ).copyWith(
    primary: c.accent,
    onPrimary: c.onAccent,
    surface: c.panel,
    onSurface: c.text,
    error: c.danger,
    outline: c.border,
    outlineVariant: c.border,
  );
  final base = ThemeData(
    useMaterial3: true,
    brightness: brightness,
    colorScheme: scheme,
    fontFamily: _platformFont,
    fontFamilyFallback: _fallbackFonts,
    scaffoldBackgroundColor: c.canvas,
    extensions: [c],
    splashFactory: InkSparkle.splashFactory,
    visualDensity: VisualDensity.standard,
  );
  final text = base.textTheme.apply(bodyColor: c.text, displayColor: c.text);
  return base.copyWith(
    textTheme: text.copyWith(
      headlineMedium: text.headlineMedium?.copyWith(fontWeight: FontWeight.w700, letterSpacing: -0.6, fontSize: 30),
      headlineSmall: text.headlineSmall?.copyWith(fontWeight: FontWeight.w700, letterSpacing: -0.4, fontSize: 24),
      titleLarge: text.titleLarge?.copyWith(fontWeight: FontWeight.w700, letterSpacing: -0.2, fontSize: 20),
      titleMedium: text.titleMedium?.copyWith(fontWeight: FontWeight.w600, fontSize: 15),
      bodyMedium: text.bodyMedium?.copyWith(fontSize: 14, height: 1.4),
      bodySmall: text.bodySmall?.copyWith(fontSize: 12.5, color: c.faint),
      labelSmall: text.labelSmall?.copyWith(
          fontSize: 11, fontWeight: FontWeight.w700, letterSpacing: 0.8, color: c.faint),
    ),
    dividerTheme: DividerThemeData(color: c.border, thickness: 1, space: 1),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: c.subtle,
      hintStyle: TextStyle(color: c.faint),
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(11), borderSide: BorderSide.none),
      enabledBorder:
          OutlineInputBorder(borderRadius: BorderRadius.circular(11), borderSide: BorderSide.none),
      focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(11), borderSide: BorderSide(color: c.accent, width: 1.6)),
      errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(11), borderSide: BorderSide(color: c.danger, width: 1.2)),
      floatingLabelBehavior: FloatingLabelBehavior.always,
      labelStyle: TextStyle(color: c.muted, fontWeight: FontWeight.w600),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: c.accent,
        foregroundColor: c.onAccent,
        minimumSize: const Size(44, 44),
        padding: const EdgeInsets.symmetric(horizontal: 18),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(11)),
        textStyle: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: c.text,
        backgroundColor: c.subtle,
        side: BorderSide.none,
        minimumSize: const Size(44, 44),
        padding: const EdgeInsets.symmetric(horizontal: 16),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(11)),
        textStyle: const TextStyle(fontWeight: FontWeight.w700, fontSize: 14),
      ),
    ),
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(
        foregroundColor: c.accent,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(9)),
        textStyle: const TextStyle(fontWeight: FontWeight.w700),
      ),
    ),
    iconButtonTheme: IconButtonThemeData(
      style: IconButton.styleFrom(
        foregroundColor: c.muted,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
      ),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: c.panel,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
    ),
    popupMenuTheme: PopupMenuThemeData(
      color: c.panel,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12), side: BorderSide(color: c.border)),
    ),
    snackBarTheme: SnackBarThemeData(
      behavior: SnackBarBehavior.floating,
      backgroundColor: c.text,
      contentTextStyle: TextStyle(color: c.panel, fontWeight: FontWeight.w600),
      actionTextColor: brightness == Brightness.light ? const Color(0xFF8CC2FF) : c.accent,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      width: Platform.isWindows ? 420 : null,
    ),
    switchTheme: SwitchThemeData(
      thumbColor: WidgetStateProperty.resolveWith(
          (s) => s.contains(WidgetState.selected) ? c.onAccent : c.faint),
      trackColor: WidgetStateProperty.resolveWith(
          (s) => s.contains(WidgetState.selected) ? c.accent : c.subtleStrong),
      trackOutlineColor: const WidgetStatePropertyAll(Colors.transparent),
    ),
    sliderTheme: SliderThemeData(activeTrackColor: c.accent, thumbColor: c.accent, inactiveTrackColor: c.subtleStrong),
    tooltipTheme: TooltipThemeData(
      decoration: BoxDecoration(color: c.text, borderRadius: BorderRadius.circular(7)),
      textStyle: TextStyle(color: c.panel, fontSize: 12, fontWeight: FontWeight.w600),
      waitDuration: const Duration(milliseconds: 400),
    ),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: c.panel,
      indicatorColor: c.accentSoft,
      surfaceTintColor: Colors.transparent,
      labelTextStyle: WidgetStatePropertyAll(
          TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: c.muted)),
    ),
    pageTransitionsTheme: const PageTransitionsTheme(builders: {
      TargetPlatform.windows: FadeForwardsPageTransitionsBuilder(),
      TargetPlatform.iOS: CupertinoPageTransitionsBuilder(),
    }),
  );
}

/// A floating white panel, as used for the list and detail areas.
class Panel extends StatelessWidget {
  const Panel({super.key, required this.child, this.padding = EdgeInsets.zero});
  final Widget child;
  final EdgeInsetsGeometry padding;

  @override
  Widget build(BuildContext context) {
    final c = context.colors;
    return Container(
      padding: padding,
      clipBehavior: Clip.antiAlias,
      decoration: BoxDecoration(
        color: c.panel,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: c.border.withValues(alpha: 0.7)),
        boxShadow: [
          BoxShadow(color: Colors.black.withValues(alpha: 0.04), blurRadius: 2, offset: const Offset(0, 1)),
          BoxShadow(color: Colors.black.withValues(alpha: 0.03), blurRadius: 18, offset: const Offset(0, 6)),
        ],
      ),
      child: child,
    );
  }
}
