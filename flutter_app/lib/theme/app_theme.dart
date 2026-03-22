import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class AppTheme {
  static const primaryColor = Color(0xFF0F6CBD);
  static const secondaryColor = Color(0xFFF59E0B);
  static const successColor = Color(0xFF0F9D7A);
  static const dangerColor = Color(0xFFD14343);

  static const darkBgColor = Color(0xFF07111F);
  static const darkSurfaceColor = Color(0xFF0E1A2B);
  static const darkCardColor = Color(0xFF132238);

  static const lightBgColor = Color(0xFFF3F7FB);
  static const lightSurfaceColor = Color(0xFFFDFEFF);
  static const lightCardColor = Color(0xFFFFFFFF);

  static ThemeData get light {
    final baseTheme = ThemeData.light();
    final textTheme = GoogleFonts.manropeTextTheme(baseTheme.textTheme);
    final colors = ColorScheme.fromSeed(
      seedColor: primaryColor,
      secondary: secondaryColor,
      brightness: Brightness.light,
      surface: lightSurfaceColor,
    );

    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.light,
      colorScheme: colors,
      scaffoldBackgroundColor: lightBgColor,
      textTheme: textTheme,
      fontFamily: GoogleFonts.manrope().fontFamily,
      dividerColor: const Color(0xFFD9E3F0),
      cardTheme: CardThemeData(
        color: lightCardColor,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        elevation: 0.5,
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: Colors.transparent,
        foregroundColor: const Color(0xFF132238),
        elevation: 0,
        titleTextStyle: GoogleFonts.spaceGrotesk(
          color: const Color(0xFF132238),
          fontSize: 20,
          fontWeight: FontWeight.w700,
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: Colors.white.withOpacity(0.92),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: BorderSide(color: colors.outlineVariant.withOpacity(0.45)),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: BorderSide(color: colors.outlineVariant.withOpacity(0.45)),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: const BorderSide(color: primaryColor, width: 1.5),
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: primaryColor,
          foregroundColor: Colors.white,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
          padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 18),
          textStyle: GoogleFonts.spaceGrotesk(
            fontWeight: FontWeight.w700,
            letterSpacing: 0.2,
          ),
        ),
      ),
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: Colors.white.withOpacity(0.78),
        indicatorColor: primaryColor.withOpacity(0.14),
        selectedIconTheme: const IconThemeData(color: primaryColor),
        unselectedIconTheme: const IconThemeData(color: Color(0xFF708198)),
      ),
    );
  }

  static ThemeData get dark {
    final baseTheme = ThemeData.dark();
    final textTheme = GoogleFonts.manropeTextTheme(baseTheme.textTheme);
    final colors = ColorScheme.fromSeed(
      seedColor: primaryColor,
      secondary: secondaryColor,
      brightness: Brightness.dark,
      surface: darkSurfaceColor,
    );

    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      colorScheme: colors,
      scaffoldBackgroundColor: darkBgColor,
      textTheme: textTheme,
      fontFamily: GoogleFonts.manrope().fontFamily,
      dividerColor: const Color(0xFF223653),
      cardTheme: CardThemeData(
        color: darkCardColor,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        elevation: 0,
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: Colors.transparent,
        foregroundColor: Colors.white,
        elevation: 0,
        titleTextStyle: GoogleFonts.spaceGrotesk(
          color: Colors.white,
          fontSize: 20,
          fontWeight: FontWeight.w700,
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: const Color(0xFF122239).withOpacity(0.94),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: BorderSide(color: Colors.white.withOpacity(0.08)),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: BorderSide(color: Colors.white.withOpacity(0.08)),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: const BorderSide(color: Color(0xFF67B7FF), width: 1.5),
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: const Color(0xFF67B7FF),
          foregroundColor: const Color(0xFF07111F),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
          padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 18),
          textStyle: GoogleFonts.spaceGrotesk(
            fontWeight: FontWeight.w700,
            letterSpacing: 0.2,
          ),
        ),
      ),
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: darkSurfaceColor.withOpacity(0.78),
        indicatorColor: const Color(0xFF67B7FF).withOpacity(0.18),
        selectedIconTheme: const IconThemeData(color: primaryColor),
        unselectedIconTheme: const IconThemeData(color: Color(0xFF92A5BF)),
      ),
    );
  }
}
