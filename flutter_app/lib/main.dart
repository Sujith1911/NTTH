import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import 'core/app_settings.dart';
import 'core/auth_service.dart';
import 'core/websocket_service.dart';
import 'screens/login_screen.dart';
import 'screens/dashboard_screen.dart';
import 'screens/devices_screen.dart';
import 'screens/threat_map_screen.dart';
import 'screens/firewall_screen.dart';
import 'screens/honeypot_screen.dart';
import 'screens/system_health_screen.dart';
import 'screens/settings_screen.dart';
import 'screens/network_topology_screen.dart';

const _storage = FlutterSecureStorage();

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const NTTHApp());
}

class NTTHApp extends StatelessWidget {
  const NTTHApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => AppSettings()),
        ChangeNotifierProxyProvider<AppSettings, AuthService>(
          create: (_) => AuthService(_storage),
          update: (_, settings, auth) {
            auth?.api.updateBaseUrl(settings.baseUrl);
            return auth ?? AuthService(_storage);
          },
        ),
        ChangeNotifierProxyProvider<AppSettings, WebSocketService>(
          create: (_) => WebSocketService(),
          update: (_, settings, ws) {
            ws?.setWsBase(settings.wsUrl);
            return ws ?? WebSocketService();
          },
        ),
      ],
      child: Builder(
        builder: (context) {
          final auth = context.watch<AuthService>();
          return MaterialApp.router(
            title: 'NO TIME TO HACK',
            debugShowCheckedModeBanner: false,
            theme: _buildTheme(),
            routerConfig: _buildRouter(auth),
          );
        },
      ),
    );
  }

  ThemeData _buildTheme() {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      colorScheme: ColorScheme.fromSeed(
        seedColor: const Color(0xFF00FF88),
        brightness: Brightness.dark,
        surface: const Color(0xFF0A0E1A),
      ),
      scaffoldBackgroundColor: const Color(0xFF080C18),
      textTheme: GoogleFonts.interTextTheme(ThemeData.dark().textTheme),
      cardTheme: CardThemeData(
        color: const Color(0xFF111827),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        elevation: 0,
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: const Color(0xFF080C18),
        foregroundColor: Colors.white,
        elevation: 0,
        titleTextStyle: GoogleFonts.inter(
          color: Colors.white,
          fontSize: 18,
          fontWeight: FontWeight.w600,
        ),
      ),
      navigationRailTheme: const NavigationRailThemeData(
        backgroundColor: Color(0xFF0D1117),
        indicatorColor: Color(0xFF00FF8820),
        selectedIconTheme: IconThemeData(color: Color(0xFF00FF88)),
        unselectedIconTheme: IconThemeData(color: Colors.white38),
      ),
    );
  }

  GoRouter _buildRouter(AuthService auth) {
    return GoRouter(
      initialLocation: '/login',
      redirect: (context, state) {
        final loggedIn = auth.isAuthenticated;
        final onLogin = state.matchedLocation == '/login';
        if (!loggedIn && !onLogin) return '/login';
        if (loggedIn && onLogin) return '/dashboard';
        return null;
      },
      routes: [
        GoRoute(path: '/login',      builder: (_, __) => const LoginScreen()),
        GoRoute(path: '/dashboard',  builder: (_, __) => const DashboardScreen()),
        GoRoute(path: '/devices',    builder: (_, __) => const DevicesScreen()),
        GoRoute(path: '/threats',    builder: (_, __) => const ThreatMapScreen()),
        GoRoute(path: '/topology',   builder: (_, __) => const NetworkTopologyScreen()),
        GoRoute(path: '/firewall',   builder: (_, __) => const FirewallScreen()),
        GoRoute(path: '/honeypot',   builder: (_, __) => const HoneypotScreen()),
        GoRoute(path: '/system',     builder: (_, __) => const SystemHealthScreen()),
        GoRoute(path: '/settings',   builder: (_, __) => const SettingsScreen()),
      ],
    );
  }
}
