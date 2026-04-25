import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:go_router/go_router.dart';
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
import 'screens/wireless_screen.dart';
import 'screens/packet_inspector_screen.dart';
import 'theme/app_theme.dart';
import 'theme/theme_provider.dart';

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
        ChangeNotifierProvider(create: (_) => ThemeProvider()),
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
          final themeProvider = context.watch<ThemeProvider>();
          return _RealtimeSessionCoordinator(
            child: MaterialApp.router(
              title: 'NO TIME TO HACK',
              debugShowCheckedModeBanner: false,
              theme: AppTheme.light,
              darkTheme: AppTheme.dark,
              themeMode: themeProvider.themeMode,
              routerConfig: _buildRouter(auth),
            ),
          );
        },
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
        GoRoute(path: '/wireless',   builder: (_, __) => const WirelessScreen()),
        GoRoute(path: '/packets',    builder: (_, __) => const PacketInspectorScreen()),
        GoRoute(path: '/system',     builder: (_, __) => const SystemHealthScreen()),
        GoRoute(path: '/settings',   builder: (_, __) => const SettingsScreen()),
      ],
    );
  }
}

class _RealtimeSessionCoordinator extends StatefulWidget {
  final Widget child;

  const _RealtimeSessionCoordinator({required this.child});

  @override
  State<_RealtimeSessionCoordinator> createState() =>
      _RealtimeSessionCoordinatorState();
}

class _RealtimeSessionCoordinatorState
    extends State<_RealtimeSessionCoordinator> {
  String? _lastToken;
  bool _disconnectQueued = false;

  @override
  Widget build(BuildContext context) {
    final auth = context.watch<AuthService>();
    final ws = context.watch<WebSocketService>();
    final token = auth.accessToken;

    WidgetsBinding.instance.addPostFrameCallback((_) async {
      if (!mounted) return;
      if (auth.isAuthenticated && token != null && token.isNotEmpty) {
        _disconnectQueued = false;
        if (_lastToken != token || !ws.connected) {
          _lastToken = token;
          await ws.ensureConnected(token);
        }
        return;
      }
      if (!_disconnectQueued) {
        _disconnectQueued = true;
        _lastToken = null;
        ws.disconnect(clearEvents: true);
      }
    });

    return widget.child;
  }
}
