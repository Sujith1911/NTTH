import 'package:flutter/material.dart';
import 'package:dio/dio.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../core/app_settings.dart';
import '../core/auth_service.dart';
import '../core/websocket_service.dart';
import '../theme/theme_provider.dart';
import '../widgets/app_shell_drawer.dart';
import '../widgets/glassy_container.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late TextEditingController _urlCtrl;
  bool _saved = false;
  bool _testingConnection = false;
  Map<String, dynamic>? _healthPreview;
  String? _connectionError;

  @override
  void initState() {
    super.initState();
    final settings = context.read<AppSettings>();
    _urlCtrl = TextEditingController(text: settings.baseUrl);
  }

  @override
  void dispose() {
    _urlCtrl.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final settings = context.read<AppSettings>();
    final ws = context.read<WebSocketService>();
    await settings.setServerUrl(_urlCtrl.text.trim());
    ws.setWsBase(settings.wsUrl);
    ws.disconnect(clearEvents: true);
    setState(() => _saved = true);
    await Future.delayed(const Duration(seconds: 2));
    if (mounted) setState(() => _saved = false);
  }

  Future<void> _testConnection() async {
    final raw = _urlCtrl.text.trim().replaceAll(RegExp(r'/$'), '');
    if (raw.isEmpty) {
      setState(() => _connectionError = 'Enter a backend URL first.');
      return;
    }

    setState(() {
      _testingConnection = true;
      _connectionError = null;
    });

    try {
      final dio = Dio(
        BaseOptions(
          baseUrl: raw,
          connectTimeout: const Duration(seconds: 8),
          receiveTimeout: const Duration(seconds: 12),
        ),
      );
      final resp = await dio.get('/api/v1/system/health');
      setState(() {
        _healthPreview = resp.data as Map<String, dynamic>;
      });
    } catch (error) {
      setState(() {
        _healthPreview = null;
        _connectionError = 'Could not reach $raw';
      });
    } finally {
      if (mounted) {
        setState(() => _testingConnection = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;

    return Scaffold(
      drawer: const AppShellDrawer(),
      appBar: AppBar(title: const Text('Settings')),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Appearance Section
            Text(
              'Appearance',
              style: GoogleFonts.inter(
                  fontSize: 18,
                  fontWeight: FontWeight.w600,
                  color: theme.colorScheme.onSurface),
            ),
            const SizedBox(height: 16),
            GlassyContainer(
              padding: const EdgeInsets.all(16),
              child: Consumer<ThemeProvider>(
                builder: (context, themeProvider, _) {
                  return Row(
                    children: [
                      Icon(isDark ? Icons.dark_mode : Icons.light_mode,
                          color: theme.colorScheme.primary),
                      const SizedBox(width: 16),
                      Text('Dark Mode',
                          style: TextStyle(
                              color: theme.colorScheme.onSurface,
                              fontSize: 16)),
                      const Spacer(),
                      Switch(
                        value: themeProvider.isDarkMode,
                        activeColor: theme.colorScheme.primary,
                        onChanged: (val) {
                          themeProvider.toggleTheme();
                        },
                      ),
                    ],
                  );
                },
              ),
            ),
            const SizedBox(height: 32),

            // Backend Server
            Text(
              'Backend Server',
              style: GoogleFonts.inter(
                  fontSize: 18,
                  fontWeight: FontWeight.w600,
                  color: theme.colorScheme.onSurface),
            ),
            const SizedBox(height: 8),
            Text(
              'Enter the IP address of your Linux server running NO TIME TO HACK.',
              style: TextStyle(
                  color: theme.colorScheme.onSurface.withOpacity(0.6),
                  fontSize: 13),
            ),
            const SizedBox(height: 16),
            TextFormField(
              controller: _urlCtrl,
              style: TextStyle(color: theme.colorScheme.onSurface),
              decoration: InputDecoration(
                labelText: 'Server URL',
                labelStyle: TextStyle(
                    color: theme.colorScheme.onSurface.withOpacity(0.5)),
                hintText: 'http://192.168.1.100:8000',
                hintStyle: TextStyle(
                    color: theme.colorScheme.onSurface.withOpacity(0.3)),
                filled: true,
                fillColor: isDark ? const Color(0xFF111827) : Colors.white,
                prefixIcon: Icon(Icons.dns_outlined,
                    color: theme.colorScheme.primary, size: 20),
                border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: BorderSide(color: theme.dividerColor)),
                focusedBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: BorderSide(
                        color: theme.colorScheme.primary, width: 1.5)),
                enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: BorderSide(color: theme.dividerColor)),
              ),
            ),
            const SizedBox(height: 20),
            Row(
              children: [
                Expanded(
                  child: SizedBox(
                    height: 50,
                    child: ElevatedButton.icon(
                      icon: _testingConnection
                          ? const SizedBox(
                              width: 16,
                              height: 16,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Icon(Icons.wifi_tethering_outlined, size: 18),
                      label: Text(_testingConnection
                          ? 'Testing...'
                          : 'Test Connection'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: theme.colorScheme.secondary,
                        foregroundColor: const Color(0xFF080C18),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(12)),
                        textStyle:
                            GoogleFonts.inter(fontWeight: FontWeight.w700),
                      ),
                      onPressed: _testingConnection ? null : _testConnection,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: SizedBox(
                    height: 50,
                    child: ElevatedButton.icon(
                      icon: Icon(_saved ? Icons.check : Icons.save_outlined,
                          size: 18),
                      label: Text(_saved ? 'Saved!' : 'Save & Reconnect'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor:
                            _saved ? Colors.green : theme.colorScheme.primary,
                        foregroundColor: const Color(0xFF080C18),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(12)),
                        textStyle:
                            GoogleFonts.inter(fontWeight: FontWeight.w700),
                      ),
                      onPressed: _save,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 32),

            GlassyContainer(
              padding: const EdgeInsets.all(16),
              child: Consumer<AppSettings>(
                builder: (_, settings, __) => Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Current Configuration',
                        style: GoogleFonts.inter(
                            color: theme.colorScheme.onSurface.withOpacity(0.7),
                            fontSize: 12,
                            fontWeight: FontWeight.w600)),
                    const SizedBox(height: 12),
                    _infoRow('REST API', settings.apiBase, theme),
                    _infoRow('WebSocket', '${settings.wsUrl}/live', theme),
                  ],
                ),
              ),
            ),

            if (_connectionError != null) ...[
              const SizedBox(height: 16),
              GlassyContainer(
                padding: const EdgeInsets.all(16),
                child: Row(
                  children: [
                    const Icon(Icons.error_outline,
                        color: Colors.red, size: 18),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        _connectionError!,
                        style: const TextStyle(color: Colors.red),
                      ),
                    ),
                  ],
                ),
              ),
            ],

            if (_healthPreview != null) ...[
              const SizedBox(height: 16),
              GlassyContainer(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Backend Reachability',
                      style: GoogleFonts.inter(
                        color: theme.colorScheme.onSurface,
                        fontSize: 14,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 12),
                    _infoRow(
                        'Status', '${_healthPreview!['status'] ?? '?'}', theme),
                    _infoRow('Environment',
                        '${_healthPreview!['environment'] ?? '?'}', theme),
                    _infoRow(
                        'DB',
                        _healthPreview!['db_ok'] == true
                            ? 'Reachable'
                            : 'Unavailable',
                        theme),
                    _infoRow(
                      'Realtime',
                      (_healthPreview!['websocket_clients'] as num? ?? 0) > 0
                          ? '${_healthPreview!['websocket_clients']} client(s)'
                          : 'No live clients connected',
                      theme,
                    ),
                    _infoRow(
                      'Event backlog',
                      '${_healthPreview!['event_bus_backlog'] ?? 0}',
                      theme,
                    ),
                  ],
                ),
              ),
            ],

            const SizedBox(height: 32),
            Divider(color: theme.dividerColor),
            const SizedBox(height: 16),
            Text('Danger Zone',
                style: GoogleFonts.inter(
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                    color: Colors.red)),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              icon: const Icon(Icons.logout, size: 16),
              label: const Text('Logout'),
              style: OutlinedButton.styleFrom(
                  foregroundColor: Colors.red,
                  side: const BorderSide(color: Colors.red)),
              onPressed: () async {
                context.read<WebSocketService>().disconnect(clearEvents: true);
                await context.read<AuthService>().logout();
                if (context.mounted) context.go('/login');
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _infoRow(String label, String value, ThemeData theme) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
              width: 80,
              child: Text(label,
                  style: TextStyle(
                      color: theme.colorScheme.onSurface.withOpacity(0.5),
                      fontSize: 12))),
          Expanded(
              child: Text(value,
                  style: TextStyle(
                      color: theme.colorScheme.onSurface.withOpacity(0.8),
                      fontSize: 12,
                      fontFamily: 'monospace'))),
        ],
      ),
    );
  }
}
