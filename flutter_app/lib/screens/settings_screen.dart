import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../core/app_settings.dart';
import '../core/auth_service.dart';
import '../core/websocket_service.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late TextEditingController _urlCtrl;
  bool _saved = false;

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
    ws.disconnect();
    setState(() => _saved = true);
    await Future.delayed(const Duration(seconds: 2));
    if (mounted) setState(() => _saved = false);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Backend Server',
              style: GoogleFonts.inter(fontSize: 16, fontWeight: FontWeight.w600, color: Colors.white),
            ),
            const SizedBox(height: 8),
            const Text(
              'Enter the IP address of your Linux server running NO TIME TO HACK.',
              style: TextStyle(color: Colors.white38, fontSize: 13),
            ),
            const SizedBox(height: 16),
            TextFormField(
              controller: _urlCtrl,
              style: const TextStyle(color: Colors.white),
              decoration: InputDecoration(
                labelText: 'Server URL',
                labelStyle: const TextStyle(color: Colors.white38),
                hintText: 'http://192.168.1.100:8000',
                hintStyle: const TextStyle(color: Colors.white24),
                filled: true,
                fillColor: const Color(0xFF111827),
                prefixIcon: const Icon(Icons.dns_outlined, color: Color(0xFF00FF88), size: 20),
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: Color(0xFF1F2937))),
                focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: Color(0xFF00FF88), width: 1.5)),
                enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: Color(0xFF1F2937))),
              ),
            ),
            const SizedBox(height: 20),
            SizedBox(
              width: double.infinity,
              height: 50,
              child: ElevatedButton.icon(
                icon: Icon(_saved ? Icons.check : Icons.save_outlined, size: 18),
                label: Text(_saved ? 'Saved!' : 'Save & Reconnect'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: _saved ? Colors.green : const Color(0xFF00FF88),
                  foregroundColor: const Color(0xFF080C18),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                  textStyle: GoogleFonts.inter(fontWeight: FontWeight.w700),
                ),
                onPressed: _save,
              ),
            ),
            const SizedBox(height: 32),

            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: const Color(0xFF111827),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: const Color(0xFF1F2937)),
              ),
              child: Consumer<AppSettings>(
                builder: (_, settings, __) => Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Current Configuration', style: GoogleFonts.inter(color: Colors.white54, fontSize: 12, fontWeight: FontWeight.w600)),
                    const SizedBox(height: 12),
                    _infoRow('REST API', settings.apiBase),
                    _infoRow('WebSocket', '${settings.wsUrl}/live'),
                  ],
                ),
              ),
            ),

            const SizedBox(height: 24),
            const Divider(color: Color(0xFF1F2937)),
            const SizedBox(height: 16),
            Text('Danger Zone', style: GoogleFonts.inter(fontSize: 14, fontWeight: FontWeight.w600, color: Colors.red)),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              icon: const Icon(Icons.logout, size: 16),
              label: const Text('Logout'),
              style: OutlinedButton.styleFrom(foregroundColor: Colors.red, side: const BorderSide(color: Colors.red)),
              onPressed: () async {
                await context.read<AuthService>().logout();
                if (context.mounted) context.go('/login');
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _infoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 80, child: Text(label, style: const TextStyle(color: Colors.white38, fontSize: 12))),
          Expanded(child: Text(value, style: const TextStyle(color: Colors.white70, fontSize: 12, fontFamily: 'monospace'))),
        ],
      ),
    );
  }
}
