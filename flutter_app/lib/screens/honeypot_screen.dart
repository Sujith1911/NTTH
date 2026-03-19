import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../core/auth_service.dart';
import '../models/honeypot_model.dart';

class HoneypotScreen extends StatefulWidget {
  const HoneypotScreen({super.key});

  @override
  State<HoneypotScreen> createState() => _HoneypotScreenState();
}

class _HoneypotScreenState extends State<HoneypotScreen> {
  List<HoneypotModel> _sessions = [];
  bool _loading = true;
  Map<String, dynamic>? _cowrieStatus;

  @override
  void initState() {
    super.initState();
    _fetchAll();
  }

  Future<void> _fetchAll() async {
    setState(() => _loading = true);
    try {
      final api = context.read<AuthService>().api;
      final [sessResp, statusResp] = await Future.wait([
        api.get('/honeypot/sessions', params: {'page': 1, 'page_size': 100}),
        api.get('/honeypot/status'),
      ]);
      setState(() {
        _sessions = ((sessResp.data as Map)['items'] as List).map((j) => HoneypotModel.fromJson(j)).toList();
        _cowrieStatus = statusResp.data as Map<String, dynamic>;
        _loading = false;
      });
    } catch (_) {
      setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final isAdmin = context.read<AuthService>().isAdmin;
    final status = _cowrieStatus?['status'] as String? ?? '?';

    return Scaffold(
      appBar: AppBar(
        title: const Text('Honeypot Sessions'),
        actions: [IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchAll)],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: Color(0xFF00FF88)))
          : Column(
              children: [
                // Cowrie status bar
                Container(
                  margin: const EdgeInsets.all(16),
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: const Color(0xFF111827),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: const Color(0xFF1F2937)),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.bug_report_outlined, color: Color(0xFF00FF88)),
                      const SizedBox(width: 12),
                      Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        const Text('Cowrie SSH Honeypot', style: TextStyle(color: Colors.white, fontWeight: FontWeight.w600)),
                        Text('Status: $status', style: TextStyle(color: status == 'running' ? const Color(0xFF00FF88) : Colors.red, fontSize: 13)),
                      ]),
                      const Spacer(),
                      if (isAdmin) ...[
                        OutlinedButton.icon(
                          icon: const Icon(Icons.play_arrow, size: 16),
                          label: const Text('Start'),
                          style: OutlinedButton.styleFrom(foregroundColor: const Color(0xFF00FF88), side: const BorderSide(color: Color(0xFF00FF88))),
                          onPressed: () async {
                            await context.read<AuthService>().api.post('/honeypot/start', {});
                            _fetchAll();
                          },
                        ),
                        const SizedBox(width: 8),
                        OutlinedButton.icon(
                          icon: const Icon(Icons.stop, size: 16),
                          label: const Text('Stop'),
                          style: OutlinedButton.styleFrom(foregroundColor: Colors.red, side: const BorderSide(color: Colors.red)),
                          onPressed: () async {
                            await context.read<AuthService>().api.post('/honeypot/stop', {});
                            _fetchAll();
                          },
                        ),
                      ],
                    ],
                  ),
                ),

                // Session list
                Expanded(
                  child: _sessions.isEmpty
                      ? const Center(child: Text('No honeypot sessions yet', style: TextStyle(color: Colors.white38)))
                      : ListView.separated(
                          padding: const EdgeInsets.symmetric(horizontal: 16),
                          itemCount: _sessions.length,
                          separatorBuilder: (_, __) => const SizedBox(height: 8),
                          itemBuilder: (_, i) {
                            final s = _sessions[i];
                            return ExpansionTile(
                              backgroundColor: const Color(0xFF111827),
                              collapsedBackgroundColor: const Color(0xFF111827),
                              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12), side: const BorderSide(color: Color(0xFF1F2937))),
                              collapsedShape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12), side: const BorderSide(color: Color(0xFF1F2937))),
                              leading: Icon(s.honeypotType == 'ssh' ? Icons.terminal : Icons.language, color: Colors.purple),
                              title: Text(s.attackerIp, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600)),
                              subtitle: Text('${s.country ?? "Unknown"} • ${timeago.format(s.startedAt)}', style: const TextStyle(color: Colors.white38, fontSize: 12)),
                              trailing: Text(s.honeypotType.toUpperCase(), style: const TextStyle(color: Colors.purple, fontSize: 11, fontWeight: FontWeight.w700)),
                              children: [
                                Padding(
                                  padding: const EdgeInsets.all(16),
                                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                                    if (s.usernameTried != null) _infoRow('Username', s.usernameTried!),
                                    if (s.passwordTried != null) _infoRow('Password', s.passwordTried!),
                                    if (s.commandsRun != null) _infoRow('Commands', s.commandsRun!),
                                    if (s.durationSeconds != null) _infoRow('Duration', '${s.durationSeconds!.toStringAsFixed(1)}s'),
                                  ]),
                                ),
                              ],
                            );
                          },
                        ),
                ),
              ],
            ),
    );
  }

  Widget _infoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        SizedBox(width: 80, child: Text(label, style: const TextStyle(color: Colors.white38, fontSize: 12))),
        Expanded(child: Text(value, style: const TextStyle(color: Colors.white70, fontSize: 12, fontFamily: 'monospace'))),
      ]),
    );
  }
}
