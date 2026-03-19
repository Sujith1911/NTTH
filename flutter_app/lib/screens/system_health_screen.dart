import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:percent_indicator/percent_indicator.dart';
import 'package:provider/provider.dart';

import '../core/auth_service.dart';

class SystemHealthScreen extends StatefulWidget {
  const SystemHealthScreen({super.key});

  @override
  State<SystemHealthScreen> createState() => _SystemHealthScreenState();
}

class _SystemHealthScreenState extends State<SystemHealthScreen> {
  Map<String, dynamic>? _health;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _fetch();
  }

  Future<void> _fetch() async {
    setState(() => _loading = true);
    try {
      final api = context.read<AuthService>().api;
      final resp = await api.get('/system/health');
      setState(() { _health = resp.data as Map<String, dynamic>; _loading = false; });
    } catch (_) {
      setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('System Health'),
        actions: [IconButton(icon: const Icon(Icons.refresh), onPressed: _fetch)],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: Color(0xFF00FF88)))
          : _health == null
              ? const Center(child: Text('Could not reach backend', style: TextStyle(color: Colors.red)))
              : SingleChildScrollView(
                  padding: const EdgeInsets.all(24),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _statusBanner(_health!),
                      const SizedBox(height: 24),
                      Text('Component Status', style: GoogleFonts.inter(fontSize: 16, fontWeight: FontWeight.w600, color: Colors.white)),
                      const SizedBox(height: 16),
                      _statusGrid(_health!),
                      const SizedBox(height: 24),
                      Text('Build Info', style: GoogleFonts.inter(fontSize: 16, fontWeight: FontWeight.w600, color: Colors.white)),
                      const SizedBox(height: 12),
                      _infoCard([
                        ('Version', _health!['version'] ?? '?'),
                        ('Environment', _health!['environment'] ?? '?'),
                      ]),
                    ],
                  ),
                ),
    );
  }

  Widget _statusBanner(Map h) {
    final ok = h['status'] == 'ok';
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: (ok ? const Color(0xFF00FF88) : Colors.red).withOpacity(0.1),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: (ok ? const Color(0xFF00FF88) : Colors.red).withOpacity(0.4)),
      ),
      child: Row(children: [
        Icon(ok ? Icons.check_circle : Icons.error, color: ok ? const Color(0xFF00FF88) : Colors.red, size: 36),
        const SizedBox(width: 16),
        Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(ok ? 'All Systems Operational' : 'System Degraded',
              style: GoogleFonts.inter(fontSize: 18, fontWeight: FontWeight.w700, color: Colors.white)),
          Text(ok ? 'Backend running normally' : 'Check component status below',
              style: const TextStyle(color: Colors.white54, fontSize: 13)),
        ]),
      ]),
    );
  }

  Widget _statusGrid(Map h) {
    final components = [
      ('Database', h['db_ok'] == true),
      ('Packet Sniffer', h['sniffer_running'] == true),
      ('Scheduler', h['scheduler_running'] == true),
    ];
    return GridView.count(
      crossAxisCount: 3,
      shrinkWrap: true,
      mainAxisSpacing: 12,
      crossAxisSpacing: 12,
      childAspectRatio: 2,
      physics: const NeverScrollableScrollPhysics(),
      children: components.map((c) => _componentCard(c.$1, c.$2)).toList(),
    );
  }

  Widget _componentCard(String name, bool ok) {
    final color = ok ? const Color(0xFF00FF88) : Colors.red;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF111827),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
        Icon(ok ? Icons.check_circle_outline : Icons.cancel_outlined, color: color, size: 20),
        const SizedBox(height: 6),
        Text(name, style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w600)),
      ]),
    );
  }

  Widget _infoCard(List<(String, String)> items) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF111827),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF1F2937)),
      ),
      child: Column(
        children: items.map((i) => Padding(
          padding: const EdgeInsets.symmetric(vertical: 6),
          child: Row(children: [
            SizedBox(width: 100, child: Text(i.$1, style: const TextStyle(color: Colors.white38, fontSize: 13))),
            Text(i.$2, style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w500)),
          ]),
        )).toList(),
      ),
    );
  }
}
