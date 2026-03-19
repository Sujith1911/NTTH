import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../core/auth_service.dart';

class FirewallScreen extends StatefulWidget {
  const FirewallScreen({super.key});

  @override
  State<FirewallScreen> createState() => _FirewallScreenState();
}

class _FirewallScreenState extends State<FirewallScreen> {
  List<dynamic> _rules = [];
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _fetchRules();
  }

  Future<void> _fetchRules() async {
    setState(() { _loading = true; _error = null; });
    try {
      final api = context.read<AuthService>().api;
      final resp = await api.get('/firewall/rules');
      setState(() { _rules = resp.data as List; _loading = false; });
    } catch (e) {
      setState(() { _error = e.toString(); _loading = false; });
    }
  }

  Future<void> _deleteRule(String ruleId) async {
    try {
      final api = context.read<AuthService>().api;
      await api.delete('/firewall/rules/$ruleId');
      _fetchRules();
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Error: $e'), backgroundColor: Colors.red));
    }
  }

  Future<void> _emergencyFlush() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: const Color(0xFF111827),
        title: Text('⚠️ Emergency Flush', style: GoogleFonts.inter(color: Colors.red, fontWeight: FontWeight.w700)),
        content: const Text('This will remove ALL dynamic firewall rules. Continue?', style: TextStyle(color: Colors.white70)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () => Navigator.pop(context, true),
            child: const Text('FLUSH ALL'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      try {
        final api = context.read<AuthService>().api;
        await api.post('/firewall/flush', {});
        _fetchRules();
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('All rules flushed'), backgroundColor: Color(0xFF00FF88)));
      } catch (e) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Error: $e'), backgroundColor: Colors.red));
      }
    }
  }

  Color _ruleColor(String type) {
    return switch (type) {
      'block' => Colors.red,
      'rate_limit' => Colors.orange,
      'redirect' => Colors.blue,
      _ => Colors.grey,
    };
  }

  @override
  Widget build(BuildContext context) {
    final isAdmin = context.read<AuthService>().isAdmin;
    return Scaffold(
      appBar: AppBar(
        title: Text('Firewall Rules (${_rules.length})'),
        actions: [
          if (isAdmin)
            IconButton(
              icon: const Icon(Icons.warning_amber, color: Colors.red),
              tooltip: 'Emergency Flush',
              onPressed: _emergencyFlush,
            ),
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchRules),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: Color(0xFF00FF88)))
          : _error != null
              ? Center(child: Text(_error!, style: const TextStyle(color: Colors.red)))
              : _rules.isEmpty
                  ? const Center(child: Text('No active firewall rules', style: TextStyle(color: Colors.white38)))
                  : ListView.separated(
                      padding: const EdgeInsets.all(16),
                      itemCount: _rules.length,
                      separatorBuilder: (_, __) => const SizedBox(height: 8),
                      itemBuilder: (_, i) {
                        final r = _rules[i] as Map<String, dynamic>;
                        final type = r['rule_type'] as String? ?? '?';
                        final color = _ruleColor(type);
                        return Container(
                          padding: const EdgeInsets.all(16),
                          decoration: BoxDecoration(
                            color: const Color(0xFF111827),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(color: color.withOpacity(0.3)),
                          ),
                          child: Row(
                            children: [
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                                decoration: BoxDecoration(
                                  color: color.withOpacity(0.15),
                                  borderRadius: BorderRadius.circular(6),
                                  border: Border.all(color: color.withOpacity(0.5)),
                                ),
                                child: Text(type.toUpperCase(), style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.w700)),
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(r['target_ip'] ?? '?', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600)),
                                    if (r['reason'] != null)
                                      Text(r['reason'], style: const TextStyle(color: Colors.white38, fontSize: 12)),
                                  ],
                                ),
                              ),
                              if (isAdmin)
                                IconButton(
                                  icon: const Icon(Icons.delete_outline, color: Colors.red, size: 20),
                                  onPressed: () => _deleteRule(r['id']),
                                ),
                            ],
                          ),
                        );
                      },
                    ),
    );
  }
}
