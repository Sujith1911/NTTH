import 'package:flutter/material.dart';
import 'package:flutter_map/flutter_map.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:latlong2/latlong.dart';
import 'package:provider/provider.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../core/auth_service.dart';
import '../models/threat_model.dart';
import '../widgets/map_widget.dart';

class ThreatMapScreen extends StatefulWidget {
  const ThreatMapScreen({super.key});

  @override
  State<ThreatMapScreen> createState() => _ThreatMapScreenState();
}

class _ThreatMapScreenState extends State<ThreatMapScreen> {
  List<ThreatModel> _threats = [];
  List<ThreatModel> _mappable = [];
  bool _loading = true;
  String? _filter; // 'high' | 'medium' | 'low'

  @override
  void initState() {
    super.initState();
    _fetchThreats();
  }

  Future<void> _fetchThreats() async {
    setState(() { _loading = true; });
    try {
      final api = context.read<AuthService>().api;
      final resp = await api.get('/threats', params: {'page': 1, 'page_size': 200});
      final data = resp.data as Map<String, dynamic>;
      final all = (data['items'] as List).map((j) => ThreatModel.fromJson(j)).toList();
      setState(() {
        _threats = all;
        _mappable = all.where((t) => t.latitude != null && t.longitude != null).toList();
        _loading = false;
      });
    } catch (_) {
      setState(() => _loading = false);
    }
  }

  List<ThreatModel> get _filtered {
    if (_filter == null) return _mappable;
    return _mappable.where((t) {
      if (_filter == 'high') return t.riskScore > 0.85;
      if (_filter == 'medium') return t.riskScore > 0.5 && t.riskScore <= 0.85;
      return t.riskScore <= 0.5;
    }).toList();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Threat Map (${_threats.length} threats, ${_mappable.length} geolocated)'),
        actions: [
          // Filter chips
          _filterChip('high', 'High', Colors.red),
          _filterChip('medium', 'Med', Colors.orange),
          _filterChip('low', 'Low', const Color(0xFF00FF88)),
          if (_filter != null)
            TextButton(
              onPressed: () => setState(() => _filter = null),
              child: const Text('All', style: TextStyle(color: Colors.white38)),
            ),
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchThreats),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: Color(0xFF00FF88)))
          : Column(children: [
              Expanded(flex: 3, child: AttackMapWidget(threats: _filtered)),
              Container(
                height: 180,
                color: const Color(0xFF111827),
                child: _threats.isEmpty
                    ? const Center(
                        child: Text('No threats recorded yet', style: TextStyle(color: Colors.white38)))
                    : ListView.builder(
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                        itemCount: _threats.length,
                        itemBuilder: (_, i) {
                          final t = _threats[i];
                          final color = t.riskScore > 0.85
                              ? Colors.red
                              : t.riskScore > 0.5 ? Colors.orange : const Color(0xFF00FF88);
                          return ListTile(
                            dense: true,
                            leading: Container(
                              width: 8, height: 8,
                              decoration: BoxDecoration(shape: BoxShape.circle, color: color),
                            ),
                            title: Text(
                              '${t.srcIp} — ${t.threatType}',
                              style: const TextStyle(color: Colors.white, fontSize: 12),
                            ),
                            subtitle: Text(
                              '${t.country ?? "Unknown"} ${t.city != null ? "• ${t.city}" : ""} • ${timeago.format(t.detectedAt)}',
                              style: const TextStyle(color: Colors.white38, fontSize: 11),
                            ),
                            trailing: Container(
                              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                              decoration: BoxDecoration(
                                color: color.withOpacity(0.15),
                                borderRadius: BorderRadius.circular(6),
                                border: Border.all(color: color.withOpacity(0.5)),
                              ),
                              child: Text(
                                '${(t.riskScore * 100).toInt()}%',
                                style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w700),
                              ),
                            ),
                          );
                        },
                      ),
              ),
            ]),
    );
  }

  Widget _filterChip(String value, String label, Color color) {
    final active = _filter == value;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 2, vertical: 8),
      child: FilterChip(
        label: Text(label, style: TextStyle(
          color: active ? const Color(0xFF080C18) : color, fontSize: 11, fontWeight: FontWeight.w700)),
        selected: active,
        selectedColor: color,
        backgroundColor: color.withOpacity(0.1),
        side: BorderSide(color: color.withOpacity(0.4)),
        onSelected: (_) => setState(() => _filter = active ? null : value),
      ),
    );
  }
}
