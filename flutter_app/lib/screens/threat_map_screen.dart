import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../core/auth_service.dart';
import '../core/websocket_service.dart';
import '../models/threat_model.dart';
import '../widgets/app_shell_drawer.dart';
import '../widgets/map_widget.dart';
import '../widgets/glassy_container.dart';

class ThreatMapScreen extends StatefulWidget {
  const ThreatMapScreen({super.key});

  @override
  State<ThreatMapScreen> createState() => _ThreatMapScreenState();
}

class _ThreatMapScreenState extends State<ThreatMapScreen> {
  List<ThreatModel> _threats = [];
  List<ThreatModel> _mappable = [];
  bool _loading = true;
  String? _filter;
  VoidCallback? _wsListener;
  DateTime? _lastSyncedAt;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _fetchThreats();
      _listenToWs();
    });
  }

  @override
  void dispose() {
    final listener = _wsListener;
    if (listener != null) {
      context.read<WebSocketService>().removeListener(listener);
    }
    super.dispose();
  }

  Future<void> _fetchThreats() async {
    setState(() => _loading = true);
    try {
      final api = context.read<AuthService>().api;
      final resp =
          await api.get('/threats', params: {'page': 1, 'page_size': 200});
      final data = resp.data as Map<String, dynamic>;
      final all =
          (data['items'] as List).map((j) => ThreatModel.fromJson(j)).toList();
      setState(() {
        _threats = all;
        _mappable = all
            .where((t) => t.latitude != null && t.longitude != null)
            .toList();
        _loading = false;
        _lastSyncedAt = DateTime.now();
      });
    } catch (_) {
      setState(() => _loading = false);
    }
  }

  void _listenToWs() {
    final ws = context.read<WebSocketService>();
    _wsListener ??= () {
      if (!mounted || ws.events.isEmpty) return;
      final latest = ws.events.first;
      if (latest['type'] != 'threat') return;

      final id = latest['id']?.toString();
      if (id == null || _threats.any((t) => t.id == id)) return;

      final threat = ThreatModel.fromJson({
        ...latest,
        'id': id,
        'action_taken': latest['action_taken'] ?? latest['action'],
        'detected_at':
            latest['detected_at'] ?? DateTime.now().toUtc().toIso8601String(),
        'acknowledged': latest['acknowledged'] ?? false,
      });

      setState(() {
        _threats = [threat, ..._threats];
        if (threat.latitude != null && threat.longitude != null) {
          _mappable = [threat, ..._mappable];
        }
      });
    };
    ws.addListener(_wsListener!);
  }

  List<ThreatModel> get _filtered {
    if (_filter == null) return _mappable;
    return _mappable.where((t) {
      if (_filter == 'high') return t.riskScore > 0.85;
      if (_filter == 'medium') {
        return t.riskScore > 0.5 && t.riskScore <= 0.85;
      }
      return t.riskScore <= 0.5;
    }).toList();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final ws = context.watch<WebSocketService>();
    final highRisk = _threats.where((threat) => threat.riskScore > 0.85).length;
    return Scaffold(
      drawer: const AppShellDrawer(),
      appBar: AppBar(
        title: Text(
            'Threat Map (${_threats.length} threats, ${_mappable.length} geolocated)'),
        actions: [
          _filterChip('high', 'High', Colors.red, theme),
          _filterChip('medium', 'Med', Colors.orange, theme),
          _filterChip('low', 'Low', theme.colorScheme.primary, theme),
          if (_filter != null)
            TextButton(
              onPressed: () => setState(() => _filter = null),
              child: Text('All',
                  style: TextStyle(
                      color: theme.colorScheme.onSurface.withOpacity(0.5))),
            ),
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchThreats),
        ],
      ),
      body: _loading
          ? Center(
              child:
                  CircularProgressIndicator(color: theme.colorScheme.primary))
          : Column(
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                  child: GlassyContainer(
                    borderRadius: 24,
                    padding: const EdgeInsets.all(18),
                    child: Wrap(
                      alignment: WrapAlignment.spaceBetween,
                      runSpacing: 12,
                      spacing: 12,
                      children: [
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Threat intelligence stream',
                              style: GoogleFonts.spaceGrotesk(
                                fontSize: 22,
                                fontWeight: FontWeight.w700,
                                color: theme.colorScheme.onSurface,
                              ),
                            ),
                            const SizedBox(height: 6),
                            Text(
                              ws.connected
                                  ? 'Incoming threat events are appended live and geolocated when enrichment is available.'
                                  : 'Realtime is offline. The map still shows stored threat history from the backend.',
                              style: TextStyle(
                                color: theme.colorScheme.onSurface
                                    .withOpacity(0.64),
                                height: 1.5,
                              ),
                            ),
                          ],
                        ),
                        Wrap(
                          spacing: 10,
                          runSpacing: 10,
                          children: [
                            _summaryPill(theme, 'Total', '${_threats.length}'),
                            _summaryPill(theme, 'High risk', '$highRisk',
                                danger: highRisk > 0),
                            _summaryPill(
                              theme,
                              'Last sync',
                              _lastSyncedAt == null
                                  ? 'Never'
                                  : timeago.format(_lastSyncedAt!),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
                Expanded(flex: 3, child: AttackMapWidget(threats: _filtered)),
                GlassyContainer(
                  borderRadius: 0,
                  margin: EdgeInsets.zero,
                  child: SizedBox(
                    height: 180,
                    child: _threats.isEmpty
                        ? Center(
                            child: Text(
                              'No threats recorded yet',
                              style: TextStyle(
                                  color: theme.colorScheme.onSurface
                                      .withOpacity(0.5)),
                            ),
                          )
                        : ListView.separated(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 16, vertical: 8),
                            itemCount: _threats.length,
                            separatorBuilder: (_, __) => Divider(
                                color: theme.dividerColor.withOpacity(0.1)),
                            itemBuilder: (_, i) {
                              final threat = _threats[i];
                              final color = threat.riskScore > 0.85
                                  ? Colors.red
                                  : threat.riskScore > 0.5
                                      ? Colors.orange
                                      : theme.colorScheme.primary;
                              final locationParts = [
                                threat.country ?? 'Unknown',
                                if (threat.city != null &&
                                    threat.city!.isNotEmpty)
                                  threat.city!,
                                timeago.format(threat.detectedAt),
                              ];
                              return ListTile(
                                dense: true,
                                leading: Container(
                                  width: 8,
                                  height: 8,
                                  decoration: BoxDecoration(
                                    shape: BoxShape.circle,
                                    color: color,
                                  ),
                                ),
                                title: Text(
                                  '${threat.srcIp} - ${threat.threatType}',
                                  style: TextStyle(
                                      color: theme.colorScheme.onSurface,
                                      fontSize: 13),
                                ),
                                subtitle: Text(
                                  locationParts.join(' - '),
                                  style: TextStyle(
                                      color: theme.colorScheme.onSurface
                                          .withOpacity(0.6),
                                      fontSize: 11),
                                ),
                                trailing: Container(
                                  padding: const EdgeInsets.symmetric(
                                      horizontal: 8, vertical: 3),
                                  decoration: BoxDecoration(
                                    color: color.withOpacity(0.15),
                                    borderRadius: BorderRadius.circular(6),
                                    border: Border.all(
                                        color: color.withOpacity(0.5)),
                                  ),
                                  child: Text(
                                    '${(threat.riskScore * 100).toInt()}%',
                                    style: TextStyle(
                                      color: color,
                                      fontSize: 11,
                                      fontWeight: FontWeight.w700,
                                    ),
                                  ),
                                ),
                              );
                            },
                          ),
                  ),
                ),
              ],
            ),
    );
  }

  Widget _filterChip(String value, String label, Color color, ThemeData theme) {
    final active = _filter == value;
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 2, vertical: 8),
      child: FilterChip(
        label: Text(
          label,
          style: TextStyle(
            color: active ? theme.colorScheme.surface : color,
            fontSize: 11,
            fontWeight: FontWeight.w700,
          ),
        ),
        selected: active,
        selectedColor: color,
        backgroundColor: color.withOpacity(0.1),
        side: BorderSide(color: color.withOpacity(0.4)),
        onSelected: (_) => setState(() => _filter = active ? null : value),
      ),
    );
  }

  Widget _summaryPill(ThemeData theme, String label, String value,
      {bool danger = false}) {
    final color = danger ? Colors.red : theme.colorScheme.primary;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: color.withOpacity(0.10),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: TextStyle(
              color: theme.colorScheme.onSurface.withOpacity(0.55),
              fontSize: 11,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            value,
            style: GoogleFonts.spaceGrotesk(
              color: color,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }
}
