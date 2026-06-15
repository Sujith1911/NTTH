import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../core/auth_service.dart';
import '../core/websocket_service.dart';
import '../models/threat_model.dart';
import '../widgets/app_shell_drawer.dart';
import '../widgets/glassy_container.dart';

class ThreatMapScreen extends StatefulWidget {
  const ThreatMapScreen({super.key});

  @override
  State<ThreatMapScreen> createState() => _ThreatMapScreenState();
}

class _ThreatMapScreenState extends State<ThreatMapScreen> {
  List<ThreatModel> _threats = [];
  bool _loading = true;
  String? _filter;
  String _query = '';
  VoidCallback? _wsListener;
  DateTime? _lastSyncedAt;
  ThreatModel? _selectedThreat;

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
      });
    };
    ws.addListener(_wsListener!);
  }

  List<ThreatModel> get _filtered {
    final visible = _threats.where((t) {
      if (_filter == 'high') return t.riskScore > 0.85;
      if (_filter == 'medium') {
        return t.riskScore > 0.5 && t.riskScore <= 0.85;
      }
      if (_filter == 'low') return t.riskScore <= 0.5;
      return true;
    }).where((t) {
      if (_query.trim().isEmpty) return true;
      final q = _query.trim().toLowerCase();
      return [
        t.srcIp,
        t.victimIp,
        t.dstIp,
        t.threatType,
        t.actionTaken,
        t.responseMode,
        t.networkOrigin,
        t.locationSummary,
        t.org,
      ].whereType<String>().any((value) => value.toLowerCase().contains(q));
    }).toList();
    return visible;
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final ws = context.watch<WebSocketService>();
    final highRisk = _threats.where((t) => t.riskScore > 0.85).length;
    final medRisk =
        _threats.where((t) => t.riskScore > 0.5 && t.riskScore <= 0.85).length;
    final lowRisk = _threats.where((t) => t.riskScore <= 0.5).length;
    final blocked =
        _threats.where((t) => t.actionTaken == 'block').length;
    final honeypotted =
        _threats.where((t) => t.actionTaken == 'honeypot').length;

    return Scaffold(
      drawer: const AppShellDrawer(),
      appBar: AppBar(
        title: Text(
          'Threat Details (${_threats.length})',
          style: GoogleFonts.spaceGrotesk(fontWeight: FontWeight.w700),
        ),
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
                // Summary header
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                  child: GlassyContainer(
                    borderRadius: 24,
                    padding: const EdgeInsets.all(18),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Icon(Icons.warning_amber_rounded,
                                color: highRisk > 0
                                    ? Colors.red
                                    : theme.colorScheme.primary,
                                size: 28),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Column(
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
                                  const SizedBox(height: 4),
                                  Text(
                                    ws.connected
                                        ? 'Live threat events with detailed risk scoring, network origin, and response actions.'
                                        : 'Realtime is offline. Showing stored threat history.',
                                    style: TextStyle(
                                      color: theme.colorScheme.onSurface
                                          .withOpacity(0.64),
                                      height: 1.5,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 14),
                        Wrap(
                          spacing: 10,
                          runSpacing: 10,
                          children: [
                            _summaryPill(theme, 'Total', '${_threats.length}'),
                            _summaryPill(theme, 'High risk', '$highRisk',
                                danger: highRisk > 0),
                            _summaryPill(theme, 'Medium', '$medRisk',
                                color: Colors.orange),
                            _summaryPill(theme, 'Low', '$lowRisk'),
                            _summaryPill(theme, 'Blocked', '$blocked',
                                color: Colors.red),
                            _summaryPill(theme, 'Honeypotted', '$honeypotted',
                                color: Colors.blue),
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
                // Search bar
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                  child: TextField(
                    onChanged: (value) => setState(() => _query = value),
                    style: TextStyle(color: theme.colorScheme.onSurface),
                    decoration: InputDecoration(
                      hintText:
                          'Filter by attacker IP, victim IP, threat type, action, or origin',
                      hintStyle: TextStyle(
                        color: theme.colorScheme.onSurface.withOpacity(0.45),
                      ),
                      prefixIcon: const Icon(Icons.search),
                      suffixIcon: _query.isEmpty
                          ? null
                          : IconButton(
                              icon: const Icon(Icons.close),
                              onPressed: () => setState(() => _query = ''),
                            ),
                    ),
                  ),
                ),
                // Threat list + detail panel
                Expanded(
                  child: LayoutBuilder(
                    builder: (context, constraints) {
                      final isWide = constraints.maxWidth > 900;
                      if (isWide) {
                        return Row(
                          children: [
                            Expanded(
                              flex: 2,
                              child: _buildThreatList(theme),
                            ),
                            Expanded(
                              flex: 3,
                              child: _selectedThreat != null
                                  ? _buildDetailPanel(theme, _selectedThreat!)
                                  : Center(
                                      child: Column(
                                        mainAxisSize: MainAxisSize.min,
                                        children: [
                                          Icon(Icons.touch_app_outlined,
                                              size: 48,
                                              color: theme
                                                  .colorScheme.onSurface
                                                  .withOpacity(0.3)),
                                          const SizedBox(height: 12),
                                          Text(
                                            'Select a threat to view detailed risk scoring',
                                            style: TextStyle(
                                              color: theme
                                                  .colorScheme.onSurface
                                                  .withOpacity(0.5),
                                            ),
                                          ),
                                        ],
                                      ),
                                    ),
                            ),
                          ],
                        );
                      }
                      // Narrow: show list or detail
                      if (_selectedThreat != null) {
                        return Column(
                          children: [
                            // Back button
                            Padding(
                              padding:
                                  const EdgeInsets.symmetric(horizontal: 16),
                              child: Row(
                                children: [
                                  TextButton.icon(
                                    icon: const Icon(Icons.arrow_back, size: 16),
                                    label: const Text('Back to list'),
                                    onPressed: () => setState(
                                        () => _selectedThreat = null),
                                  ),
                                ],
                              ),
                            ),
                            Expanded(
                                child: _buildDetailPanel(
                                    theme, _selectedThreat!)),
                          ],
                        );
                      }
                      return _buildThreatList(theme);
                    },
                  ),
                ),
              ],
            ),
    );
  }

  Widget _buildThreatList(ThemeData theme) {
    final threats = _filtered;
    if (threats.isEmpty) {
      return Center(
        child: Text(
          'No threats match the current filter',
          style: TextStyle(
              color: theme.colorScheme.onSurface.withOpacity(0.5)),
        ),
      );
    }
    return ListView.builder(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      itemCount: threats.length,
      itemBuilder: (_, i) {
        final threat = threats[i];
        final color = threat.riskScore > 0.85
            ? Colors.red
            : threat.riskScore > 0.5
                ? Colors.orange
                : theme.colorScheme.primary;
        final isSelected = _selectedThreat?.id == threat.id;

        return GestureDetector(
          onTap: () => setState(() => _selectedThreat = threat),
          child: Container(
            margin: const EdgeInsets.only(bottom: 6),
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: isSelected
                  ? theme.colorScheme.primary.withOpacity(0.08)
                  : theme.colorScheme.surface.withOpacity(0.18),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: isSelected
                    ? theme.colorScheme.primary.withOpacity(0.5)
                    : color.withOpacity(0.15),
                width: isSelected ? 2 : 1,
              ),
            ),
            child: Row(
              children: [
                // Risk score circle
                Container(
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: color.withOpacity(0.12),
                    border: Border.all(color: color.withOpacity(0.4)),
                  ),
                  child: Center(
                    child: Text(
                      '${(threat.riskScore * 100).toInt()}',
                      style: GoogleFonts.spaceGrotesk(
                        color: color,
                        fontWeight: FontWeight.w800,
                        fontSize: 14,
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Expanded(
                            child: Text(
                              threat.srcIp,
                              style: TextStyle(
                                color: theme.colorScheme.onSurface,
                                fontWeight: FontWeight.w700,
                                fontSize: 13,
                              ),
                            ),
                          ),
                          _actionBadge(theme, threat.actionTaken),
                        ],
                      ),
                      const SizedBox(height: 4),
                      Text(
                        '${threat.threatType.replaceAll('_', ' ').toUpperCase()}  •  ${timeago.format(threat.detectedAt)}',
                        style: TextStyle(
                          color:
                              theme.colorScheme.onSurface.withOpacity(0.55),
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                Icon(
                  Icons.chevron_right,
                  color: theme.colorScheme.onSurface.withOpacity(0.3),
                  size: 18,
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildDetailPanel(ThemeData theme, ThreatModel threat) {
    final color = threat.riskScore > 0.85
        ? Colors.red
        : threat.riskScore > 0.5
            ? Colors.orange
            : theme.colorScheme.primary;
    final riskPercent = (threat.riskScore * 100).toInt();

    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Risk score hero
          GlassyContainer(
            borderRadius: 24,
            padding: const EdgeInsets.all(24),
            color: color.withOpacity(0.06),
            child: Column(
              children: [
                Row(
                  children: [
                    // Large risk circle
                    Container(
                      width: 80,
                      height: 80,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        gradient: LinearGradient(
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                          colors: [
                            color.withOpacity(0.2),
                            color.withOpacity(0.05),
                          ],
                        ),
                        border: Border.all(color: color.withOpacity(0.6), width: 3),
                      ),
                      child: Center(
                        child: Text(
                          '$riskPercent%',
                          style: GoogleFonts.spaceGrotesk(
                            color: color,
                            fontWeight: FontWeight.w800,
                            fontSize: 24,
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(width: 20),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            threat.threatType
                                .replaceAll('_', ' ')
                                .toUpperCase(),
                            style: GoogleFonts.spaceGrotesk(
                              color: color,
                              fontWeight: FontWeight.w700,
                              fontSize: 20,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            _riskLabel(threat.riskScore),
                            style: TextStyle(
                              color: theme.colorScheme.onSurface
                                  .withOpacity(0.7),
                              fontSize: 13,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 20),
                // Risk bar
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'RISK SCORE BREAKDOWN',
                      style: TextStyle(
                        color:
                            theme.colorScheme.onSurface.withOpacity(0.45),
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1.2,
                      ),
                    ),
                    const SizedBox(height: 8),
                    ClipRRect(
                      borderRadius: BorderRadius.circular(6),
                      child: LinearProgressIndicator(
                        value: threat.riskScore,
                        minHeight: 10,
                        backgroundColor: color.withOpacity(0.1),
                        valueColor: AlwaysStoppedAnimation(color),
                      ),
                    ),
                    const SizedBox(height: 8),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text('0%',
                            style: TextStyle(
                                color: theme.colorScheme.onSurface
                                    .withOpacity(0.4),
                                fontSize: 10)),
                        Row(
                          children: [
                            _thresholdMarker(
                                theme, '15% Log', 0.15, threat.riskScore),
                            const SizedBox(width: 12),
                            _thresholdMarker(
                                theme, '25% Throttle', 0.25, threat.riskScore),
                            const SizedBox(width: 12),
                            _thresholdMarker(
                                theme, '40% Honeypot', 0.40, threat.riskScore),
                            const SizedBox(width: 12),
                            _thresholdMarker(
                                theme, '80% Block', 0.80, threat.riskScore),
                          ],
                        ),
                        Text('100%',
                            style: TextStyle(
                                color: theme.colorScheme.onSurface
                                    .withOpacity(0.4),
                                fontSize: 10)),
                      ],
                    ),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Attacker details
          _sectionTitle(theme, 'ATTACKER DETAILS'),
          GlassyContainer(
            borderRadius: 18,
            padding: const EdgeInsets.all(16),
            child: Column(
              children: [
                _detailRow(theme, 'Source IP', threat.srcIp),
                _detailRow(
                    theme, 'Source Tag', threat.sourceTag ?? 'Not tagged'),
                _detailRow(theme, 'Network Origin',
                    threat.networkOrigin ?? 'Unknown'),
                _detailRow(theme, 'Location',
                    threat.locationSummary ?? 'Unresolved'),
                _detailRow(theme, 'Country', threat.country ?? 'Unknown'),
                _detailRow(theme, 'City', threat.city ?? 'Unknown'),
                _detailRow(theme, 'ASN', threat.asn ?? 'Unknown'),
                _detailRow(theme, 'Organization', threat.org ?? 'Unknown'),
                if (threat.latitude != null && threat.longitude != null)
                  _detailRow(theme, 'Coordinates',
                      '${threat.latitude!.toStringAsFixed(4)}, ${threat.longitude!.toStringAsFixed(4)}'),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Target details
          _sectionTitle(theme, 'TARGET DETAILS'),
          GlassyContainer(
            borderRadius: 18,
            padding: const EdgeInsets.all(16),
            child: Column(
              children: [
                _detailRow(theme, 'Victim IP',
                    threat.victimIp ?? threat.dstIp ?? 'Unknown'),
                _detailRow(theme, 'Destination Port',
                    threat.dstPort?.toString() ?? 'N/A'),
                _detailRow(
                    theme, 'Protocol', threat.protocol?.toUpperCase() ?? 'N/A'),
                _detailRow(theme, 'Target Hidden',
                    threat.targetHidden ? 'Yes' : 'No'),
                _detailRow(theme, 'Quarantine',
                    threat.quarantineTarget ? 'Active' : 'None'),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Response details
          _sectionTitle(theme, 'RESPONSE & ENFORCEMENT'),
          GlassyContainer(
            borderRadius: 18,
            padding: const EdgeInsets.all(16),
            child: Column(
              children: [
                _detailRow(theme, 'Action Taken',
                    (threat.actionTaken ?? 'Logged').toUpperCase(),
                    valueColor: _actionColor(threat.actionTaken)),
                _detailRow(theme, 'Response Mode',
                    threat.responseMode ?? 'Default'),
                if (threat.honeypotPort != null)
                  _detailRow(
                      theme, 'Honeypot Port', '${threat.honeypotPort}'),
                _detailRow(theme, 'Detected At',
                    '${threat.detectedAt.toLocal()}'),
                _detailRow(theme, 'Location Accuracy',
                    threat.locationAccuracy ?? 'N/A'),
                _detailRow(theme, 'Acknowledged',
                    threat.acknowledged ? 'Yes' : 'No'),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Notes
          if (threat.notes != null && threat.notes!.isNotEmpty) ...[
            _sectionTitle(theme, 'INCIDENT NOTES'),
            GlassyContainer(
              borderRadius: 18,
              padding: const EdgeInsets.all(16),
              child: Text(
                threat.notes!,
                style: TextStyle(
                  color: theme.colorScheme.onSurface.withOpacity(0.75),
                  height: 1.5,
                  fontSize: 13,
                ),
              ),
            ),
          ],
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  Widget _thresholdMarker(
      ThemeData theme, String label, double threshold, double current) {
    final passed = current >= threshold;
    return Text(
      label,
      style: TextStyle(
        color: passed
            ? theme.colorScheme.onSurface.withOpacity(0.8)
            : theme.colorScheme.onSurface.withOpacity(0.3),
        fontSize: 9,
        fontWeight: passed ? FontWeight.w700 : FontWeight.w500,
      ),
    );
  }

  Widget _sectionTitle(ThemeData theme, String title) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Text(
        title,
        style: TextStyle(
          color: theme.colorScheme.onSurface.withOpacity(0.45),
          fontSize: 11,
          fontWeight: FontWeight.w700,
          letterSpacing: 1.2,
        ),
      ),
    );
  }

  Widget _detailRow(ThemeData theme, String label, String value,
      {Color? valueColor}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 140,
            child: Text(
              label,
              style: TextStyle(
                color: theme.colorScheme.onSurface.withOpacity(0.55),
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                color: valueColor ??
                    theme.colorScheme.onSurface.withOpacity(0.85),
                fontSize: 13,
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _actionBadge(ThemeData theme, String? action) {
    final color = _actionColor(action);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withOpacity(0.12),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withOpacity(0.4)),
      ),
      child: Text(
        (action ?? 'logged').toUpperCase(),
        style: TextStyle(
          color: color,
          fontSize: 9,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }

  Color _actionColor(String? action) {
    return switch (action) {
      'block' => Colors.red,
      'honeypot' => Colors.blue,
      'rate_limit' => Colors.orange,
      'log' => Colors.grey,
      _ => Colors.grey,
    };
  }

  String _riskLabel(double score) {
    if (score >= 0.80) return 'CRITICAL — Full network block applied';
    if (score >= 0.40) return 'HIGH — Redirected to honeypot for analysis';
    if (score >= 0.25) return 'MEDIUM — Traffic throttled via rate limiting';
    if (score >= 0.15) return 'LOW — Logged for monitoring';
    return 'MINIMAL — Normal traffic, no action needed';
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
      {bool danger = false, Color? color}) {
    final c = color ?? (danger ? Colors.red : theme.colorScheme.primary);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: c.withOpacity(0.10),
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
              color: c,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }
}
