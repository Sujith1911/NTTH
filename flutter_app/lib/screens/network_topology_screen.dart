import 'dart:async';
import 'dart:math' as math;
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../core/auth_service.dart';
import '../core/websocket_service.dart';
import '../widgets/app_shell_drawer.dart';
import '../widgets/glassy_container.dart';

class NetworkTopologyScreen extends StatefulWidget {
  const NetworkTopologyScreen({super.key});

  @override
  State<NetworkTopologyScreen> createState() => _NetworkTopologyScreenState();
}

class _NetworkTopologyScreenState extends State<NetworkTopologyScreen>
    with TickerProviderStateMixin {
  Map<String, dynamic>? _topology;
  bool _loading = true;
  bool _scanning = false;
  String? _error;
  String? _selectedNodeId;
  Timer? _refreshTimer;
  VoidCallback? _wsListener;
  DateTime? _lastSyncedAt;

  // Canvas interaction
  Offset _panOffset = Offset.zero;
  Offset _lastPanStart = Offset.zero;
  double _scale = 1.0;

  // Layout positions for nodes
  final Map<String, Offset> _nodePositions = {};

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _fetchTopology();
      _listenWS();
    });
    // Refresh every 30s
    _refreshTimer =
        Timer.periodic(const Duration(seconds: 30), (_) => _fetchTopology());
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    final listener = _wsListener;
    if (listener != null) {
      context.read<WebSocketService>().removeListener(listener);
    }
    super.dispose();
  }

  void _listenWS() {
    final ws = context.read<WebSocketService>();
    _wsListener ??= _onWSEvent;
    ws.addListener(_wsListener!);
  }

  void _onWSEvent() {
    final ws = context.read<WebSocketService>();
    if (ws.events.isNotEmpty) {
      final latest = ws.events.first;
      if (latest['type'] == 'topology_updated' ||
          latest['type'] == 'device_seen' ||
          latest['type'] == 'device_updated') {
        _fetchTopology();
      }
    }
  }

  Future<void> _fetchTopology() async {
    if (!mounted) return;
    setState(() {
      _loading = _topology == null;
      _error = null;
    });
    try {
      final api = context.read<AuthService>().api;
      final resp = await api.get('/network/topology');
      final data = resp.data as Map<String, dynamic>;
      setState(() {
        _topology = data;
        _loading = false;
        _lastSyncedAt = DateTime.now();
        _layoutNodes(data);
      });
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
          _loading = false;
        });
      }
    }
  }

  Future<void> _triggerScan() async {
    setState(() => _scanning = true);
    final theme = Theme.of(context);
    try {
      final api = context.read<AuthService>().api;
      await api.post('/network/scan', {});
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content:
                const Text('Network scan started — results appear in ~30s'),
            backgroundColor: theme.colorScheme.primary,
          ),
        );
      }
      _waitForScanCompletion();
    } catch (e) {
      if (!mounted) return;
      setState(() => _scanning = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Unable to start scan: $e'),
          backgroundColor: Colors.red,
        ),
      );
    }
  }

  Future<void> _waitForScanCompletion() async {
    final api = context.read<AuthService>().api;
    try {
      for (var attempt = 0; attempt < 18; attempt++) {
        final resp = await api.get('/network/scan/status');
        final status = resp.data as Map<String, dynamic>;
        if (status['running'] != true) {
          await _fetchTopology();
          if (mounted) {
            setState(() => _scanning = false);
          }
          return;
        }
        await Future.delayed(const Duration(seconds: 2));
      }
      await _fetchTopology();
    } catch (_) {
      await _fetchTopology();
    } finally {
      if (mounted) {
        setState(() => _scanning = false);
      }
    }
  }

  void _layoutNodes(Map<String, dynamic> topo) {
    final nodes = (topo['nodes'] as List? ?? []).cast<Map<String, dynamic>>();
    final size = MediaQuery.of(context).size;
    final cx = size.width / 2;
    final cy = size.height / 2.2;

    _nodePositions['gateway'] = Offset(cx, cy - 180);
    _nodePositions['server'] = Offset(cx, cy);
    _nodePositions['honeypot'] = Offset(cx + 200, cy);

    final deviceNodes = nodes.where((n) => n['type'] == 'device').toList();
    final attackerNodes = nodes.where((n) => n['type'] == 'attacker').toList();

    for (int i = 0; i < deviceNodes.length; i++) {
      final angle =
          math.pi * (i / math.max(deviceNodes.length - 1, 1)) + math.pi;
      const radius = 220.0;
      final id = deviceNodes[i]['id'] as String;
      if (!_nodePositions.containsKey(id)) {
        _nodePositions[id] = Offset(
          cx + radius * math.cos(angle),
          cy + radius * math.sin(angle),
        );
      }
    }

    for (int i = 0; i < attackerNodes.length; i++) {
      final id = attackerNodes[i]['id'] as String;
      if (!_nodePositions.containsKey(id)) {
        _nodePositions[id] = Offset(
          cx + 300 + (i % 3) * 80.0,
          cy - 180 + (i ~/ 3) * 70.0,
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final ws = context.watch<WebSocketService>();
    final nodes =
        (_topology?['nodes'] as List? ?? []).cast<Map<String, dynamic>>();
    final deviceCount = nodes.where((n) => n['type'] == 'device').length;
    final attackerCount = nodes.where((n) => n['type'] == 'attacker').length;
    final blockedCount = nodes.where((n) => n['is_blocked'] == true).length;
    final selected = _selectedNodeId != null
        ? nodes.firstWhere((n) => n['id'] == _selectedNodeId, orElse: () => {})
        : null;

    return Scaffold(
      drawer: const AppShellDrawer(),
      appBar: AppBar(
        title: Text(
          'Network Topology',
          style: GoogleFonts.spaceGrotesk(fontWeight: FontWeight.w700),
        ),
        actions: [
          if (_scanning)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Center(
                child: SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: theme.colorScheme.primary,
                  ),
                ),
              ),
            )
          else
            TextButton.icon(
              icon:
                  Icon(Icons.radar, color: theme.colorScheme.primary, size: 18),
              label: Text(
                'Scan Network',
                style:
                    TextStyle(color: theme.colorScheme.primary, fontSize: 13),
              ),
              onPressed: _triggerScan,
            ),
          IconButton(
            icon: const Icon(Icons.center_focus_strong),
            onPressed: () {
              setState(() {
                _panOffset = Offset.zero;
                _lastPanStart = Offset.zero;
                _scale = 1.0;
              });
            },
            tooltip: 'Reset view',
          ),
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _fetchTopology,
            tooltip: 'Refresh topology',
          ),
        ],
      ),
      body: _loading
          ? Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  CircularProgressIndicator(color: theme.colorScheme.primary),
                  const SizedBox(height: 16),
                  Text(
                    'Building the latest network picture...',
                    style: TextStyle(
                      color: theme.colorScheme.onSurface.withOpacity(0.5),
                    ),
                  ),
                ],
              ),
            )
          : _error != null
              ? Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.error_outline,
                          color: Colors.red, size: 48),
                      const SizedBox(height: 12),
                      Text(_error!, style: const TextStyle(color: Colors.red)),
                      const SizedBox(height: 12),
                      ElevatedButton(
                          onPressed: _fetchTopology,
                          child: const Text('Retry')),
                    ],
                  ),
                )
              : Column(
                  children: [
                    Padding(
                      padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
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
                                  'Live network graph',
                                  style: GoogleFonts.spaceGrotesk(
                                    fontSize: 24,
                                    fontWeight: FontWeight.w700,
                                    color: theme.colorScheme.onSurface,
                                  ),
                                ),
                                const SizedBox(height: 6),
                                Text(
                                  ws.connected
                                      ? 'Realtime topology updates are active. New scans, device discoveries, and risk changes feed into this graph automatically.'
                                      : 'Realtime is offline. You can still scan and refresh manually, but new device activity will not stream in live.',
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
                                _summaryPill(theme, 'Devices', '$deviceCount'),
                                _summaryPill(
                                    theme, 'Attackers', '$attackerCount',
                                    color: Colors.red),
                                _summaryPill(theme, 'Blocked', '$blockedCount',
                                    color: Colors.orange),
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
                    Expanded(
                      child: Row(
                        children: [
                          Expanded(flex: 3, child: _buildCanvas(theme, isDark)),
                          if (MediaQuery.of(context).size.width > 800)
                            _buildSidebar(theme, isDark),
                        ],
                      ),
                    ),
                    if (MediaQuery.of(context).size.width <= 800)
                      Padding(
                        padding: const EdgeInsets.fromLTRB(16, 12, 16, 16),
                        child: selected != null && selected.isNotEmpty
                            ? _buildMobileInspector(theme, selected)
                            : GlassyContainer(
                                borderRadius: 18,
                                padding: const EdgeInsets.all(14),
                                child: Row(
                                  children: [
                                    Icon(Icons.touch_app_outlined,
                                        size: 18,
                                        color: theme.colorScheme.primary),
                                    const SizedBox(width: 10),
                                    Expanded(
                                      child: Text(
                                        'Tap a node to inspect risk, traffic, and trust status.',
                                        style: TextStyle(
                                          color: theme.colorScheme.onSurface
                                              .withOpacity(0.68),
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                      ),
                  ],
                ),
    );
  }

  Widget _buildCanvas(ThemeData theme, bool isDark) {
    final nodes =
        (_topology?['nodes'] as List? ?? []).cast<Map<String, dynamic>>();
    final edges =
        (_topology?['edges'] as List? ?? []).cast<Map<String, dynamic>>();

    return GestureDetector(
      onScaleStart: (d) {
        _lastPanStart = d.focalPoint - _panOffset;
      },
      onScaleUpdate: (d) {
        setState(() {
          _panOffset = d.focalPoint - _lastPanStart;
          _scale = (_scale * d.scale).clamp(0.4, 2.5);
        });
      },
      onTapUp: (d) {
        final localPos = (d.localPosition - _panOffset) / _scale;
        String? hit;
        for (final node in nodes) {
          final id = node['id'] as String;
          final pos = _nodePositions[id];
          if (pos != null) {
            if ((localPos - pos).distance < 36) {
              hit = id;
              break;
            }
          }
        }
        setState(() => _selectedNodeId = hit == _selectedNodeId ? null : hit);
      },
      child: Container(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: isDark
                ? const [
                    Color(0xFF08111E),
                    Color(0xFF0E1C30),
                    Color(0xFF08111E)
                  ]
                : const [
                    Color(0xFFF6FAFE),
                    Color(0xFFE9F2FB),
                    Color(0xFFF8FBFE)
                  ],
          ),
        ),
        child: ClipRect(
          child: CustomPaint(
            painter: _TopologyPainter(
              nodes: nodes,
              edges: edges,
              positions: _nodePositions,
              panOffset: _panOffset,
              scale: _scale,
              selectedNodeId: _selectedNodeId,
              theme: theme,
              isDark: isDark,
            ),
            child: const SizedBox.expand(),
          ),
        ),
      ),
    );
  }

  Widget _buildSidebar(ThemeData theme, bool isDark) {
    final nodes =
        (_topology?['nodes'] as List? ?? []).cast<Map<String, dynamic>>();
    final meta = _topology?['meta'] as Map<String, dynamic>? ?? {};
    final selected = _selectedNodeId != null
        ? nodes.firstWhere((n) => n['id'] == _selectedNodeId, orElse: () => {})
        : null;

    return Container(
      width: 280,
      padding: const EdgeInsets.fromLTRB(0, 0, 16, 16),
      child: GlassyContainer(
        borderRadius: 24,
        padding: const EdgeInsets.all(16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          // Legend
          Text('Legend',
              style: GoogleFonts.inter(
                  color: theme.colorScheme.onSurface.withOpacity(0.6),
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.2)),
          const SizedBox(height: 8),
          ..._legends(theme),
          Divider(color: theme.dividerColor.withOpacity(0.2), height: 24),

          // Network info
          Text('Network',
              style: GoogleFonts.inter(
                  color: theme.colorScheme.onSurface.withOpacity(0.6),
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.2)),
          const SizedBox(height: 8),
          _infoRow('Gateway', meta['gateway_ip'] ?? '—', theme),
          _infoRow('Server IP', meta['local_ip'] ?? '—', theme),
          _infoRow('Last scan', _shortTime(meta['last_scan']), theme),
          _infoRow('Devices',
              '${nodes.where((n) => n['type'] == 'device').length}', theme),
          _infoRow('Attackers',
              '${nodes.where((n) => n['type'] == 'attacker').length}', theme),
          Divider(color: theme.dividerColor.withOpacity(0.2), height: 24),

          // Selected node detail
          if (selected != null && selected.isNotEmpty) ...[
            Text('Selected Node',
                style: GoogleFonts.inter(
                    color: theme.colorScheme.onSurface.withOpacity(0.6),
                    fontSize: 11,
                    fontWeight: FontWeight.w600,
                    letterSpacing: 1.2)),
            const SizedBox(height: 8),
            _nodeDetailCard(selected, theme),
          ] else
            Text('Tap a node for details',
                style: TextStyle(
                    color: theme.colorScheme.onSurface.withOpacity(0.4),
                    fontSize: 12)),

          const Spacer(),
          // Device count summary
          GlassyContainer(
            padding: const EdgeInsets.all(12),
            borderRadius: 10,
            color: theme.colorScheme.primary.withOpacity(isDark ? 0.08 : 0.15),
            child: Row(children: [
              Icon(Icons.devices, color: theme.colorScheme.primary, size: 18),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  '${nodes.where((n) => n['type'] == 'device').length} devices on network',
                  style: TextStyle(
                      color: theme.colorScheme.primary,
                      fontSize: 12,
                      fontWeight: FontWeight.w600),
                ),
              ),
            ]),
          ),
        ]),
      ),
    );
  }

  List<Widget> _legends(ThemeData theme) => [
        _legendItem(Colors.blue.shade300, 'Gateway/Router', theme),
        _legendItem(theme.colorScheme.primary, 'NTTH Server', theme),
        _legendItem(Colors.purple.shade300, 'Device (trusted)', theme),
        _legendItem(Colors.orange, 'Device (unknown)', theme),
        _legendItem(Colors.red, 'Device (high-risk/blocked)', theme),
        _legendItem(Colors.amber, 'Honeypot', theme),
        _legendItem(Colors.red.shade800, 'External Attacker', theme),
      ];

  Widget _legendItem(Color color, String label, ThemeData theme) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(children: [
          Container(
              width: 12,
              height: 12,
              decoration: BoxDecoration(shape: BoxShape.circle, color: color)),
          const SizedBox(width: 8),
          Text(label,
              style: TextStyle(
                  color: theme.colorScheme.onSurface.withOpacity(0.8),
                  fontSize: 11)),
        ]),
      );

  Widget _nodeDetailCard(Map<String, dynamic> node, ThemeData theme) {
    final type = node['type'] as String? ?? '';
    final live = node['live'] as Map<String, dynamic>? ?? {};
    final riskScore = (node['risk_score'] as num? ?? 0).toDouble();
    final riskColor = riskScore > 0.85
        ? Colors.red
        : riskScore > 0.5
            ? Colors.orange
            : theme.colorScheme.primary;

    return GlassyContainer(
      padding: const EdgeInsets.all(12),
      borderRadius: 10,
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        _infoRow('IP', node['ip']?.toString() ?? '-', theme),
        if (node['hostname'] != null)
          _infoRow('Host', node['hostname'].toString(), theme),
        if (node['mac'] != null) _infoRow('MAC', node['mac'].toString(), theme),
        if (node['vendor'] != null)
          _infoRow('Vendor', node['vendor'].toString(), theme),
        if (node['country'] != null)
          _infoRow('Country', node['country'].toString(), theme),
        _infoRow('Type', type, theme),
        if (type == 'device') ...[
          _infoRow('Trusted', node['is_trusted'] == true ? 'Yes' : 'No', theme),
          _infoRow('Blocked', node['is_blocked'] == true ? 'Yes' : 'No', theme),
          const SizedBox(height: 6),
          Text('Risk Score',
              style: TextStyle(
                  color: theme.colorScheme.onSurface.withOpacity(0.5),
                  fontSize: 11)),
          const SizedBox(height: 4),
          ClipRRect(
            borderRadius: BorderRadius.circular(3),
            child: LinearProgressIndicator(
              value: riskScore,
              backgroundColor: theme.dividerColor.withOpacity(0.1),
              color: riskColor,
              minHeight: 6,
            ),
          ),
          Text('${(riskScore * 100).toInt()}%',
              style: TextStyle(
                  color: riskColor, fontSize: 11, fontWeight: FontWeight.w700)),
        ],
        if (type == 'honeypot') ...[
          _infoRow('Active Sessions', '${node['active_sessions'] ?? 0}', theme),
          _infoRow('Total Sessions', '${node['total_sessions'] ?? 0}', theme),
        ],
        if (live.isNotEmpty) ...[
          Divider(color: theme.dividerColor.withOpacity(0.2), height: 16),
          Text('Live Traffic',
              style: TextStyle(
                  color: theme.colorScheme.onSurface.withOpacity(0.5),
                  fontSize: 11)),
          _infoRow('Packets', '${live['packets'] ?? 0}', theme),
          _infoRow(
              'Bytes in', _humanBytes(live['bytes_in'] as int? ?? 0), theme),
          _infoRow('Unique ports', '${live['unique_ports'] ?? 0}', theme),
        ],
      ]),
    );
  }

  Widget _infoRow(String label, String value, ThemeData theme) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 2),
        child: Row(children: [
          SizedBox(
            width: 80,
            child: Text(label,
                style: TextStyle(
                    color: theme.colorScheme.onSurface.withOpacity(0.5),
                    fontSize: 11)),
          ),
          Expanded(
            child: Text(value,
                style:
                    TextStyle(color: theme.colorScheme.onSurface, fontSize: 11),
                overflow: TextOverflow.ellipsis),
          ),
        ]),
      );

  String _shortTime(dynamic iso) {
    if (iso == null) return 'Never';
    try {
      return timeago.format(DateTime.parse(iso.toString()).toLocal());
    } catch (_) {
      return '-';
    }
  }

  String _humanBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }

  Widget _buildMobileInspector(ThemeData theme, Map<String, dynamic> selected) {
    return GlassyContainer(
      borderRadius: 20,
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Selected node',
            style: GoogleFonts.spaceGrotesk(
              fontWeight: FontWeight.w700,
              color: theme.colorScheme.onSurface,
            ),
          ),
          const SizedBox(height: 10),
          _nodeDetailCard(selected, theme),
        ],
      ),
    );
  }

  Widget _summaryPill(ThemeData theme, String label, String value,
      {Color? color}) {
    final tone = color ?? theme.colorScheme.primary;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: tone.withOpacity(0.10),
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
              color: tone,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }
}

// ── Canvas painter ────────────────────────────────────────────────────────────

class _TopologyPainter extends CustomPainter {
  final List<Map<String, dynamic>> nodes;
  final List<Map<String, dynamic>> edges;
  final Map<String, Offset> positions;
  final Offset panOffset;
  final double scale;
  final String? selectedNodeId;
  final ThemeData theme;
  final bool isDark;

  _TopologyPainter({
    required this.nodes,
    required this.edges,
    required this.positions,
    required this.panOffset,
    required this.scale,
    this.selectedNodeId,
    required this.theme,
    required this.isDark,
  });

  Color _nodeColor(Map<String, dynamic> node) {
    final type = node['type'] as String? ?? '';
    switch (type) {
      case 'gateway':
        return Colors.blue.shade300;
      case 'server':
        return theme.colorScheme.primary;
      case 'honeypot':
        return Colors.amber;
      case 'attacker':
        return Colors.red.shade800;
      case 'device':
        if (node['is_blocked'] == true) return Colors.red;
        final rs = (node['risk_score'] as num? ?? 0).toDouble();
        if (rs > 0.85) return Colors.red;
        if (rs > 0.5) return Colors.orange;
        if (node['is_trusted'] == true) return Colors.purple.shade300;
        return isDark ? Colors.blueGrey : Colors.blueGrey.shade300;
      default:
        return theme.colorScheme.onSurface.withOpacity(0.4);
    }
  }

  @override
  void paint(Canvas canvas, Size size) {
    canvas.save();
    canvas.translate(panOffset.dx, panOffset.dy);
    canvas.scale(scale);

    // Draw grid
    _drawGrid(canvas, size);

    // Draw edges first (behind nodes)
    for (final edge in edges) {
      final fromId = edge['from'] as String?;
      final toId = edge['to'] as String?;
      if (fromId == null || toId == null) continue;
      final fromPos = positions[fromId];
      final toPos = positions[toId];
      if (fromPos == null || toPos == null) continue;

      final isAttack = edge['type'] == 'attack';
      final isRedirected = edge['type'] == 'redirected';
      final rs = (edge['risk_score'] as num? ?? 0).toDouble();
      final edgeColor = isAttack
          ? Colors.red.withOpacity(0.7)
          : isRedirected
              ? Colors.orange.withOpacity(0.6)
              : rs > 0.5
                  ? Colors.orange.withOpacity(0.5)
                  : theme.dividerColor.withOpacity(0.3);

      final paint = Paint()
        ..color = edgeColor
        ..strokeWidth = isAttack ? 2.0 : 1.2
        ..style = PaintingStyle.stroke;

      if (isAttack || isRedirected) {
        _drawDashedLine(canvas, fromPos, toPos, paint);
      } else {
        canvas.drawLine(fromPos, toPos, paint);
      }
    }

    // Draw nodes
    for (final node in nodes) {
      final id = node['id'] as String;
      final pos = positions[id];
      if (pos == null) continue;
      _drawNode(canvas, node, pos, id == selectedNodeId);
    }

    canvas.restore();
  }

  void _drawGrid(Canvas canvas, Size size) {
    final gridPaint = Paint()
      ..color = theme.dividerColor.withOpacity(isDark ? 0.1 : 0.05)
      ..strokeWidth = 1;
    const step = 50.0;
    final w = size.width / scale;
    final h = size.height / scale;
    for (double x = -panOffset.dx / scale % step - step;
        x < w + step;
        x += step) {
      canvas.drawLine(Offset(x, -panOffset.dy / scale - step),
          Offset(x, h + step), gridPaint);
    }
    for (double y = -panOffset.dy / scale % step - step;
        y < h + step;
        y += step) {
      canvas.drawLine(Offset(-panOffset.dx / scale - step, y),
          Offset(w + step, y), gridPaint);
    }
  }

  void _drawNode(
      Canvas canvas, Map<String, dynamic> node, Offset pos, bool selected) {
    final type = node['type'] as String? ?? '';
    final color = _nodeColor(node);
    final radius = type == 'gateway'
        ? 32.0
        : type == 'server'
            ? 28.0
            : type == 'honeypot'
                ? 26.0
                : 22.0;

    // Glow effect for selected + high-risk
    if (selected ||
        (node['risk_score'] as num? ?? 0) > 0.85 ||
        type == 'attacker') {
      final glowPaint = Paint()
        ..color = color.withOpacity(0.2)
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 16);
      canvas.drawCircle(pos, radius + 12, glowPaint);
    }

    // Selection ring
    if (selected) {
      canvas.drawCircle(
          pos,
          radius + 6,
          Paint()
            ..color = theme.colorScheme.onSurface.withOpacity(0.6)
            ..style = PaintingStyle.stroke
            ..strokeWidth = 2);
    }

    // Node fill
    canvas.drawCircle(
        pos,
        radius,
        Paint()
          ..color = theme.scaffoldBackgroundColor
          ..style = PaintingStyle.fill);
    canvas.drawCircle(
        pos,
        radius,
        Paint()
          ..color = color.withOpacity(0.15)
          ..style = PaintingStyle.fill);
    canvas.drawCircle(
        pos,
        radius,
        Paint()
          ..color = color
          ..style = PaintingStyle.stroke
          ..strokeWidth = 2.0);

    // Inner circle
    if (type == 'honeypot' || type == 'server') {
      canvas.drawCircle(
          pos,
          radius * 0.55,
          Paint()
            ..color = color.withOpacity(0.3)
            ..style = PaintingStyle.fill);
    }

    // Live traffic indicator
    final live = node['live'] as Map<String, dynamic>? ?? {};
    final packets = live['packets'] as int? ?? 0;
    if (packets > 0) {
      canvas.drawCircle(
          pos,
          radius + 4,
          Paint()
            ..color = theme.colorScheme.primary.withOpacity(0.4)
            ..style = PaintingStyle.stroke
            ..strokeWidth = 1.5);
    }

    // Label below
    final labelText = node['label']?.toString() ??
        node['ip']?.toString() ??
        node['id']?.toString() ??
        '';
    final short =
        labelText.length > 16 ? labelText.substring(0, 16) : labelText;
    final tp = TextPainter(
      text: TextSpan(
        text: short,
        style: TextStyle(
          color: selected
              ? theme.colorScheme.onSurface
              : theme.colorScheme.onSurface.withOpacity(0.7),
          fontSize: 9.5,
          fontWeight: selected ? FontWeight.w700 : FontWeight.w500,
        ),
      ),
      textDirection: ui.TextDirection.ltr,
    )..layout(maxWidth: 100);
    tp.paint(canvas, pos.translate(-tp.width / 2, radius + 4));

    // Vendor/type sub-label
    final sub = node['vendor']?.toString() ?? type;
    if (sub.isNotEmpty) {
      final tp2 = TextPainter(
        text: TextSpan(
            text: sub,
            style: TextStyle(color: color.withOpacity(0.8), fontSize: 8)),
        textDirection: ui.TextDirection.ltr,
      )..layout(maxWidth: 100);
      tp2.paint(canvas, pos.translate(-tp2.width / 2, radius + 16));
    }
  }

  void _drawDashedLine(Canvas canvas, Offset from, Offset to, Paint paint) {
    const dashLen = 8.0;
    const gapLen = 5.0;
    final dx = to.dx - from.dx;
    final dy = to.dy - from.dy;
    final dist = math.sqrt(dx * dx + dy * dy);
    final ux = dx / dist;
    final uy = dy / dist;
    double drawn = 0;
    bool drawing = true;
    while (drawn < dist) {
      final segLen = drawing ? dashLen : gapLen;
      final end = math.min(drawn + segLen, dist);
      if (drawing) {
        canvas.drawLine(
          Offset(from.dx + ux * drawn, from.dy + uy * drawn),
          Offset(from.dx + ux * end, from.dy + uy * end),
          paint,
        );
      }
      drawn = end;
      drawing = !drawing;
    }
  }

  @override
  bool shouldRepaint(covariant _TopologyPainter oldDelegate) =>
      oldDelegate.nodes != nodes ||
      oldDelegate.positions != positions ||
      oldDelegate.panOffset != panOffset ||
      oldDelegate.scale != scale ||
      oldDelegate.selectedNodeId != selectedNodeId ||
      oldDelegate.theme != theme ||
      oldDelegate.isDark != isDark;
}
