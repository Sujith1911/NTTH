import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../core/auth_service.dart';
import '../core/websocket_service.dart';
import '../widgets/app_shell_drawer.dart';
import '../widgets/glassy_container.dart';

class SystemHealthScreen extends StatefulWidget {
  const SystemHealthScreen({super.key});

  @override
  State<SystemHealthScreen> createState() => _SystemHealthScreenState();
}

class _SystemHealthScreenState extends State<SystemHealthScreen> {
  Map<String, dynamic>? _health;
  List<Map<String, dynamic>> _agents = [];
  bool _loading = true;
  DateTime? _lastCheckedAt;

  @override
  void initState() {
    super.initState();
    _fetch();
  }

  Future<void> _fetch() async {
    setState(() => _loading = true);
    try {
      final api = context.read<AuthService>().api;
      final responses = await Future.wait([
        api.get('/system/health'),
        api.get('/system/agents'),
      ]);
      setState(() {
        _health = responses[0].data as Map<String, dynamic>;
        _agents = ((responses[1].data as Map<String, dynamic>)['items'] as List)
            .cast<Map<String, dynamic>>();
        _loading = false;
        _lastCheckedAt = DateTime.now();
      });
    } catch (_) {
      setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final ws = context.watch<WebSocketService>();

    return Scaffold(
      drawer: const AppShellDrawer(),
      appBar: AppBar(
        title: const Text('System Health'),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetch)
        ],
      ),
      body: _loading
          ? Center(
              child:
                  CircularProgressIndicator(color: theme.colorScheme.primary))
          : _health == null
              ? const Center(
                  child: Text('Could not reach the backend',
                      style: TextStyle(color: Colors.red)))
              : SingleChildScrollView(
                  padding: const EdgeInsets.all(24),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _statusBanner(_health!, theme),
                      const SizedBox(height: 24),
                      _operationsSummary(_health!, theme),
                      const SizedBox(height: 24),
                      Text(
                        'Component Status',
                        style: GoogleFonts.inter(
                          fontSize: 16,
                          fontWeight: FontWeight.w600,
                          color: theme.colorScheme.onSurface,
                        ),
                      ),
                      const SizedBox(height: 16),
                      _statusGrid(_health!, theme, ws),
                      const SizedBox(height: 32),
                      Text(
                        'Security Agents',
                        style: GoogleFonts.inter(
                          fontSize: 16,
                          fontWeight: FontWeight.w600,
                          color: theme.colorScheme.onSurface,
                        ),
                      ),
                      const SizedBox(height: 12),
                      _agentsGrid(theme),
                      const SizedBox(height: 32),
                      Text(
                        'Diagnostics',
                        style: GoogleFonts.inter(
                          fontSize: 16,
                          fontWeight: FontWeight.w600,
                          color: theme.colorScheme.onSurface,
                        ),
                      ),
                      const SizedBox(height: 12),
                      _infoCard([
                        ('Version', _health!['version'] ?? '?'),
                        ('Environment', _health!['environment'] ?? '?'),
                        (
                          'Realtime mode',
                          _health!['realtime_mode']?.toString() ?? 'unknown'
                        ),
                        (
                          'Firewall mode',
                          _health!['firewall_mode']?.toString() ?? 'unknown'
                        ),
                        (
                          'Capture iface',
                          _health!['capture_interface']?.toString() ?? '?'
                        ),
                        (
                          'Capture IP',
                          _health!['capture_ip']?.toString() ?? 'Unavailable'
                        ),
                        (
                          'Scan subnet',
                          _health!['scan_subnet']?.toString() ?? 'Unavailable'
                        ),
                        (
                          'Discovered devices',
                          '${_health!['discovered_devices'] ?? 0}'
                        ),
                        (
                          'Agents',
                          '${_health!['security_agents_active'] ?? 0}/${_health!['security_agents_total'] ?? 0} active'
                        ),
                        (
                          'Last scan',
                          _health!['last_scan']?.toString() ?? 'Never'
                        ),
                        ('WS Clients', '${_health!['websocket_clients'] ?? 0}'),
                        (
                          'Event Backlog',
                          '${_health!['event_bus_backlog'] ?? 0}'
                        ),
                        (
                          'Event Handlers',
                          '${_health!['event_bus_subscribers'] ?? 0}'
                        ),
                        (
                          'Last checked',
                          _lastCheckedAt == null
                              ? 'Never'
                              : timeago.format(_lastCheckedAt!)
                        ),
                      ], theme),
                    ],
                  ),
                ),
    );
  }

  Widget _statusBanner(Map h, ThemeData theme) {
    final ok = h['status'] == 'ok';
    final isDark = theme.brightness == Brightness.dark;
    final color = ok ? theme.colorScheme.primary : Colors.red;
    final degradedReason = h['packet_capture_reason']?.toString() ??
        h['firewall_reason']?.toString();

    return GlassyContainer(
      padding: const EdgeInsets.all(20),
      borderRadius: 16,
      color: color.withOpacity(isDark ? 0.1 : 0.05),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Icon(ok ? Icons.check_circle : Icons.error, color: color, size: 40),
        const SizedBox(width: 20),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(
              ok ? 'Security pipeline is healthy' : 'Security pipeline is running with limits',
              style: GoogleFonts.inter(
                fontSize: 18,
                fontWeight: FontWeight.w700,
                color: theme.colorScheme.onSurface,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              ok
                  ? 'Detection, analysis, containment, and reporting are online.'
                  : degradedReason ?? 'Check the summaries below.',
              style: TextStyle(
                color: theme.colorScheme.onSurface.withOpacity(0.6),
                fontSize: 13,
                height: 1.5,
              ),
            ),
          ]),
        ),
      ]),
    );
  }

  Widget _operationsSummary(Map h, ThemeData theme) {
    final items = [
      (
        'Detection',
        h['realtime_mode'] == 'scan_fallback'
            ? 'Scan-based detection active'
            : 'Packet capture active'
      ),
      (
        'Firewall',
        h['firewall_mode'] == 'enforcing'
            ? 'Containment enforcing'
            : h['firewall_mode'] == 'simulation'
                ? 'Containment simulation'
                : 'Containment degraded'
      ),
      ('Honeypot', h['honeypot_ready'] == true ? 'Ready for diversion' : 'Needs attention'),
    ];
    return GlassyContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(16),
      child: Wrap(
        spacing: 12,
        runSpacing: 12,
        children: items
            .map(
              (item) => Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                decoration: BoxDecoration(
                  color: theme.colorScheme.primary.withOpacity(0.08),
                  borderRadius: BorderRadius.circular(999),
                ),
                child: Text(
                  '${item.$1}: ${item.$2}',
                  style: TextStyle(
                    color: theme.colorScheme.onSurface.withOpacity(0.76),
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            )
            .toList(),
      ),
    );
  }

  Widget _statusGrid(Map h, ThemeData theme, WebSocketService ws) {
    final components = [
      ('Database', h['db_ok'] == true),
      ('Packet Sniffer', h['sniffer_running'] == true),
      ('Scheduler', h['scheduler_running'] == true),
      ('Client WebSocket', ws.connected),
      ('Backend WebSocket', (h['websocket_clients'] as num? ?? 0) > 0),
      ('Honeypot', h['honeypot_ready'] == true),
    ];
    final w = MediaQuery.of(context).size.width;
    final crossAxisCount = w > 800
        ? 3
        : w > 500
            ? 2
            : 1;
    final aspect = w > 800 ? 2.0 : 3.0;

    return GridView.count(
      crossAxisCount: crossAxisCount,
      shrinkWrap: true,
      mainAxisSpacing: 12,
      crossAxisSpacing: 12,
      childAspectRatio: aspect,
      physics: const NeverScrollableScrollPhysics(),
      children:
          components.map((c) => _componentCard(c.$1, c.$2, theme, h)).toList(),
    );
  }

  Widget _componentCard(String name, bool ok, ThemeData theme, Map h) {
    final color = ok ? theme.colorScheme.primary : Colors.red;
    final detail = switch (name) {
      'Packet Sniffer' => ok
          ? 'Live packet capture is available.'
          : (h['packet_capture_reason']?.toString() ??
              'The app is relying on scheduled and manual scans.'),
      'Honeypot' => ok
          ? 'Deception service is ready to accept redirected traffic.'
          : 'The honeypot is not currently ready to receive attacker sessions.',
      'Backend WebSocket' => ok
          ? 'At least one UI session is connected to live updates.'
          : 'No dashboard client is attached to the live event stream.',
      _ => ok ? 'Operating normally.' : 'Needs attention.',
    };
    return GlassyContainer(
      padding: const EdgeInsets.all(16),
      borderRadius: 12,
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(ok ? Icons.check_circle_outline : Icons.cancel_outlined,
              color: color, size: 24),
          const SizedBox(height: 8),
          Text(
            name,
            style: TextStyle(
              color: theme.colorScheme.onSurface.withOpacity(0.9),
              fontSize: 13,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            detail,
            style: TextStyle(
              color: theme.colorScheme.onSurface.withOpacity(0.55),
              fontSize: 11,
              height: 1.35,
            ),
          ),
        ],
      ),
    );
  }

  Widget _agentsGrid(ThemeData theme) {
    final w = MediaQuery.of(context).size.width;
    final crossAxisCount = w > 900 ? 3 : w > 560 ? 2 : 1;
    return GridView.count(
      crossAxisCount: crossAxisCount,
      shrinkWrap: true,
      mainAxisSpacing: 12,
      crossAxisSpacing: 12,
      childAspectRatio: w > 900 ? 2.4 : 2.8,
      physics: const NeverScrollableScrollPhysics(),
      children: _agents
          .map(
            (agent) => GlassyContainer(
              padding: const EdgeInsets.all(16),
              borderRadius: 14,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    agent['name']?.toString() ?? 'Agent',
                    style: TextStyle(
                      color: theme.colorScheme.onSurface,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    agent['status']?.toString() ?? 'unknown',
                    style: TextStyle(
                      color: (agent['status'] == 'active'
                              ? theme.colorScheme.primary
                              : Colors.orange)
                          .withOpacity(0.95),
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    agent['summary']?.toString() ?? '',
                    style: TextStyle(
                      color: theme.colorScheme.onSurface.withOpacity(0.62),
                      height: 1.4,
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
            ),
          )
          .toList(),
    );
  }

  Widget _infoCard(List<(String, String)> items, ThemeData theme) {
    return GlassyContainer(
      padding: const EdgeInsets.all(16),
      borderRadius: 12,
      child: Column(
        children: items
            .map((i) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                  child: Row(children: [
                    SizedBox(
                      width: 120,
                      child: Text(
                        i.$1,
                        style: TextStyle(
                          color: theme.colorScheme.onSurface.withOpacity(0.5),
                          fontSize: 13,
                        ),
                      ),
                    ),
                    Expanded(
                      child: Text(
                        i.$2,
                        style: TextStyle(
                          color: theme.colorScheme.onSurface,
                          fontSize: 13,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ),
                  ]),
                ))
            .toList(),
      ),
    );
  }
}
