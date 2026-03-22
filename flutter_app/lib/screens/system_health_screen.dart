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
      final resp = await api.get('/system/health');
      setState(() {
        _health = resp.data as Map<String, dynamic>;
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
                  child: Text('Could not reach backend',
                      style: TextStyle(color: Colors.red)))
              : SingleChildScrollView(
                  padding: const EdgeInsets.all(24),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _statusBanner(_health!, theme),
                      const SizedBox(height: 24),
                      Text('Component Status',
                          style: GoogleFonts.inter(
                              fontSize: 16,
                              fontWeight: FontWeight.w600,
                              color: theme.colorScheme.onSurface)),
                      const SizedBox(height: 16),
                      _statusGrid(_health!, theme, ws),
                      const SizedBox(height: 32),
                      Text('Build Info',
                          style: GoogleFonts.inter(
                              fontSize: 16,
                              fontWeight: FontWeight.w600,
                              color: theme.colorScheme.onSurface)),
                      const SizedBox(height: 12),
                      _infoCard([
                        ('Version', _health!['version'] ?? '?'),
                        ('Environment', _health!['environment'] ?? '?'),
                        (
                          'Realtime mode',
                          _health!['realtime_mode']?.toString() ?? 'unknown'
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
    final degradedReason = h['packet_capture_reason']?.toString();

    return GlassyContainer(
      padding: const EdgeInsets.all(20),
      borderRadius: 16,
      color: color.withOpacity(isDark ? 0.1 : 0.05),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Icon(ok ? Icons.check_circle : Icons.error, color: color, size: 40),
        const SizedBox(width: 20),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(ok ? 'All Systems Operational' : 'System Degraded',
                style: GoogleFonts.inter(
                    fontSize: 18,
                    fontWeight: FontWeight.w700,
                    color: theme.colorScheme.onSurface)),
            const SizedBox(height: 4),
            Text(
              ok
                  ? 'Backend running normally'
                  : degradedReason ?? 'Check component status below',
              style: TextStyle(
                  color: theme.colorScheme.onSurface.withOpacity(0.6),
                  fontSize: 13,
                  height: 1.5),
            ),
          ]),
        ),
      ]),
    );
  }

  Widget _statusGrid(Map h, ThemeData theme, WebSocketService ws) {
    final components = [
      ('Database', h['db_ok'] == true),
      ('Packet Sniffer', h['sniffer_running'] == true),
      ('Scheduler', h['scheduler_running'] == true),
      ('Client WebSocket', ws.connected),
      ('Backend WebSocket', (h['websocket_clients'] as num? ?? 0) > 0),
    ];
    // Responsive grid
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
          components.map((c) => _componentCard(c.$1, c.$2, theme)).toList(),
    );
  }

  Widget _componentCard(String name, bool ok, ThemeData theme) {
    final color = ok ? theme.colorScheme.primary : Colors.red;
    return GlassyContainer(
      padding: const EdgeInsets.all(16),
      borderRadius: 12,
      child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
        Icon(ok ? Icons.check_circle_outline : Icons.cancel_outlined,
            color: color, size: 24),
        const SizedBox(height: 8),
        Text(name,
            style: TextStyle(
                color: theme.colorScheme.onSurface.withOpacity(0.9),
                fontSize: 13,
                fontWeight: FontWeight.w600)),
      ]),
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
                        child: Text(i.$1,
                            style: TextStyle(
                                color: theme.colorScheme.onSurface
                                    .withOpacity(0.5),
                                fontSize: 13))),
                    Text(i.$2,
                        style: TextStyle(
                            color: theme.colorScheme.onSurface,
                            fontSize: 13,
                            fontWeight: FontWeight.w500)),
                  ]),
                ))
            .toList(),
      ),
    );
  }
}
