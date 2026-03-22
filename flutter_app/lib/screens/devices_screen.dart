import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../core/auth_service.dart';
import '../core/websocket_service.dart';
import '../models/device_model.dart';
import '../widgets/app_shell_drawer.dart';
import '../widgets/device_tile.dart';
import '../widgets/glassy_container.dart';

class DevicesScreen extends StatefulWidget {
  const DevicesScreen({super.key});

  @override
  State<DevicesScreen> createState() => _DevicesScreenState();
}

class _DevicesScreenState extends State<DevicesScreen> {
  List<DeviceModel> _devices = [];
  bool _loading = true;
  String? _error;
  final int _page = 1;
  int _total = 0;
  VoidCallback? _wsListener;
  DateTime? _lastSyncedAt;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _fetchDevices();
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

  Future<void> _fetchDevices() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final api = context.read<AuthService>().api;
      final resp =
          await api.get('/devices', params: {'page': _page, 'page_size': 50});
      final data = resp.data as Map<String, dynamic>;
      setState(() {
        _devices = (data['items'] as List)
            .map((j) => DeviceModel.fromJson(j))
            .toList();
        _total = data['total'];
        _loading = false;
        _lastSyncedAt = DateTime.now();
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  Future<void> _toggleTrust(DeviceModel device) async {
    final isAdmin = context.read<AuthService>().isAdmin;
    if (!isAdmin) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
            content: Text('Admin access required'),
            backgroundColor: Colors.red),
      );
      return;
    }
    try {
      final api = context.read<AuthService>().api;
      await api.put(
          '/devices/${device.id}/trust', {'is_trusted': !device.isTrusted});
      _fetchDevices();
      if (!mounted) return;
      final theme = Theme.of(context);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content:
              Text(device.isTrusted ? 'Device untrusted' : 'Device trusted'),
          backgroundColor: theme.colorScheme.primary,
          action: SnackBarAction(
              label: 'OK', textColor: Colors.black, onPressed: () {}),
        ),
      );
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Error: $e'), backgroundColor: Colors.red),
      );
    }
  }

  Future<void> _triggerScan() async {
    final messenger = ScaffoldMessenger.of(context);
    final theme = Theme.of(context);
    try {
      await context.read<AuthService>().api.post('/network/scan', {});
      if (!mounted) return;
      messenger.showSnackBar(
        SnackBar(
          content: const Text(
            'Network scan started. Devices will refresh as the backend publishes updates.',
          ),
          backgroundColor: theme.colorScheme.primary,
        ),
      );
    } catch (error) {
      if (!mounted) return;
      messenger.showSnackBar(
        SnackBar(
          content: Text('Could not start scan: $error'),
          backgroundColor: Colors.red,
        ),
      );
    }
  }

  void _listenToWs() {
    final ws = context.read<WebSocketService>();
    _wsListener ??= () {
      if (!mounted || ws.events.isEmpty) return;
      final latest = ws.events.first;
      final type = latest['type']?.toString();
      if (type == 'device_updated') {
        final ip = latest['ip']?.toString();
        if (ip == null) return;
        final index = _devices.indexWhere((device) => device.ipAddress == ip);
        if (index >= 0) {
          final updated = _devices[index].copyWith(
            riskScore: (latest['risk_score'] as num?)?.toDouble() ??
                _devices[index].riskScore,
            lastSeen: DateTime.now(),
          );
          setState(() {
            _devices[index] = updated;
            _devices.sort((a, b) => b.riskScore.compareTo(a.riskScore));
          });
          return;
        }
        if (!_loading) _fetchDevices();
        return;
      }
      if (type == 'device_seen') {
        final ip = latest['ip']?.toString();
        if (ip == null) return;
        if (_devices.any((device) => device.ipAddress == ip)) {
          return;
        }
        if (!_loading) _fetchDevices();
        return;
      }
      if (type == 'topology_updated' && !_loading) {
        _fetchDevices();
      }
    };
    ws.addListener(_wsListener!);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final ws = context.watch<WebSocketService>();
    final highRiskCount =
        _devices.where((device) => device.riskScore >= 0.85).length;
    return Scaffold(
      drawer: const AppShellDrawer(),
      appBar: AppBar(
        title: Text('Devices ($_total total)'),
        actions: [
          IconButton(
            icon: const Icon(Icons.radar_outlined),
            tooltip: 'Run network scan',
            onPressed: _triggerScan,
          ),
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchDevices),
        ],
      ),
      body: _loading
          ? Center(
              child:
                  CircularProgressIndicator(color: theme.colorScheme.primary))
          : _error != null
              ? Center(
                  child: Column(mainAxisSize: MainAxisSize.min, children: [
                    Text(_error!, style: const TextStyle(color: Colors.red)),
                    const SizedBox(height: 12),
                    ElevatedButton(
                        onPressed: _fetchDevices, child: const Text('Retry')),
                  ]),
                )
              : RefreshIndicator(
                  onRefresh: _fetchDevices,
                  child: ListView(
                    padding: const EdgeInsets.all(16),
                    children: [
                      GlassyContainer(
                        borderRadius: 26,
                        padding: const EdgeInsets.all(20),
                        child: Wrap(
                          alignment: WrapAlignment.spaceBetween,
                          runSpacing: 14,
                          spacing: 14,
                          children: [
                            Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  'Device posture',
                                  style: GoogleFonts.spaceGrotesk(
                                    fontSize: 24,
                                    fontWeight: FontWeight.w700,
                                    color: theme.colorScheme.onSurface,
                                  ),
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  ws.connected
                                      ? 'Live updates are flowing. Device risk changes will appear here as threats are scored.'
                                      : 'Realtime is offline right now. Pull to refresh or reconnect from the dashboard/settings.',
                                  style: TextStyle(
                                    color: theme.colorScheme.onSurface
                                        .withOpacity(0.65),
                                    height: 1.5,
                                  ),
                                ),
                              ],
                            ),
                            Wrap(
                              spacing: 10,
                              runSpacing: 10,
                              children: [
                                _statPill(theme, 'Tracked', '$_total'),
                                _statPill(theme, 'High risk', '$highRiskCount',
                                    danger: highRiskCount > 0),
                                _statPill(
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
                      const SizedBox(height: 16),
                      if (_devices.isEmpty)
                        Padding(
                          padding: const EdgeInsets.only(top: 48),
                          child:
                              Column(mainAxisSize: MainAxisSize.min, children: [
                            Icon(Icons.devices_outlined,
                                color: theme.iconTheme.color?.withOpacity(0.3),
                                size: 64),
                            const SizedBox(height: 12),
                            Text('No devices discovered yet',
                                style: TextStyle(
                                    color: theme.colorScheme.onSurface
                                        .withOpacity(0.5))),
                            const SizedBox(height: 4),
                            Text(
                                'Run a network scan to populate devices in realtime',
                                style: TextStyle(
                                    color: theme.colorScheme.onSurface
                                        .withOpacity(0.3),
                                    fontSize: 12)),
                            const SizedBox(height: 16),
                            ElevatedButton.icon(
                              onPressed: _triggerScan,
                              icon: const Icon(Icons.radar_outlined),
                              label: const Text('Run scan'),
                            ),
                          ]),
                        )
                      else
                        ...List.generate(
                          _devices.length,
                          (i) => Padding(
                            padding: EdgeInsets.only(
                                bottom: i == _devices.length - 1 ? 0 : 8),
                            child: DeviceTile(
                              device: _devices[i],
                              onToggleTrust: () => _toggleTrust(_devices[i]),
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
    );
  }

  Widget _statPill(ThemeData theme, String label, String value,
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
