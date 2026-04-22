import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../core/auth_service.dart';
import '../core/websocket_service.dart';
import '../widgets/app_shell_drawer.dart';
import '../widgets/glassy_container.dart';

/// Wireless monitoring screen — shows AR9271 adapter status,
/// tracked WiFi devices, probe requests, access points, and threats.
class WirelessScreen extends StatefulWidget {
  const WirelessScreen({super.key});

  @override
  State<WirelessScreen> createState() => _WirelessScreenState();
}

class _WirelessScreenState extends State<WirelessScreen>
    with SingleTickerProviderStateMixin {
  Map<String, dynamic>? _status;
  List<Map<String, dynamic>> _devices = [];
  List<Map<String, dynamic>> _aps = [];
  Map<String, dynamic>? _threats;
  List<Map<String, dynamic>> _attackers = [];
  bool _loading = true;
  Timer? _refreshTimer;
  late TabController _tabController;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 4, vsync: this);
    WidgetsBinding.instance.addPostFrameCallback((_) => _fetchAll());
    _refreshTimer = Timer.periodic(
        const Duration(seconds: 8), (_) => _fetchAll());
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _fetchAll() async {
    try {
      final api = context.read<AuthService>().api;
      final results = await Future.wait([
        api.get('/wireless/status').catchError((_) => _emptyResp()),
        api.get('/wireless/devices').catchError((_) => _emptyResp()),
        api.get('/wireless/aps').catchError((_) => _emptyResp()),
        api.get('/wireless/threats').catchError((_) => _emptyResp()),
      ]);
      if (!mounted) return;
      setState(() {
        _status = results[0].data is Map ? results[0].data as Map<String, dynamic> : null;
        _devices = _parseList(results[1].data);
        _aps = _parseList(results[2].data);
        _threats = results[3].data is Map ? results[3].data as Map<String, dynamic> : null;
        _loading = false;
      });
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  List<Map<String, dynamic>> _parseList(dynamic data) {
    if (data is List) return data.cast<Map<String, dynamic>>();
    if (data is Map && data.containsKey('items')) {
      return (data['items'] as List).cast<Map<String, dynamic>>();
    }
    if (data is Map && data.containsKey('devices')) {
      return (data['devices'] as List).cast<Map<String, dynamic>>();
    }
    return [];
  }

  dynamic _emptyResp() => _FakeResponse({});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      drawer: const AppShellDrawer(),
      appBar: AppBar(
        title: const Text('Wireless Monitor'),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchAll),
        ],
        bottom: TabBar(
          controller: _tabController,
          isScrollable: true,
          tabs: const [
            Tab(icon: Icon(Icons.wifi), text: 'Status'),
            Tab(icon: Icon(Icons.phone_android), text: 'Devices'),
            Tab(icon: Icon(Icons.cell_tower), text: 'Access Points'),
            Tab(icon: Icon(Icons.warning_amber), text: 'Threats'),
          ],
        ),
      ),
      body: _loading
          ? Center(child: CircularProgressIndicator(color: theme.colorScheme.primary))
          : TabBarView(
              controller: _tabController,
              children: [
                _buildStatusTab(theme),
                _buildDevicesTab(theme),
                _buildAPsTab(theme),
                _buildThreatsTab(theme),
              ],
            ),
    );
  }

  // ── Tab 1: Adapter Status ──────────────────────────────────────

  Widget _buildStatusTab(ThemeData theme) {
    if (_status == null) {
      return _noData(theme, 'AR9271 adapter not detected or wireless API unavailable.');
    }

    final enabled = _status!['enabled'] == true;
    final running = _status!['running'] == true;
    final iface = _status!['interface']?.toString() ?? 'wlan0mon';
    final stats = _status!['capture_stats'] as Map<String, dynamic>? ?? {};
    final tracked = _status!['tracked_devices'] ?? 0;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Adapter banner
          GlassyContainer(
            borderRadius: 16,
            padding: const EdgeInsets.all(20),
            color: (running ? theme.colorScheme.primary : Colors.red)
                .withOpacity(0.1),
            child: Row(children: [
              Icon(
                running ? Icons.check_circle : Icons.cancel,
                color: running ? theme.colorScheme.primary : Colors.red,
                size: 40,
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      running
                          ? 'AR9271 — Active on $iface'
                          : 'AR9271 — Not Running',
                      style: GoogleFonts.inter(
                        fontSize: 18,
                        fontWeight: FontWeight.w700,
                        color: theme.colorScheme.onSurface,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      running
                          ? 'Monitor mode active. Channel hopping enabled.'
                          : enabled
                              ? 'Adapter enabled but capture is not running.'
                              : 'Wireless monitoring is disabled in config.',
                      style: TextStyle(
                        color: theme.colorScheme.onSurface.withOpacity(0.6),
                        fontSize: 13,
                      ),
                    ),
                  ],
                ),
              ),
            ]),
          ),
          const SizedBox(height: 24),

          // Capture statistics
          Text(
            'Capture Statistics',
            style: GoogleFonts.inter(
              fontSize: 16, fontWeight: FontWeight.w600,
              color: theme.colorScheme.onSurface,
            ),
          ),
          const SizedBox(height: 12),
          _statsGrid(theme, stats, tracked),
          const SizedBox(height: 24),

          // Config info
          Text(
            'Configuration',
            style: GoogleFonts.inter(
              fontSize: 16, fontWeight: FontWeight.w600,
              color: theme.colorScheme.onSurface,
            ),
          ),
          const SizedBox(height: 12),
          _configCard(theme),
        ],
      ),
    );
  }

  Widget _statsGrid(ThemeData theme, Map<String, dynamic> stats, dynamic tracked) {
    final items = [
      ('Frames Captured', '${stats['frames_captured'] ?? 0}', Icons.wifi_tethering),
      ('Probes Seen', '${stats['probes_seen'] ?? 0}', Icons.phone_android),
      ('Deauths Seen', '${stats['deauths_seen'] ?? 0}', Icons.warning_amber),
      ('Beacons Seen', '${stats['beacons_seen'] ?? 0}', Icons.cell_tower),
      ('Threats Detected', '${stats['threats_detected'] ?? 0}', Icons.shield),
      ('Tracked Devices', '$tracked', Icons.devices),
    ];

    return GridView.count(
      crossAxisCount: MediaQuery.of(context).size.width > 800 ? 3 : 2,
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      mainAxisSpacing: 12,
      crossAxisSpacing: 12,
      childAspectRatio: 2.2,
      children: items
          .map((item) => GlassyContainer(
                borderRadius: 12,
                padding: const EdgeInsets.all(14),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Row(children: [
                      Icon(item.$3, size: 18, color: theme.colorScheme.primary),
                      const SizedBox(width: 8),
                      Text(item.$1, style: TextStyle(
                        fontSize: 12, fontWeight: FontWeight.w600,
                        color: theme.colorScheme.onSurface.withOpacity(0.6),
                      )),
                    ]),
                    const SizedBox(height: 8),
                    Text(item.$2, style: GoogleFonts.spaceGrotesk(
                      fontSize: 22, fontWeight: FontWeight.w700,
                      color: theme.colorScheme.onSurface,
                    )),
                  ],
                ),
              ))
          .toList(),
    );
  }

  Widget _configCard(ThemeData theme) {
    final items = [
      ('Interface', _status?['interface']?.toString() ?? 'wlan0mon'),
      ('Driver', 'ath9k_htc'),
      ('Adapter', 'Atheros AR9271'),
      ('Mode', 'Monitor (passive)'),
      ('Channels', '1–13 (2.4 GHz)'),
      ('Hop Interval', '0.3s'),
    ];
    return GlassyContainer(
      borderRadius: 12,
      padding: const EdgeInsets.all(16),
      child: Column(
        children: items.map((i) => Padding(
          padding: const EdgeInsets.symmetric(vertical: 6),
          child: Row(children: [
            SizedBox(width: 120, child: Text(i.$1, style: TextStyle(
              color: theme.colorScheme.onSurface.withOpacity(0.5), fontSize: 13,
            ))),
            Expanded(child: Text(i.$2, style: TextStyle(
              color: theme.colorScheme.onSurface, fontSize: 13,
              fontWeight: FontWeight.w500,
            ))),
          ]),
        )).toList(),
      ),
    );
  }

  // ── Tab 2: WiFi Devices ────────────────────────────────────────

  Widget _buildDevicesTab(ThemeData theme) {
    if (_devices.isEmpty) {
      return _noData(theme, 'No WiFi devices detected yet. Waiting for probe requests...');
    }
    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: _devices.length,
      itemBuilder: (_, i) {
        final d = _devices[i];
        final mac = d['mac']?.toString() ?? 'unknown';
        final ssids = (d['ssids'] as List?)?.join(', ') ?? d['ssid']?.toString() ?? '';
        final rssi = d['rssi']?.toString() ?? '';
        final lastSeen = d['last_seen']?.toString() ?? '';
        final randomized = d['is_randomized'] == true;

        return Padding(
          padding: const EdgeInsets.only(bottom: 10),
          child: GlassyContainer(
            borderRadius: 14,
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                Icon(
                  randomized ? Icons.shuffle : Icons.phone_android,
                  color: randomized ? Colors.orange : theme.colorScheme.primary,
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(mac, style: GoogleFonts.jetBrainsMono(
                        fontSize: 13, fontWeight: FontWeight.w600,
                        color: theme.colorScheme.onSurface,
                      )),
                      if (ssids.isNotEmpty) ...[
                        const SizedBox(height: 4),
                        Text('SSIDs: $ssids', style: TextStyle(
                          fontSize: 12,
                          color: theme.colorScheme.onSurface.withOpacity(0.6),
                        )),
                      ],
                      if (lastSeen.isNotEmpty) ...[
                        const SizedBox(height: 2),
                        Text('Last seen: $lastSeen', style: TextStyle(
                          fontSize: 11,
                          color: theme.colorScheme.onSurface.withOpacity(0.45),
                        )),
                      ],
                    ],
                  ),
                ),
                if (rssi.isNotEmpty)
                  Column(children: [
                    Icon(Icons.signal_wifi_4_bar, size: 20,
                        color: theme.colorScheme.primary.withOpacity(0.6)),
                    Text(rssi, style: TextStyle(
                      fontSize: 11,
                      color: theme.colorScheme.onSurface.withOpacity(0.5),
                    )),
                  ]),
                if (randomized)
                  Container(
                    margin: const EdgeInsets.only(left: 8),
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(
                      color: Colors.orange.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: const Text('RANDOM', style: TextStyle(
                      fontSize: 10, fontWeight: FontWeight.w700, color: Colors.orange,
                    )),
                  ),
              ],
            ),
          ),
        );
      },
    );
  }

  // ── Tab 3: Access Points ───────────────────────────────────────

  Widget _buildAPsTab(ThemeData theme) {
    if (_aps.isEmpty) {
      return _noData(theme, 'No access points discovered yet. Waiting for beacons...');
    }
    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: _aps.length,
      itemBuilder: (_, i) {
        final ap = _aps[i];
        final ssid = ap['ssid']?.toString() ?? '<hidden>';
        final bssid = ap['bssid']?.toString() ?? '';
        final channel = ap['channel']?.toString() ?? '';
        final privacy = ap['privacy']?.toString() ?? '';

        return Padding(
          padding: const EdgeInsets.only(bottom: 10),
          child: GlassyContainer(
            borderRadius: 14,
            padding: const EdgeInsets.all(16),
            child: Row(children: [
              Icon(Icons.cell_tower, color: theme.colorScheme.primary),
              const SizedBox(width: 14),
              Expanded(child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(ssid, style: TextStyle(
                    fontSize: 15, fontWeight: FontWeight.w600,
                    color: theme.colorScheme.onSurface,
                  )),
                  const SizedBox(height: 4),
                  Text('BSSID: $bssid', style: GoogleFonts.jetBrainsMono(
                    fontSize: 11,
                    color: theme.colorScheme.onSurface.withOpacity(0.5),
                  )),
                ],
              )),
              Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
                if (channel.isNotEmpty)
                  Text('CH $channel', style: TextStyle(
                    fontSize: 12, fontWeight: FontWeight.w600,
                    color: theme.colorScheme.primary,
                  )),
                if (privacy.isNotEmpty)
                  Text(privacy, style: TextStyle(
                    fontSize: 11,
                    color: theme.colorScheme.onSurface.withOpacity(0.5),
                  )),
              ]),
            ]),
          ),
        );
      },
    );
  }

  // ── Tab 4: WiFi Threats ────────────────────────────────────────

  Widget _buildThreatsTab(ThemeData theme) {
    final deauthActive = _threats?['deauth_active'] == true;
    final rogueActive = _threats?['rogue_ap_active'] == true;
    final deauthEvents = (_threats?['recent_deauth_events'] as List?) ?? [];
    final rogueEvents = (_threats?['recent_rogue_events'] as List?) ?? [];
    final noThreats = !deauthActive && !rogueActive && deauthEvents.isEmpty && rogueEvents.isEmpty;

    if (_threats == null || noThreats) {
      return _noData(theme, 'No wireless threats detected. Network is clean.');
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (deauthActive)
            _threatBanner(theme, 'Deauth Attack Active', Colors.red,
                Icons.warning_amber, 'Deauthentication flood detected on the network.'),
          if (rogueActive)
            _threatBanner(theme, 'Rogue AP Detected', Colors.orange,
                Icons.cell_tower, 'An unauthorized access point with a known SSID was found.'),
          if (!deauthActive && !rogueActive)
            _threatBanner(theme, 'No Active Threats', theme.colorScheme.primary,
                Icons.check_circle, 'Past threats are listed below.'),
          const SizedBox(height: 16),
          if (deauthEvents.isNotEmpty) ...[
            Text('Deauth Events', style: GoogleFonts.inter(
              fontSize: 14, fontWeight: FontWeight.w600,
              color: theme.colorScheme.onSurface,
            )),
            const SizedBox(height: 8),
            ...deauthEvents.map((e) => _threatEventCard(theme, e)),
          ],
          if (rogueEvents.isNotEmpty) ...[
            const SizedBox(height: 16),
            Text('Rogue AP Events', style: GoogleFonts.inter(
              fontSize: 14, fontWeight: FontWeight.w600,
              color: theme.colorScheme.onSurface,
            )),
            const SizedBox(height: 8),
            ...rogueEvents.map((e) => _threatEventCard(theme, e)),
          ],
        ],
      ),
    );
  }

  Widget _threatBanner(ThemeData theme, String title, Color color,
      IconData icon, String detail) {
    return GlassyContainer(
      borderRadius: 14,
      padding: const EdgeInsets.all(16),
      color: color.withOpacity(0.1),
      child: Row(children: [
        Icon(icon, color: color, size: 32),
        const SizedBox(width: 14),
        Expanded(child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: TextStyle(
              fontSize: 16, fontWeight: FontWeight.w700, color: color,
            )),
            const SizedBox(height: 4),
            Text(detail, style: TextStyle(
              fontSize: 12, color: theme.colorScheme.onSurface.withOpacity(0.6),
            )),
          ],
        )),
      ]),
    );
  }

  Widget _threatEventCard(ThemeData theme, dynamic event) {
    final e = event is Map ? event : <String, dynamic>{};
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: GlassyContainer(
        borderRadius: 10,
        padding: const EdgeInsets.all(12),
        child: Row(children: [
          Icon(Icons.warning_amber, size: 18, color: Colors.red.withOpacity(0.7)),
          const SizedBox(width: 10),
          Expanded(child: Text(
            e['description']?.toString() ??
                'BSSID: ${e['bssid'] ?? 'unknown'} | MAC: ${e['src_mac'] ?? 'unknown'}',
            style: TextStyle(
              fontSize: 12, color: theme.colorScheme.onSurface.withOpacity(0.7),
            ),
          )),
          Text(e['timestamp']?.toString().substring(11, 19) ?? '', style: TextStyle(
            fontSize: 11, color: theme.colorScheme.onSurface.withOpacity(0.4),
          )),
        ]),
      ),
    );
  }

  // ── Helpers ────────────────────────────────────────────────────

  Widget _noData(ThemeData theme, String message) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.wifi_off, size: 64,
              color: theme.colorScheme.onSurface.withOpacity(0.2)),
          const SizedBox(height: 16),
          Text(message, textAlign: TextAlign.center, style: TextStyle(
            color: theme.colorScheme.onSurface.withOpacity(0.5),
          )),
        ],
      ),
    );
  }
}

/// Minimal fake response for error handling.
class _FakeResponse {
  final dynamic data;
  _FakeResponse(this.data);
}
