import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../core/auth_service.dart';
import '../core/websocket_service.dart';
import '../widgets/glassy_container.dart';
import '../widgets/risk_card.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen>
    with SingleTickerProviderStateMixin {
  Map<String, dynamic>? _stats;
  Map<String, dynamic>? _topology;
  VoidCallback? _wsListener;
  late final AnimationController _controller;
  late final Animation<double> _fade;

  final List<_NavItem> _navItems = const [
    _NavItem(
        icon: Icons.dashboard_outlined, label: 'Dashboard', path: '/dashboard'),
    _NavItem(icon: Icons.devices_outlined, label: 'Devices', path: '/devices'),
    _NavItem(
        icon: Icons.public_outlined, label: 'Threat Map', path: '/threats'),
    _NavItem(icon: Icons.hub_outlined, label: 'Topology', path: '/topology'),
    _NavItem(
        icon: Icons.security_outlined, label: 'Firewall', path: '/firewall'),
    _NavItem(
        icon: Icons.bug_report_outlined, label: 'Honeypot', path: '/honeypot'),
    _NavItem(
        icon: Icons.monitor_heart_outlined, label: 'System', path: '/system'),
    _NavItem(
        icon: Icons.settings_outlined, label: 'Settings', path: '/settings'),
  ];

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 700),
    );
    _fade = CurvedAnimation(parent: _controller, curve: Curves.easeOutCubic);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _connectWs();
      _attachWsListener();
      _loadStats();
      _loadTopology();
      _controller.forward();
    });
  }

  @override
  void dispose() {
    final listener = _wsListener;
    if (listener != null) {
      context.read<WebSocketService>().removeListener(listener);
    }
    _controller.dispose();
    super.dispose();
  }

  void _connectWs() {
    final auth = context.read<AuthService>();
    final ws = context.read<WebSocketService>();
    final token = auth.accessToken ?? '';
    if (!ws.connected && token.isNotEmpty) {
      ws.connect(token);
    }
  }

  void _attachWsListener() {
    final ws = context.read<WebSocketService>();
    _wsListener ??= () {
      if (!mounted || ws.events.isEmpty) return;
      final latest = ws.events.first;
      final type = latest['type']?.toString();
      if (type == 'threat' ||
          type == 'topology_updated' ||
          type == 'device_seen' ||
          type == 'device_updated') {
        _loadStats();
      }
      if (type == 'topology_updated' ||
          type == 'device_seen' ||
          type == 'device_updated') {
        _loadTopology();
      }
    };
    ws.addListener(_wsListener!);
  }

  Future<void> _loadStats() async {
    try {
      final api = context.read<AuthService>().api;
      final resp = await api.get('/system/stats');
      if (mounted) {
        setState(() => _stats = resp.data as Map<String, dynamic>);
      }
    } catch (_) {}
  }

  Future<void> _loadTopology() async {
    try {
      final api = context.read<AuthService>().api;
      final resp = await api.get('/network/topology');
      if (mounted) {
        setState(() => _topology = resp.data as Map<String, dynamic>);
      }
    } catch (_) {}
  }

  Future<void> _triggerScan() async {
    final messenger = ScaffoldMessenger.of(context);
    final theme = Theme.of(context);
    try {
      final api = context.read<AuthService>().api;
      await api.post('/network/scan', {});
      if (!mounted) return;
      messenger.showSnackBar(
        SnackBar(
          content: const Text(
              'Network scan started. Fresh devices will stream in as the backend publishes updates.'),
          backgroundColor: theme.colorScheme.primary,
        ),
      );
    } catch (error) {
      if (!mounted) return;
      messenger.showSnackBar(
        SnackBar(
          content: Text('Could not start scan: $error'),
          backgroundColor: const Color(0xFFD14343),
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final ws = context.watch<WebSocketService>();
    final auth = context.read<AuthService>();
    final width = MediaQuery.of(context).size.width;
    final isMobile = width < 960;
    final currentPath = GoRouterState.of(context).uri.path;

    return Scaffold(
      body: Container(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: theme.brightness == Brightness.dark
                ? const [
                    Color(0xFF07111F),
                    Color(0xFF0A162A),
                    Color(0xFF07111F)
                  ]
                : const [
                    Color(0xFFF4F8FC),
                    Color(0xFFEAF2FB),
                    Color(0xFFF5F8FC)
                  ],
          ),
        ),
        child: Row(
          children: [
            if (!isMobile) _buildNavRail(context, auth, theme, currentPath),
            Expanded(
              child: SafeArea(
                child: FadeTransition(
                  opacity: _fade,
                  child: Column(
                    children: [
                      _buildTopBar(context, ws, auth, theme, isMobile),
                      Expanded(
                        child: RefreshIndicator(
                          onRefresh: () async {
                            await _loadStats();
                            await _loadTopology();
                          },
                          child: _buildBody(context, ws, theme),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
      bottomNavigationBar:
          isMobile ? _buildBottomNav(context, theme, currentPath) : null,
    );
  }

  Widget _buildBody(
      BuildContext context, WebSocketService ws, ThemeData theme) {
    final width = MediaQuery.of(context).size.width;
    final nodes = (_topology?['nodes'] as List? ?? []);
    final deviceCount = nodes.where((n) => n['type'] == 'device').length;
    final attackerCount = nodes.where((n) => n['type'] == 'attacker').length;
    final honeypotCount = _toInt(_stats?['total_honeypot_sessions']);
    final threatCount = _toInt(_stats?['total_threats']);
    final highRisk = _toInt(_stats?['high_risk_threats']);
    final ruleCount = _toInt(_stats?['active_firewall_rules']);
    final gatewayIp =
        (_topology?['meta'] as Map<String, dynamic>?)?['gateway_ip']
                ?.toString() ??
            'Unavailable';
    final events = ws.events.take(20).toList();
    final columns = width > 1320
        ? 4
        : width > 900
            ? 2
            : 1;

    return ListView(
      padding: EdgeInsets.fromLTRB(
          width < 760 ? 18 : 28, 16, width < 760 ? 18 : 28, 28),
      children: [
        _buildHeroSection(theme, deviceCount, attackerCount, gatewayIp),
        const SizedBox(height: 22),
        GridView.count(
          crossAxisCount: columns,
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          mainAxisSpacing: 16,
          crossAxisSpacing: 16,
          childAspectRatio: width > 1320
              ? 1.55
              : width > 900
                  ? 1.65
                  : 1.5,
          children: [
            RiskCard(
              title: 'Threat events',
              value: '$threatCount',
              icon: Icons.warning_amber_outlined,
              color: const Color(0xFFD14343),
            ),
            RiskCard(
              title: 'High risk alerts',
              value: '$highRisk',
              icon: Icons.priority_high_outlined,
              color: const Color(0xFFF59E0B),
            ),
            RiskCard(
              title: 'Protected devices',
              value: '$deviceCount',
              icon: Icons.devices_outlined,
              color: const Color(0xFF0F6CBD),
            ),
            RiskCard(
              title: 'Honeypot sessions',
              value: '$honeypotCount',
              icon: Icons.bug_report_outlined,
              color: const Color(0xFF0F9D7A),
            ),
          ],
        ),
        const SizedBox(height: 22),
        Wrap(
          spacing: 16,
          runSpacing: 16,
          children: [
            SizedBox(
              width: width > 1100 ? (width - 104) * 0.58 : double.infinity,
              child: _buildFeedPanel(theme, events),
            ),
            SizedBox(
              width: width > 1100 ? (width - 104) * 0.36 : double.infinity,
              child: _buildPosturePanel(
                theme,
                gatewayIp: gatewayIp,
                deviceCount: deviceCount,
                attackerCount: attackerCount,
                ruleCount: ruleCount,
                ws: ws,
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildHeroSection(
    ThemeData theme,
    int deviceCount,
    int attackerCount,
    String gatewayIp,
  ) {
    return GlassyContainer(
      borderRadius: 30,
      padding: const EdgeInsets.all(26),
      color: theme.brightness == Brightness.dark
          ? const Color(0xFF10233D).withOpacity(0.84)
          : Colors.white.withOpacity(0.82),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final compact = constraints.maxWidth < 860;
          return Flex(
            direction: compact ? Axis.vertical : Axis.horizontal,
            crossAxisAlignment:
                compact ? CrossAxisAlignment.start : CrossAxisAlignment.center,
            children: [
              Expanded(
                flex: compact ? 0 : 7,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 12, vertical: 8),
                      decoration: BoxDecoration(
                        color: theme.colorScheme.primary.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(999),
                      ),
                      child: Text(
                        'Operations overview',
                        style: GoogleFonts.spaceGrotesk(
                          color: theme.colorScheme.primary,
                          fontWeight: FontWeight.w700,
                          letterSpacing: 0.4,
                        ),
                      ),
                    ),
                    const SizedBox(height: 18),
                    Text(
                      'See your live network posture without the noise.',
                      style: GoogleFonts.spaceGrotesk(
                        fontSize: compact ? 28 : 36,
                        fontWeight: FontWeight.w700,
                        height: 1.05,
                        color: theme.colorScheme.onSurface,
                      ),
                    ),
                    const SizedBox(height: 14),
                    Text(
                      'Gateway $gatewayIp is the anchor for this view. Realtime events, scans, and honeypot sessions are surfaced here as soon as the backend publishes them.',
                      style: TextStyle(
                        fontSize: 14,
                        height: 1.7,
                        color: theme.colorScheme.onSurface.withOpacity(0.7),
                      ),
                    ),
                    const SizedBox(height: 20),
                    Wrap(
                      spacing: 12,
                      runSpacing: 12,
                      children: [
                        _ActionChip(
                          icon: Icons.hub_outlined,
                          label: 'Open topology',
                          onTap: () => context.go('/topology'),
                        ),
                        _ActionChip(
                          icon: Icons.radar_outlined,
                          label: 'Run scan',
                          onTap: _triggerScan,
                        ),
                        _ActionChip(
                          icon: Icons.bug_report_outlined,
                          label: 'Review honeypot',
                          onTap: () => context.go('/honeypot'),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              if (!compact) const SizedBox(width: 24),
              Expanded(
                flex: compact ? 0 : 4,
                child: Padding(
                  padding: EdgeInsets.only(top: compact ? 20 : 0),
                  child: Column(
                    children: [
                      _MiniStat(
                        title: 'Visible devices',
                        value: '$deviceCount',
                        icon: Icons.router_outlined,
                      ),
                      const SizedBox(height: 12),
                      _MiniStat(
                        title: 'Active threat nodes',
                        value: '$attackerCount',
                        icon: Icons.gpp_maybe_outlined,
                      ),
                    ],
                  ),
                ),
              ),
            ],
          );
        },
      ),
    );
  }

  Widget _buildFeedPanel(ThemeData theme, List<Map<String, dynamic>> events) {
    return GlassyContainer(
      borderRadius: 28,
      padding: const EdgeInsets.all(22),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                'Live activity',
                style: GoogleFonts.spaceGrotesk(
                  fontSize: 22,
                  fontWeight: FontWeight.w700,
                  color: theme.colorScheme.onSurface,
                ),
              ),
              const Spacer(),
              Text(
                '${events.length} recent events',
                style: TextStyle(
                  color: theme.colorScheme.onSurface.withOpacity(0.58),
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          if (events.isEmpty)
            Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: theme.colorScheme.primary.withOpacity(0.06),
                borderRadius: BorderRadius.circular(22),
              ),
              child: Text(
                'Waiting for live activity from scans, threats, or honeypot sessions.',
                style: TextStyle(
                  color: theme.colorScheme.onSurface.withOpacity(0.68),
                  height: 1.6,
                ),
              ),
            )
          else
            ...events.map((event) => _EventRow(event: event)),
        ],
      ),
    );
  }

  Widget _buildPosturePanel(
    ThemeData theme, {
    required String gatewayIp,
    required int deviceCount,
    required int attackerCount,
    required int ruleCount,
    required WebSocketService ws,
  }) {
    final statusLine = _realtimeStatusText(ws);
    final items = [
      ('Gateway', gatewayIp, Icons.router_outlined),
      ('Tracked devices', '$deviceCount', Icons.devices_outlined),
      ('Threat nodes', '$attackerCount', Icons.warning_amber_outlined),
      ('Firewall rules', '$ruleCount', Icons.security_outlined),
    ];

    return GlassyContainer(
      borderRadius: 28,
      padding: const EdgeInsets.all(22),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                'System posture',
                style: GoogleFonts.spaceGrotesk(
                  fontSize: 22,
                  fontWeight: FontWeight.w700,
                  color: theme.colorScheme.onSurface,
                ),
              ),
              const Spacer(),
              _StatusPill(
                color: ws.connected
                    ? const Color(0xFF0F9D7A)
                    : ws.reconnectAttempts > 0
                        ? const Color(0xFFF59E0B)
                        : const Color(0xFFD14343),
                label: ws.connected
                    ? 'Realtime connected'
                    : ws.reconnectAttempts > 0
                        ? 'Reconnecting'
                        : 'Realtime offline',
              ),
            ],
          ),
          const SizedBox(height: 18),
          Text(
            statusLine,
            style: TextStyle(
              color: theme.colorScheme.onSurface.withOpacity(0.62),
              height: 1.5,
            ),
          ),
          const SizedBox(height: 14),
          ...items.map(
            (item) => Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: theme.colorScheme.primary.withOpacity(0.05),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Row(
                  children: [
                    Icon(item.$3, color: theme.colorScheme.primary),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        item.$1,
                        style: TextStyle(
                          color: theme.colorScheme.onSurface.withOpacity(0.66),
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                    Text(
                      item.$2,
                      style: GoogleFonts.spaceGrotesk(
                        fontWeight: FontWeight.w700,
                        color: theme.colorScheme.onSurface,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBottomNav(
      BuildContext context, ThemeData theme, String currentPath) {
    final items = _navItems.take(5).toList();
    return NavigationBar(
      selectedIndex: _navIndexForPath(currentPath).clamp(0, items.length - 1),
      backgroundColor: theme.colorScheme.surface.withOpacity(0.96),
      indicatorColor: theme.colorScheme.primary.withOpacity(0.14),
      onDestinationSelected: (index) {
        context.go(items[index].path);
      },
      destinations: items
          .map((item) =>
              NavigationDestination(icon: Icon(item.icon), label: item.label))
          .toList(),
    );
  }

  Widget _buildNavRail(
    BuildContext context,
    AuthService auth,
    ThemeData theme,
    String currentPath,
  ) {
    return Padding(
      padding: const EdgeInsets.all(18),
      child: GlassyContainer(
        borderRadius: 28,
        padding: const EdgeInsets.symmetric(vertical: 20),
        child: NavigationRail(
          selectedIndex: _navIndexForPath(currentPath),
          extended: MediaQuery.of(context).size.width > 1260,
          backgroundColor: Colors.transparent,
          indicatorColor: theme.colorScheme.primary.withOpacity(0.14),
          selectedIconTheme: IconThemeData(color: theme.colorScheme.primary),
          unselectedIconTheme: IconThemeData(
            color: theme.colorScheme.onSurface.withOpacity(0.5),
          ),
          selectedLabelTextStyle: TextStyle(
            color: theme.colorScheme.primary,
            fontWeight: FontWeight.w700,
          ),
          unselectedLabelTextStyle: TextStyle(
            color: theme.colorScheme.onSurface.withOpacity(0.5),
          ),
          leading: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Column(
              children: [
                Container(
                  width: 50,
                  height: 50,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(18),
                    color: theme.colorScheme.primary.withOpacity(0.12),
                  ),
                  child: Icon(Icons.shield_outlined,
                      color: theme.colorScheme.primary),
                ),
                const SizedBox(height: 12),
                Text(
                  'NTTH',
                  style: GoogleFonts.spaceGrotesk(
                    color: theme.colorScheme.onSurface,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ],
            ),
          ),
          trailing: Expanded(
            child: Align(
              alignment: Alignment.bottomCenter,
              child: IconButton(
                onPressed: () async {
                  context
                      .read<WebSocketService>()
                      .disconnect(clearEvents: true);
                  await auth.logout();
                  if (context.mounted) context.go('/login');
                },
                icon: Icon(
                  Icons.logout,
                  color: theme.colorScheme.onSurface.withOpacity(0.5),
                ),
              ),
            ),
          ),
          onDestinationSelected: (index) => context.go(_navItems[index].path),
          destinations: _navItems
              .map(
                (item) => NavigationRailDestination(
                  icon: Icon(item.icon),
                  label: Text(item.label),
                ),
              )
              .toList(),
        ),
      ),
    );
  }

  Widget _buildTopBar(
    BuildContext context,
    WebSocketService ws,
    AuthService auth,
    ThemeData theme,
    bool isMobile,
  ) {
    return Padding(
      padding:
          EdgeInsets.fromLTRB(isMobile ? 18 : 28, 18, isMobile ? 18 : 28, 10),
      child: GlassyContainer(
        borderRadius: 24,
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
        child: Wrap(
          alignment: WrapAlignment.spaceBetween,
          crossAxisAlignment: WrapCrossAlignment.center,
          runSpacing: 12,
          children: [
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Network command center',
                  style: GoogleFonts.spaceGrotesk(
                    fontSize: 26,
                    fontWeight: FontWeight.w700,
                    color: theme.colorScheme.onSurface,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  'Signed in as ${auth.username}',
                  style: TextStyle(
                    color: theme.colorScheme.onSurface.withOpacity(0.64),
                  ),
                ),
              ],
            ),
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                _StatusPill(
                  color: ws.connected
                      ? const Color(0xFF0F9D7A)
                      : ws.reconnectAttempts > 0
                          ? const Color(0xFFF59E0B)
                          : const Color(0xFFD14343),
                  label: ws.connected
                      ? 'Live updates active'
                      : ws.reconnectAttempts > 0
                          ? 'Reconnecting live feed'
                          : 'Live updates offline',
                ),
                const SizedBox(width: 10),
                if (isMobile)
                  PopupMenuButton<String>(
                    tooltip: 'Open more sections',
                    onSelected: (value) async {
                      if (value == '__logout__') {
                        context
                            .read<WebSocketService>()
                            .disconnect(clearEvents: true);
                        await auth.logout();
                        if (context.mounted) context.go('/login');
                        return;
                      }
                      if (context.mounted) {
                        context.go(value);
                      }
                    },
                    itemBuilder: (context) => [
                      ..._navItems.skip(5).map(
                            (item) => PopupMenuItem<String>(
                              value: item.path,
                              child: Text(item.label),
                            ),
                          ),
                      const PopupMenuDivider(),
                      const PopupMenuItem<String>(
                        value: '__logout__',
                        child: Text('Logout'),
                      ),
                    ],
                    icon: Icon(
                      Icons.menu,
                      color: theme.colorScheme.onSurface.withOpacity(0.7),
                    ),
                  ),
                if (isMobile) const SizedBox(width: 4),
                IconButton(
                  tooltip: 'Refresh dashboard',
                  onPressed: () {
                    _loadStats();
                    _loadTopology();
                  },
                  icon: Icon(
                    Icons.refresh,
                    color: theme.colorScheme.onSurface.withOpacity(0.7),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  int _toInt(dynamic value) {
    if (value is int) return value;
    if (value is num) return value.toInt();
    return 0;
  }

  int _navIndexForPath(String path) {
    final index = _navItems.indexWhere((item) => item.path == path);
    return index < 0 ? 0 : index;
  }

  String _realtimeStatusText(WebSocketService ws) {
    if (ws.connected) {
      final lastEventAt = ws.lastEventAt;
      if (lastEventAt == null) {
        return 'Connected to the backend and waiting for the first live event.';
      }
      return 'Connected. Last live event arrived ${timeago.format(lastEventAt)}.';
    }
    if (ws.reconnectAttempts > 0) {
      return 'The live channel dropped and is retrying automatically. Attempt ${ws.reconnectAttempts}.';
    }
    return 'Realtime is offline. Dashboard cards still refresh manually, but live threat and topology events will be delayed.';
  }
}

class _NavItem {
  final IconData icon;
  final String label;
  final String path;

  const _NavItem({
    required this.icon,
    required this.label,
    required this.path,
  });
}

class _ActionChip extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onTap;

  const _ActionChip({
    required this.icon,
    required this.label,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(999),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        decoration: BoxDecoration(
          color: theme.colorScheme.primary.withOpacity(0.08),
          borderRadius: BorderRadius.circular(999),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 18, color: theme.colorScheme.primary),
            const SizedBox(width: 10),
            Text(
              label,
              style: TextStyle(
                color: theme.colorScheme.onSurface,
                fontWeight: FontWeight.w700,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _MiniStat extends StatelessWidget {
  final String title;
  final String value;
  final IconData icon;

  const _MiniStat({
    required this.title,
    required this.value,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: theme.colorScheme.primary.withOpacity(0.06),
        borderRadius: BorderRadius.circular(22),
      ),
      child: Row(
        children: [
          Container(
            width: 42,
            height: 42,
            decoration: BoxDecoration(
              color: theme.colorScheme.primary.withOpacity(0.12),
              borderRadius: BorderRadius.circular(14),
            ),
            child: Icon(icon, color: theme.colorScheme.primary),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface.withOpacity(0.62),
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  value,
                  style: GoogleFonts.spaceGrotesk(
                    color: theme.colorScheme.onSurface,
                    fontSize: 22,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _StatusPill extends StatelessWidget {
  final Color color;
  final String label;

  const _StatusPill({required this.color, required this.label});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: color.withOpacity(0.12),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 8),
          Text(
            label,
            style: TextStyle(color: color, fontWeight: FontWeight.w700),
          ),
        ],
      ),
    );
  }
}

class _EventRow extends StatelessWidget {
  final Map<String, dynamic> event;

  const _EventRow({required this.event});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final type = event['type']?.toString() ?? 'event';
    final risk = (event['risk_score'] as num?)?.toDouble() ?? 0;
    final title = type == 'topology_updated'
        ? 'Topology refreshed'
        : '${event['src_ip'] ?? 'Unknown'} ${event['threat_type'] ?? 'activity'}';
    final subtitle = type == 'topology_updated'
        ? '${event['devices_found'] ?? 0} devices found in latest scan'
        : '${event['action_taken'] ?? event['action'] ?? 'logged'}';

    final Color dotColor;
    if (type == 'topology_updated') {
      dotColor = const Color(0xFF0F6CBD);
    } else if (risk > 0.85) {
      dotColor = const Color(0xFFD14343);
    } else if (risk > 0.5) {
      dotColor = const Color(0xFFF59E0B);
    } else {
      dotColor = const Color(0xFF0F9D7A);
    }

    DateTime? timestamp;
    final rawTime =
        event['detected_at']?.toString() ?? event['timestamp']?.toString();
    if (rawTime != null) {
      timestamp = DateTime.tryParse(rawTime);
    }

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: theme.colorScheme.primary.withOpacity(0.04),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 12,
            height: 12,
            margin: const EdgeInsets.only(top: 4),
            decoration: BoxDecoration(color: dotColor, shape: BoxShape.circle),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  subtitle,
                  style: TextStyle(
                    color: theme.colorScheme.onSurface.withOpacity(0.64),
                    height: 1.5,
                  ),
                ),
              ],
            ),
          ),
          if (timestamp != null)
            Padding(
              padding: const EdgeInsets.only(left: 10),
              child: Text(
                timeago.format(timestamp),
                style: TextStyle(
                  color: theme.colorScheme.onSurface.withOpacity(0.46),
                  fontSize: 12,
                ),
              ),
            ),
        ],
      ),
    );
  }
}
