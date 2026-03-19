import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:go_router/go_router.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../core/auth_service.dart';
import '../core/websocket_service.dart';
import '../widgets/risk_card.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  int _navIndex = 0;
  Map<String, dynamic>? _stats;

  final List<_NavItem> _navItems = const [
    _NavItem(icon: Icons.dashboard_outlined,     label: 'Dashboard',   path: '/dashboard'),
    _NavItem(icon: Icons.devices_outlined,        label: 'Devices',     path: '/devices'),
    _NavItem(icon: Icons.public_outlined,         label: 'Threat Map',  path: '/threats'),
    _NavItem(icon: Icons.security_outlined,       label: 'Firewall',    path: '/firewall'),
    _NavItem(icon: Icons.bug_report_outlined,     label: 'Honeypot',    path: '/honeypot'),
    _NavItem(icon: Icons.monitor_heart_outlined,  label: 'System',      path: '/system'),
    _NavItem(icon: Icons.settings_outlined,       label: 'Settings',    path: '/settings'),
  ];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _connectWS();
      _loadStats();
    });
  }

  void _connectWS() {
    final auth = context.read<AuthService>();
    final ws = context.read<WebSocketService>();
    final token = auth.api.dio.options.headers['Authorization']
            ?.toString()
            .replaceFirst('Bearer ', '') ??
        '';
    if (!ws.connected && token.isNotEmpty) ws.connect(token);
  }

  Future<void> _loadStats() async {
    try {
      final api = context.read<AuthService>().api;
      final resp = await api.get('/system/stats');
      if (mounted) setState(() => _stats = resp.data as Map<String, dynamic>);
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    final ws = context.watch<WebSocketService>();
    final auth = context.read<AuthService>();

    return Scaffold(
      body: Row(
        children: [
          _buildNavRail(context, auth),
          Expanded(
            child: Column(children: [
              _buildTopBar(context, ws, auth),
              Expanded(child: _buildDashboardContent(context, ws)),
            ]),
          ),
        ],
      ),
    );
  }

  Widget _buildNavRail(BuildContext context, AuthService auth) {
    return NavigationRail(
      selectedIndex: _navIndex,
      onDestinationSelected: (i) {
        setState(() => _navIndex = i);
        context.go(_navItems[i].path);
      },
      extended: MediaQuery.of(context).size.width > 900,
      leading: Padding(
        padding: const EdgeInsets.symmetric(vertical: 24),
        child: Column(children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              border: Border.all(color: const Color(0xFF00FF88), width: 1.5),
            ),
            child: const Icon(Icons.shield_outlined, color: Color(0xFF00FF88), size: 24),
          ),
          const SizedBox(height: 8),
          Text('NTTH',
              style: GoogleFonts.inter(
                  color: const Color(0xFF00FF88), fontSize: 11, fontWeight: FontWeight.w700)),
        ]),
      ),
      trailing: Padding(
        padding: const EdgeInsets.only(bottom: 16),
        child: IconButton(
          icon: const Icon(Icons.logout, color: Colors.white38),
          onPressed: () async {
            await auth.logout();
            if (context.mounted) context.go('/login');
          },
        ),
      ),
      destinations: _navItems
          .map((n) => NavigationRailDestination(icon: Icon(n.icon), label: Text(n.label)))
          .toList(),
    );
  }

  Widget _buildTopBar(BuildContext context, WebSocketService ws, AuthService auth) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
      decoration: const BoxDecoration(
        color: Color(0xFF0D1117),
        border: Border(bottom: BorderSide(color: Color(0xFF1F2937))),
      ),
      child: Row(children: [
        Text('Dashboard',
            style: GoogleFonts.inter(fontSize: 20, fontWeight: FontWeight.w700, color: Colors.white)),
        const Spacer(),
        _wsIndicator(ws.connected),
        const SizedBox(width: 16),
        Text('👤 ${auth.username}', style: const TextStyle(color: Colors.white54, fontSize: 13)),
        const SizedBox(width: 16),
        IconButton(icon: const Icon(Icons.refresh, color: Colors.white38), onPressed: _loadStats),
      ]),
    );
  }

  Widget _wsIndicator(bool connected) {
    return Row(children: [
      Container(
        width: 8, height: 8,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: connected ? const Color(0xFF00FF88) : Colors.red,
          boxShadow: [BoxShadow(color: (connected ? const Color(0xFF00FF88) : Colors.red).withOpacity(0.6), blurRadius: 6)],
        ),
      ),
      const SizedBox(width: 6),
      Text(connected ? 'LIVE' : 'OFFLINE',
          style: TextStyle(
              color: connected ? const Color(0xFF00FF88) : Colors.red,
              fontSize: 11,
              fontWeight: FontWeight.w700)),
    ]);
  }

  Widget _buildDashboardContent(BuildContext context, WebSocketService ws) {
    final threats = ws.events.where((e) => e['type'] == 'threat').toList();
    final high = threats.where((e) => (e['risk_score'] as num? ?? 0) > 0.85).length;
    final medium = threats.where((e) {
      final s = (e['risk_score'] as num? ?? 0).toDouble();
      return s > 0.5 && s <= 0.85;
    }).length;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Stats Row — REST data takes priority over WS counters
          Row(children: [
            Expanded(child: RiskCard(
              title: 'Total Threats',
              value: '${_stats?['total_threats'] ?? ws.events.length}',
              icon: Icons.timeline,
              color: const Color(0xFF3B82F6),
            )),
            const SizedBox(width: 16),
            Expanded(child: RiskCard(
              title: 'High Risk',
              value: '${_stats?['high_risk_threats'] ?? high}',
              icon: Icons.warning_amber,
              color: Colors.red,
            )),
            const SizedBox(width: 16),
            Expanded(child: RiskCard(
              title: 'Active Rules',
              value: '${_stats?['active_firewall_rules'] ?? medium}',
              icon: Icons.security,
              color: Colors.orange,
            )),
            const SizedBox(width: 16),
            Expanded(child: RiskCard(
              title: 'Devices',
              value: '${_stats?['total_devices'] ?? '—'}',
              icon: Icons.devices,
              color: const Color(0xFF8B5CF6),
            )),
          ]),
          const SizedBox(height: 16),
          Row(children: [
            Expanded(child: RiskCard(
              title: 'HP Sessions',
              value: '${_stats?['total_honeypot_sessions'] ?? '—'}',
              icon: Icons.bug_report_outlined,
              color: const Color(0xFF10B981),
            )),
            const SizedBox(width: 16),
            Expanded(child: RiskCard(
              title: 'Unacknowledged',
              value: '${_stats?['unacknowledged_threats'] ?? '—'}',
              icon: Icons.notifications_active_outlined,
              color: Colors.deepOrange,
            )),
            const SizedBox(width: 16),
            const Expanded(child: SizedBox()),
            const SizedBox(width: 16),
            const Expanded(child: SizedBox()),
          ]),
          const SizedBox(height: 24),

          // Live event feed
          Row(children: [
            Text('Live Event Feed',
                style: GoogleFonts.inter(fontSize: 16, fontWeight: FontWeight.w600, color: Colors.white)),
            const Spacer(),
            Text('${threats.length} events', style: const TextStyle(color: Colors.white38, fontSize: 12)),
          ]),
          const SizedBox(height: 12),
          Container(
            height: 380,
            decoration: BoxDecoration(
              color: const Color(0xFF111827),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: const Color(0xFF1F2937)),
            ),
            child: ws.events.isEmpty
                ? const Center(child: Text('Waiting for live events…', style: TextStyle(color: Colors.white38)))
                : ListView.separated(
                    padding: const EdgeInsets.all(12),
                    itemCount: ws.events.length,
                    separatorBuilder: (_, __) => const Divider(color: Color(0xFF1F2937), height: 1),
                    itemBuilder: (context, i) {
                      final e = ws.events[i];
                      final risk = (e['risk_score'] as num? ?? 0).toDouble();
                      return ListTile(
                        dense: true,
                        leading: _riskDot(risk),
                        title: Text(
                          '${e['src_ip'] ?? '?'} → ${e['threat_type'] ?? '?'}',
                          style: const TextStyle(color: Colors.white, fontSize: 13),
                        ),
                        subtitle: Text(
                          '${e['country'] ?? 'Unknown'} • ${e['action_taken'] ?? '?'}',
                          style: const TextStyle(color: Colors.white38, fontSize: 11),
                        ),
                        trailing: Text(
                          e['detected_at'] != null
                              ? timeago.format(DateTime.parse(e['detected_at'].toString()))
                              : '',
                          style: const TextStyle(color: Colors.white24, fontSize: 10),
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }

  Widget _riskDot(double risk) {
    final color = risk > 0.85 ? Colors.red : risk > 0.5 ? Colors.orange : const Color(0xFF00FF88);
    return Container(
      width: 10, height: 10,
      decoration: BoxDecoration(
        shape: BoxShape.circle, color: color,
        boxShadow: [BoxShadow(color: color.withOpacity(0.5), blurRadius: 4)],
      ),
    );
  }
}

class _NavItem {
  final IconData icon;
  final String label;
  final String path;
  const _NavItem({required this.icon, required this.label, required this.path});
}
