import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:timeago/timeago.dart' as timeago;
import 'dart:convert';

import '../core/auth_service.dart';
import '../core/websocket_service.dart';
import '../models/honeypot_model.dart';
import '../widgets/app_shell_drawer.dart';
import '../widgets/glassy_container.dart';

class HoneypotScreen extends StatefulWidget {
  const HoneypotScreen({super.key});

  @override
  State<HoneypotScreen> createState() => _HoneypotScreenState();
}

class _HoneypotScreenState extends State<HoneypotScreen>
    with SingleTickerProviderStateMixin {
  List<HoneypotModel> _sessions = [];
  List<Map<String, dynamic>> _multiSessions = [];
  List<Map<String, dynamic>> _activeHoneypots = [];
  Map<String, dynamic>? _status;
  bool _loading = true;
  DateTime? _lastSyncedAt;
  VoidCallback? _wsListener;
  late TabController _tabController;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _fetchAll();
      _listenToWs();
    });
  }

  @override
  void dispose() {
    _tabController.dispose();
    final listener = _wsListener;
    if (listener != null) {
      context.read<WebSocketService>().removeListener(listener);
    }
    super.dispose();
  }

  Future<void> _fetchAll() async {
    setState(() => _loading = true);
    try {
      final api = context.read<AuthService>().api;
      final responses = await Future.wait([
        api.get('/honeypot/sessions', params: {'page': 1, 'page_size': 100}),
        api.get('/honeypot/status'),
        api.get('/honeypot/active'),
        api.get('/honeypot/multi/sessions', params: {'limit': 200}),
      ]);
      setState(() {
        _sessions = ((responses[0].data as Map)['items'] as List)
            .map((j) => HoneypotModel.fromJson(j))
            .toList();
        _status = responses[1].data as Map<String, dynamic>;
        _activeHoneypots = List<Map<String, dynamic>>.from(
            (responses[2].data as Map)['honeypots'] ?? []);
        _multiSessions = List<Map<String, dynamic>>.from(
            (responses[3].data as Map)['sessions'] ?? []);
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
      if (latest['type'] == 'honeypot_session') {
        final session = HoneypotModel.fromJson(latest);
        final idx = _sessions.indexWhere((s) => s.sessionId == session.sessionId);
        setState(() {
          if (idx >= 0) _sessions[idx] = session;
          else _sessions = [session, ..._sessions];
          _lastSyncedAt = DateTime.now();
        });
      }
    };
    ws.addListener(_wsListener!);
  }

  @override
  Widget build(BuildContext context) {
    final isAdmin = context.read<AuthService>().isAdmin;
    final theme = Theme.of(context);
    final cowrieStatus = _status?['status'] as String? ?? '?';
    final multiInfo = _status?['multi_honeypots'] as Map<String, dynamic>? ?? {};
    final activePorts = multiInfo['total_active'] as int? ?? _activeHoneypots.length;
    final multiTotal = multiInfo['total_sessions'] as int? ?? 0;
    final byProto = multiInfo['sessions_by_protocol'] as Map<String, dynamic>? ?? {};

    return Scaffold(
      drawer: const AppShellDrawer(),
      appBar: AppBar(
        title: const Text('Honeypot Center'),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchAll),
        ],
        bottom: TabBar(
          controller: _tabController,
          tabs: const [
            Tab(text: 'Overview'),
            Tab(text: 'SSH / Cowrie'),
            Tab(text: 'Multi-Protocol'),
          ],
        ),
      ),
      body: _loading
          ? Center(child: CircularProgressIndicator(color: theme.colorScheme.primary))
          : TabBarView(
              controller: _tabController,
              children: [
                _buildOverview(theme, cowrieStatus, activePorts, multiTotal, byProto, isAdmin),
                _buildCowrieSessions(theme),
                _buildMultiSessions(theme, isAdmin),
              ],
            ),
    );
  }

  // ── Tab 1: Overview ────────────────────────────────────────────────────────

  Widget _buildOverview(ThemeData theme, String cowrieStatus, int activePorts,
      int multiTotal, Map<String, dynamic> byProto, bool isAdmin) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Header card
        GlassyContainer(
          padding: const EdgeInsets.all(20),
          borderRadius: 24,
          margin: const EdgeInsets.only(bottom: 16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Deception Surface',
                  style: GoogleFonts.spaceGrotesk(
                      fontSize: 22, fontWeight: FontWeight.w700)),
              const SizedBox(height: 6),
              Text(
                'All active honeypots lure, trap, and log attacker activity in real-time. '
                'Any attacked port is automatically covered.',
                style: TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.6), height: 1.5),
              ),
              const SizedBox(height: 16),
              Wrap(spacing: 10, runSpacing: 10, children: [
                _pill(theme, 'Cowrie SSH',
                    cowrieStatus == 'running' ? 'Running' : 'Offline',
                    color: cowrieStatus == 'running' ? Colors.green : Colors.red),
                _pill(theme, 'Active Honeypots', '$activePorts',
                    color: theme.colorScheme.primary),
                _pill(theme, 'Multi-Protocol Sessions', '$multiTotal',
                    color: Colors.orange),
                _pill(theme, 'Cowrie Sessions', '${_sessions.length}',
                    color: Colors.purple),
                _pill(theme, 'Last sync',
                    _lastSyncedAt == null ? 'Never' : timeago.format(_lastSyncedAt!),
                    color: theme.colorScheme.primary),
              ]),
            ],
          ),
        ),

        // Cowrie control
        GlassyContainer(
          padding: const EdgeInsets.all(16),
          borderRadius: 16,
          margin: const EdgeInsets.only(bottom: 16),
          child: Row(
            children: [
              Icon(Icons.terminal, color: Colors.purple.shade300, size: 32),
              const SizedBox(width: 16),
              Expanded(
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text('Cowrie SSH Honeypot',
                      style: TextStyle(fontWeight: FontWeight.w700, fontSize: 16)),
                  Text('Port 30022 · Status: $cowrieStatus',
                      style: TextStyle(
                          color: cowrieStatus == 'running' ? Colors.green : Colors.red,
                          fontSize: 13)),
                ]),
              ),
              if (isAdmin) ...[
                OutlinedButton.icon(
                  icon: const Icon(Icons.play_arrow, size: 16),
                  label: const Text('Start'),
                  style: OutlinedButton.styleFrom(foregroundColor: Colors.green,
                      side: const BorderSide(color: Colors.green)),
                  onPressed: () async {
                    await context.read<AuthService>().api.post('/honeypot/start', {});
                    _fetchAll();
                  },
                ),
                const SizedBox(width: 8),
                OutlinedButton.icon(
                  icon: const Icon(Icons.stop, size: 16),
                  label: const Text('Stop'),
                  style: OutlinedButton.styleFrom(foregroundColor: Colors.red,
                      side: const BorderSide(color: Colors.red)),
                  onPressed: () async {
                    await context.read<AuthService>().api.post('/honeypot/stop', {});
                    _fetchAll();
                  },
                ),
              ],
            ],
          ),
        ),

        // Active honeypots grid
        if (_activeHoneypots.isNotEmpty) ...[
          Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: Text('Active Multi-Protocol Honeypots',
                style: GoogleFonts.spaceGrotesk(fontWeight: FontWeight.w700, fontSize: 16)),
          ),
          GridView.builder(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            gridDelegate: const SliverGridDelegateWithMaxCrossAxisExtent(
              maxCrossAxisExtent: 180,
              childAspectRatio: 1.6,
              crossAxisSpacing: 10,
              mainAxisSpacing: 10,
            ),
            itemCount: _activeHoneypots.length,
            itemBuilder: (ctx, i) {
              final hp = _activeHoneypots[i];
              final port = hp['port'] as int;
              final proto = (hp['protocol'] as String? ?? 'tcp').toUpperCase();
              final sessions = byProto[(hp['protocol'] as String?) ?? ''] as int? ?? 0;
              return GlassyContainer(
                padding: const EdgeInsets.all(12),
                borderRadius: 14,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Row(children: [
                      Container(width: 8, height: 8,
                          decoration: const BoxDecoration(
                              color: Colors.green, shape: BoxShape.circle)),
                      const SizedBox(width: 6),
                      Text('Port $port',
                          style: GoogleFonts.spaceGrotesk(
                              fontWeight: FontWeight.w700, fontSize: 13)),
                    ]),
                    const SizedBox(height: 4),
                    Text(proto, style: TextStyle(
                        color: theme.colorScheme.primary,
                        fontWeight: FontWeight.w600, fontSize: 12)),
                    Text('$sessions sessions',
                        style: TextStyle(
                            color: theme.colorScheme.onSurface.withOpacity(0.5),
                            fontSize: 11)),
                  ],
                ),
              );
            },
          ),
          const SizedBox(height: 16),
        ] else
          GlassyContainer(
            padding: const EdgeInsets.all(20),
            borderRadius: 16,
            margin: const EdgeInsets.only(bottom: 16),
            child: Row(children: [
              Icon(Icons.info_outline, color: theme.colorScheme.primary),
              const SizedBox(width: 12),
              Expanded(child: Text(
                'No multi-protocol honeypots active yet. They auto-deploy when an attack is detected on any port.',
                style: TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.7)),
              )),
            ]),
          ),

        // Protocol breakdown
        if (byProto.isNotEmpty) ...[
          Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: Text('Sessions by Protocol',
                style: GoogleFonts.spaceGrotesk(fontWeight: FontWeight.w700, fontSize: 16)),
          ),
          GlassyContainer(
            padding: const EdgeInsets.all(16),
            borderRadius: 16,
            child: Column(
              children: byProto.entries.map((e) => Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Row(children: [
                  Text(e.key.toUpperCase(),
                      style: TextStyle(
                          color: theme.colorScheme.primary,
                          fontWeight: FontWeight.w700, fontSize: 13)),
                  const Spacer(),
                  Text('${e.value} sessions',
                      style: TextStyle(
                          color: theme.colorScheme.onSurface.withOpacity(0.7))),
                ]),
              )).toList(),
            ),
          ),
        ],
      ],
    );
  }

  // ── Tab 2: Cowrie SSH sessions ─────────────────────────────────────────────

  Widget _buildCowrieSessions(ThemeData theme) {
    if (_sessions.isEmpty) {
      return Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Icon(Icons.terminal, size: 48, color: theme.colorScheme.onSurface.withOpacity(0.3)),
          const SizedBox(height: 12),
          Text('No Cowrie sessions yet',
              style: TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.5))),
          const SizedBox(height: 6),
          Text('SSH to port 30022 to trigger a session',
              style: TextStyle(
                  fontSize: 12, color: theme.colorScheme.onSurface.withOpacity(0.35))),
        ]),
      );
    }
    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: _sessions.length,
      itemBuilder: (ctx, i) {
        final session = _sessions[i];
        return Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: GlassyContainer(
            borderRadius: 18,
            child: ExpansionTile(
              backgroundColor: Colors.transparent,
              collapsedBackgroundColor: Colors.transparent,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
              collapsedShape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
              leading: Icon(Icons.terminal, color: Colors.purple.shade300),
              title: Text(session.attackerIp,
                  style: TextStyle(fontWeight: FontWeight.w600)),
              subtitle: Text(
                  session.endedAt == null
                      ? 'Active now'
                      : 'Ended ${timeago.format(session.endedAt!)}',
                  style: TextStyle(
                      color: theme.colorScheme.onSurface.withOpacity(0.55), fontSize: 12)),
              trailing: _typeBadge('SSH', Colors.purple.shade300),
              children: [
                Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Divider(color: theme.dividerColor),
                    const SizedBox(height: 8),
                    if (session.usernameTried != null)
                      _infoRow('Username', session.usernameTried!, theme),
                    if (session.passwordTried != null)
                      _infoRow('Password', session.passwordTried!, theme),
                    if (session.victimIp != null)
                      _infoRow('Target',
                          session.victimPort != null
                              ? '${session.victimIp}:${session.victimPort}'
                              : session.victimIp!,
                          theme),
                    if (session.commandsRun != null)
                      _infoRow('Commands', _formatCommands(session.commandsRun!), theme),
                    if (session.durationSeconds != null)
                      _infoRow('Duration', '${session.durationSeconds!.toStringAsFixed(1)}s', theme),
                    if (session.org != null) _infoRow('Org', session.org!, theme),
                    if (session.country != null) _infoRow('Country', session.country!, theme),
                  ]),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  // ── Tab 3: Multi-Protocol sessions ─────────────────────────────────────────

  Widget _buildMultiSessions(ThemeData theme, bool isAdmin) {
    return Column(children: [
      if (isAdmin)
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
          child: GlassyContainer(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            borderRadius: 14,
            child: Row(children: [
              Icon(Icons.add_circle_outline, color: theme.colorScheme.primary, size: 20),
              const SizedBox(width: 10),
              Text('Tap a port below or attacks auto-deploy honeypots',
                  style: TextStyle(
                      color: theme.colorScheme.onSurface.withOpacity(0.65), fontSize: 13)),
            ]),
          ),
        ),
      Expanded(
        child: _multiSessions.isEmpty
            ? Center(
                child: Column(mainAxisSize: MainAxisSize.min, children: [
                  Icon(Icons.shield_outlined, size: 48,
                      color: theme.colorScheme.onSurface.withOpacity(0.3)),
                  const SizedBox(height: 12),
                  Text('No multi-protocol sessions yet',
                      style: TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.5))),
                  const SizedBox(height: 6),
                  Text('Honeypots auto-deploy when any port is attacked',
                      style: TextStyle(
                          fontSize: 12,
                          color: theme.colorScheme.onSurface.withOpacity(0.35))),
                ]),
              )
            : ListView.builder(
                padding: const EdgeInsets.all(16),
                itemCount: _multiSessions.length,
                itemBuilder: (ctx, i) {
                  final s = _multiSessions[_multiSessions.length - 1 - i];
                  final proto = s['protocol'] as String? ?? 'tcp';
                  final ip = s['attacker_ip'] as String? ?? '?';
                  final port = s['honeypot_port'] as int? ?? 0;
                  final data = s['data_received'] as String? ?? '';
                  final connected = s['connected_at'] as String? ?? '';
                  final duration = s['duration_seconds'] as num? ?? 0;
                  return Padding(
                    padding: const EdgeInsets.only(bottom: 8),
                    child: GlassyContainer(
                      borderRadius: 16,
                      child: ExpansionTile(
                        backgroundColor: Colors.transparent,
                        collapsedBackgroundColor: Colors.transparent,
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                        collapsedShape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                        leading: Icon(_protoIcon(proto), color: _protoColor(proto)),
                        title: Text(ip, style: TextStyle(fontWeight: FontWeight.w600)),
                        subtitle: Text('Port $port · ${duration.toStringAsFixed(1)}s',
                            style: TextStyle(
                                color: theme.colorScheme.onSurface.withOpacity(0.55),
                                fontSize: 12)),
                        trailing: _typeBadge(proto.toUpperCase(), _protoColor(proto)),
                        children: [
                          Padding(
                            padding: const EdgeInsets.all(16),
                            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                              Divider(color: theme.dividerColor),
                              const SizedBox(height: 8),
                              _infoRow('IP', ip, theme),
                              _infoRow('Port', '$port', theme),
                              _infoRow('Protocol', proto.toUpperCase(), theme),
                              _infoRow('Connected', connected, theme),
                              _infoRow('Duration', '${duration.toStringAsFixed(2)}s', theme),
                              if (data.isNotEmpty)
                                _infoRow('Data captured', data.length > 300 ? '${data.substring(0, 300)}…' : data, theme),
                              if (s['credentials_captured'] == true)
                                Padding(
                                  padding: const EdgeInsets.only(top: 6),
                                  child: Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                                    decoration: BoxDecoration(
                                      color: Colors.red.withOpacity(0.1),
                                      borderRadius: BorderRadius.circular(8),
                                      border: Border.all(color: Colors.red.withOpacity(0.4)),
                                    ),
                                    child: const Text('⚠ Credentials captured',
                                        style: TextStyle(color: Colors.red, fontWeight: FontWeight.w700, fontSize: 12)),
                                  ),
                                ),
                            ]),
                          ),
                        ],
                      ),
                    ),
                  );
                },
              ),
      ),
    ]);
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  Widget _pill(ThemeData theme, String label, String value, {required Color color}) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
          color: color.withOpacity(0.10), borderRadius: BorderRadius.circular(999)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(label,
            style: TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.55),
                fontSize: 11, fontWeight: FontWeight.w600)),
        const SizedBox(height: 2),
        Text(value,
            style: GoogleFonts.spaceGrotesk(color: color, fontWeight: FontWeight.w700)),
      ]),
    );
  }

  Widget _typeBadge(String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withOpacity(0.5)),
      ),
      child: Text(label,
          style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.w800)),
    );
  }

  Widget _infoRow(String label, String value, ThemeData theme) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        SizedBox(
            width: 80,
            child: Text(label,
                style: TextStyle(
                    color: theme.colorScheme.onSurface.withOpacity(0.5), fontSize: 12))),
        Expanded(
            child: Text(value,
                style: TextStyle(
                    color: theme.colorScheme.onSurface.withOpacity(0.9),
                    fontSize: 12, fontFamily: 'monospace'))),
      ]),
    );
  }

  String _formatCommands(String raw) {
    try {
      final decoded = jsonDecode(raw);
      if (decoded is List) return decoded.map((e) => e.toString()).join('\n');
      if (decoded is Map) return decoded.entries.map((e) => '${e.key}: ${e.value}').join('\n');
    } catch (_) {}
    return raw;
  }

  IconData _protoIcon(String proto) {
    switch (proto) {
      case 'http': case 'https': case 'http-alt': return Icons.language;
      case 'ftp': return Icons.folder_open;
      case 'telnet': case 'ssh': return Icons.terminal;
      case 'mysql': case 'postgres': case 'mssql': return Icons.storage;
      case 'rdp': return Icons.desktop_windows;
      case 'smb': return Icons.share;
      case 'redis': case 'mongodb': return Icons.dns;
      case 'vnc': return Icons.screen_share;
      default: return Icons.electrical_services;
    }
  }

  Color _protoColor(String proto) {
    switch (proto) {
      case 'http': case 'https': case 'http-alt': return Colors.blue;
      case 'ftp': return Colors.orange;
      case 'ssh': case 'telnet': return Colors.purple;
      case 'mysql': case 'postgres': case 'mssql': return Colors.teal;
      case 'rdp': return Colors.indigo;
      case 'smb': return Colors.brown;
      case 'redis': return Colors.red;
      case 'mongodb': return Colors.green;
      default: return Colors.grey;
    }
  }
}
