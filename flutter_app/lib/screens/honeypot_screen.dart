import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../core/auth_service.dart';
import '../models/honeypot_model.dart';
import '../widgets/app_shell_drawer.dart';
import '../widgets/glassy_container.dart';

class HoneypotScreen extends StatefulWidget {
  const HoneypotScreen({super.key});

  @override
  State<HoneypotScreen> createState() => _HoneypotScreenState();
}

class _HoneypotScreenState extends State<HoneypotScreen> {
  List<HoneypotModel> _sessions = [];
  bool _loading = true;
  Map<String, dynamic>? _cowrieStatus;
  DateTime? _lastSyncedAt;

  @override
  void initState() {
    super.initState();
    _fetchAll();
  }

  Future<void> _fetchAll() async {
    setState(() => _loading = true);
    try {
      final api = context.read<AuthService>().api;
      final responses = await Future.wait([
        api.get('/honeypot/sessions', params: {'page': 1, 'page_size': 100}),
        api.get('/honeypot/status'),
      ]);
      final sessResp = responses[0];
      final statusResp = responses[1];
      setState(() {
        _sessions = ((sessResp.data as Map)['items'] as List)
            .map((j) => HoneypotModel.fromJson(j))
            .toList();
        _cowrieStatus = statusResp.data as Map<String, dynamic>;
        _loading = false;
        _lastSyncedAt = DateTime.now();
      });
    } catch (_) {
      setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final isAdmin = context.read<AuthService>().isAdmin;
    final status = _cowrieStatus?['status'] as String? ?? '?';
    final theme = Theme.of(context);
    final activeSessions =
        _sessions.where((session) => session.endedAt == null).length;
    final sshSessions =
        _sessions.where((session) => session.honeypotType == 'ssh').length;

    return Scaffold(
      drawer: const AppShellDrawer(),
      appBar: AppBar(
        title: const Text('Honeypot Sessions'),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchAll)
        ],
      ),
      body: _loading
          ? Center(
              child:
                  CircularProgressIndicator(color: theme.colorScheme.primary))
          : RefreshIndicator(
              onRefresh: _fetchAll,
              child: ListView(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                children: [
                  GlassyContainer(
                    margin: const EdgeInsets.only(bottom: 16),
                    padding: const EdgeInsets.all(20),
                    borderRadius: 24,
                    child: Wrap(
                      alignment: WrapAlignment.spaceBetween,
                      runSpacing: 14,
                      spacing: 14,
                      children: [
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Deception surface',
                              style: GoogleFonts.spaceGrotesk(
                                fontSize: 24,
                                fontWeight: FontWeight.w700,
                                color: theme.colorScheme.onSurface,
                              ),
                            ),
                            const SizedBox(height: 8),
                            Text(
                              'Track attacker sessions, credential attempts, and command activity captured by the honeypot services.',
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
                            _pill(theme, 'Status',
                                status == 'running' ? 'Running' : 'Offline',
                                color: status == 'running'
                                    ? theme.colorScheme.primary
                                    : Colors.red),
                            _pill(theme, 'Active', '$activeSessions',
                                color: Colors.purple.shade300),
                            _pill(theme, 'SSH sessions', '$sshSessions',
                                color: Colors.indigo),
                            _pill(
                              theme,
                              'Last sync',
                              _lastSyncedAt == null
                                  ? 'Never'
                                  : timeago.format(_lastSyncedAt!),
                              color: theme.colorScheme.primary,
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  GlassyContainer(
                    margin: const EdgeInsets.only(bottom: 16),
                    padding: const EdgeInsets.all(16),
                    borderRadius: 16,
                    child: Row(
                      children: [
                        Icon(Icons.bug_report_outlined,
                            color: theme.colorScheme.primary, size: 32),
                        const SizedBox(width: 16),
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              'Cowrie SSH Honeypot',
                              style: TextStyle(
                                  color: theme.colorScheme.onSurface,
                                  fontWeight: FontWeight.w600,
                                  fontSize: 16),
                            ),
                            Text(
                              'Status: $status',
                              style: TextStyle(
                                color: status == 'running'
                                    ? theme.colorScheme.primary
                                    : Colors.red,
                                fontSize: 13,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                          ],
                        ),
                        const Spacer(),
                        if (isAdmin) ...[
                          OutlinedButton.icon(
                            icon: const Icon(Icons.play_arrow, size: 16),
                            label: const Text('Start'),
                            style: OutlinedButton.styleFrom(
                              foregroundColor: theme.colorScheme.primary,
                              side:
                                  BorderSide(color: theme.colorScheme.primary),
                            ),
                            onPressed: () async {
                              await context
                                  .read<AuthService>()
                                  .api
                                  .post('/honeypot/start', {});
                              _fetchAll();
                            },
                          ),
                          const SizedBox(width: 8),
                          OutlinedButton.icon(
                            icon: const Icon(Icons.stop, size: 16),
                            label: const Text('Stop'),
                            style: OutlinedButton.styleFrom(
                              foregroundColor: Colors.red,
                              side: const BorderSide(color: Colors.red),
                            ),
                            onPressed: () async {
                              await context
                                  .read<AuthService>()
                                  .api
                                  .post('/honeypot/stop', {});
                              _fetchAll();
                            },
                          ),
                        ],
                      ],
                    ),
                  ),
                  if (_sessions.isEmpty)
                    Padding(
                      padding: const EdgeInsets.only(top: 48),
                      child: Center(
                        child: Text(
                          'No honeypot sessions yet',
                          style: TextStyle(
                              color:
                                  theme.colorScheme.onSurface.withOpacity(0.5)),
                        ),
                      ),
                    )
                  else
                    ...List.generate(_sessions.length, (i) {
                      final session = _sessions[i];
                      return Padding(
                        padding: EdgeInsets.only(
                            bottom: i == _sessions.length - 1 ? 0 : 8),
                        child: GlassyContainer(
                          borderRadius: 18,
                          child: ExpansionTile(
                            backgroundColor: Colors.transparent,
                            collapsedBackgroundColor: Colors.transparent,
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(18),
                            ),
                            collapsedShape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(18),
                            ),
                            leading: Icon(
                              session.honeypotType == 'ssh'
                                  ? Icons.terminal
                                  : Icons.language,
                              color: Colors.purple.shade300,
                            ),
                            title: Text(
                              session.attackerIp,
                              style: TextStyle(
                                color: theme.colorScheme.onSurface,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                            subtitle: Text(
                              '${session.country ?? "Unknown"} - ${timeago.format(session.startedAt)}',
                              style: TextStyle(
                                  color: theme.colorScheme.onSurface
                                      .withOpacity(0.6),
                                  fontSize: 12),
                            ),
                            trailing: Container(
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 8, vertical: 4),
                              decoration: BoxDecoration(
                                color: Colors.purple.shade300.withOpacity(0.1),
                                borderRadius: BorderRadius.circular(6),
                                border: Border.all(
                                    color: Colors.purple.shade300
                                        .withOpacity(0.5)),
                              ),
                              child: Text(
                                session.honeypotType.toUpperCase(),
                                style: TextStyle(
                                  color: Colors.purple.shade300,
                                  fontSize: 10,
                                  fontWeight: FontWeight.w800,
                                ),
                              ),
                            ),
                            children: [
                              Padding(
                                padding: const EdgeInsets.all(16),
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Divider(color: theme.dividerColor),
                                    const SizedBox(height: 8),
                                    if (session.usernameTried != null)
                                      _infoRow('Username',
                                          session.usernameTried!, theme),
                                    if (session.passwordTried != null)
                                      _infoRow('Password',
                                          session.passwordTried!, theme),
                                    if (session.commandsRun != null)
                                      _infoRow('Commands', session.commandsRun!,
                                          theme),
                                    if (session.durationSeconds != null)
                                      _infoRow(
                                          'Duration',
                                          '${session.durationSeconds!.toStringAsFixed(1)}s',
                                          theme),
                                    _infoRow(
                                      'Status',
                                      session.endedAt == null
                                          ? 'Active session'
                                          : 'Closed ${timeago.format(session.endedAt!)}',
                                      theme,
                                    ),
                                  ],
                                ),
                              ),
                            ],
                          ),
                        ),
                      );
                    }),
                ],
              ),
            ),
    );
  }

  Widget _pill(ThemeData theme, String label, String value,
      {required Color color}) {
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

  Widget _infoRow(String label, String value, ThemeData theme) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 80,
            child: Text(label,
                style: TextStyle(
                    color: theme.colorScheme.onSurface.withOpacity(0.5),
                    fontSize: 12)),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                color: theme.colorScheme.onSurface.withOpacity(0.9),
                fontSize: 12,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ],
      ),
    );
  }
}
