import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../core/auth_service.dart';
import '../models/firewall_rule_model.dart';
import '../widgets/app_shell_drawer.dart';
import '../widgets/glassy_container.dart';

class FirewallScreen extends StatefulWidget {
  const FirewallScreen({super.key});

  @override
  State<FirewallScreen> createState() => _FirewallScreenState();
}

class _FirewallScreenState extends State<FirewallScreen> {
  List<FirewallRuleModel> _rules = [];
  Map<String, dynamic>? _status;
  bool _loading = true;
  String? _error;
  DateTime? _lastSyncedAt;

  @override
  void initState() {
    super.initState();
    _fetchRules();
  }

  Future<void> _fetchRules() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final api = context.read<AuthService>().api;
      final responses = await Future.wait([
        api.get('/firewall/rules'),
        api.get('/firewall/status'),
      ]);
      setState(() {
        _rules = (responses[0].data as List)
            .map((item) =>
                FirewallRuleModel.fromJson(item as Map<String, dynamic>))
            .toList();
        _status = responses[1].data as Map<String, dynamic>;
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

  Future<void> _deleteRule(String ruleId) async {
    try {
      final api = context.read<AuthService>().api;
      await api.delete('/firewall/rules/$ruleId');
      _fetchRules();
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Error: $e'), backgroundColor: Colors.red),
      );
    }
  }

  Future<void> _emergencyFlush() async {
    final theme = Theme.of(context);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: theme.dialogBackgroundColor,
        title: Text(
          'Emergency Flush',
          style: GoogleFonts.inter(
            color: Colors.red,
            fontWeight: FontWeight.w700,
          ),
        ),
        content: Text(
          'This will remove all dynamic firewall rules. Continue?',
          style: TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.8)),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () => Navigator.pop(context, true),
            child: const Text(
              'Flush all',
              style: TextStyle(color: Colors.white),
            ),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      try {
        final api = context.read<AuthService>().api;
        await api.post('/firewall/flush', {});
        _fetchRules();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: const Text('All rules flushed'),
              backgroundColor: Theme.of(context).colorScheme.primary,
            ),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Error: $e'), backgroundColor: Colors.red),
          );
        }
      }
    }
  }

  Color _ruleColor(String type) {
    return switch (type) {
      'block' => Colors.red,
      'rate_limit' => Colors.orange,
      'redirect' => Colors.blue,
      _ => Colors.grey,
    };
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final isAdmin = context.read<AuthService>().isAdmin;
    final mode = _status?['mode']?.toString() ?? 'unknown';
    final reason = _status?['reason']?.toString();
    final containment = _status?['containment'] as Map<String, dynamic>?;
    final attempted = containment?['attempted'] as Map<String, dynamic>?;
    final blockCount = _rules.where((rule) => rule.ruleType == 'block').length;
    final redirectCount =
        _rules.where((rule) => rule.ruleType == 'redirect').length;
    final rateLimitCount =
        _rules.where((rule) => rule.ruleType == 'rate_limit').length;

    return Scaffold(
      drawer: const AppShellDrawer(),
      appBar: AppBar(
        title: Text('Firewall Rules (${_rules.length})'),
        actions: [
          if (isAdmin)
            IconButton(
              icon: const Icon(Icons.warning_amber, color: Colors.red),
              tooltip: 'Emergency Flush',
              onPressed: _emergencyFlush,
            ),
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchRules),
        ],
      ),
      body: _loading
          ? Center(
              child:
                  CircularProgressIndicator(color: theme.colorScheme.primary))
          : _error != null
              ? Center(
                  child:
                      Text(_error!, style: const TextStyle(color: Colors.red)))
              : RefreshIndicator(
                  onRefresh: _fetchRules,
                  child: ListView(
                    padding: const EdgeInsets.all(16),
                    children: [
                      _statusBanner(theme, mode, reason),
                      const SizedBox(height: 16),
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
                                  'Containment controls',
                                  style: GoogleFonts.spaceGrotesk(
                                    fontSize: 24,
                                    fontWeight: FontWeight.w700,
                                    color: theme.colorScheme.onSurface,
                                  ),
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  'This page shows what the firewall can actually enforce, what it is only simulating, and which live containment rules are active.',
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
                                _summaryPill(theme, 'Blocks', '$blockCount',
                                    color: Colors.red),
                                _summaryPill(theme, 'Active redirects', '$redirectCount',
                                    color: Colors.blue),
                                _summaryPill(
                                    theme, 'Active rate limits', '$rateLimitCount',
                                    color: Colors.orange),
                                _summaryPill(
                                  theme,
                                  'Mode',
                                  mode[0].toUpperCase() + mode.substring(1),
                                  color: mode == 'enforcing'
                                      ? theme.colorScheme.primary
                                      : mode == 'simulation'
                                          ? Colors.orange
                                          : Colors.red,
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 12),
                      GlassyContainer(
                        borderRadius: 22,
                        padding: const EdgeInsets.all(16),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Wrap(
                              spacing: 10,
                              runSpacing: 10,
                              children: [
                                _metaChip(theme, 'Block = drop all traffic'),
                                _metaChip(theme, 'Redirect = send source to honeypot'),
                                _metaChip(theme, 'Rate limit = slow noisy traffic'),
                                _metaChip(
                                  theme,
                                  'Attempts can increase even when active rules stay at zero.',
                                ),
                                _metaChip(
                                  theme,
                                  _lastSyncedAt == null
                                      ? 'Last sync: never'
                                      : 'Last sync: ${timeago.format(_lastSyncedAt!)}',
                                ),
                              ],
                            ),
                            const SizedBox(height: 14),
                            Wrap(
                              spacing: 10,
                              runSpacing: 10,
                              children: [
                                _summaryPill(
                                  theme,
                                  'Attempted redirects',
                                  '${_toInt(attempted?['honeypot'])}',
                                  color: Colors.blue,
                                ),
                                _summaryPill(
                                  theme,
                                  'Attempted blocks',
                                  '${_toInt(attempted?['block'])}',
                                  color: Colors.red,
                                ),
                                _summaryPill(
                                  theme,
                                  'Attempted throttles',
                                  '${_toInt(attempted?['rate_limit'])}',
                                  color: Colors.orange,
                                ),
                                _summaryPill(
                                  theme,
                                  'Observed only',
                                  '${_toInt(attempted?['log'])}',
                                  color: theme.colorScheme.primary,
                                ),
                              ],
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 16),
                      if (_rules.isEmpty)
                        Padding(
                          padding: const EdgeInsets.only(top: 48),
                          child: Center(
                            child: Column(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Text(
                                  mode == 'simulation'
                                      ? 'Firewall is currently simulating response'
                                      : mode == 'degraded'
                                          ? 'Firewall enforcement is currently degraded'
                                          : 'No active containment rules right now',
                                  style: TextStyle(
                                    color: theme.colorScheme.onSurface
                                        .withOpacity(0.6),
                                  ),
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  reason ??
                                      'No hostile source currently requires an active firewall rule.',
                                  textAlign: TextAlign.center,
                                  style: TextStyle(
                                    color: theme.colorScheme.onSurface
                                        .withOpacity(0.45),
                                    fontSize: 12,
                                    height: 1.5,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        )
                      else
                        ...List.generate(_rules.length, (i) {
                          final rule = _rules[i];
                          final color = _ruleColor(rule.ruleType);
                          return Padding(
                            padding: EdgeInsets.only(
                                bottom: i == _rules.length - 1 ? 0 : 8),
                            child: GlassyContainer(
                              padding: const EdgeInsets.all(16),
                              borderRadius: 18,
                              child: Row(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Container(
                                    padding: const EdgeInsets.symmetric(
                                        horizontal: 10, vertical: 4),
                                    decoration: BoxDecoration(
                                      color: color
                                          .withOpacity(isDark ? 0.15 : 0.1),
                                      borderRadius: BorderRadius.circular(999),
                                      border: Border.all(
                                          color: color.withOpacity(0.5)),
                                    ),
                                    child: Text(
                                      rule.ruleType.toUpperCase(),
                                      style: TextStyle(
                                        color: color,
                                        fontSize: 10,
                                        fontWeight: FontWeight.w700,
                                      ),
                                    ),
                                  ),
                                  const SizedBox(width: 12),
                                  Expanded(
                                    child: Column(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Text(
                                          rule.targetIp,
                                          style: TextStyle(
                                            color: theme.colorScheme.onSurface,
                                            fontWeight: FontWeight.w700,
                                          ),
                                        ),
                                        const SizedBox(height: 4),
                                        Text(
                                          rule.reason ??
                                              'No reason attached to this rule.',
                                          style: TextStyle(
                                            color: theme.colorScheme.onSurface
                                                .withOpacity(0.62),
                                            fontSize: 12,
                                            height: 1.4,
                                          ),
                                        ),
                                        const SizedBox(height: 10),
                                        Wrap(
                                          spacing: 10,
                                          runSpacing: 8,
                                          children: [
                                            _metaChip(theme,
                                                'Created ${timeago.format(rule.createdAt)}'),
                                            if (rule.protocol != null)
                                              _metaChip(theme,
                                                  rule.protocol!.toUpperCase()),
                                            if (rule.targetPort != null)
                                              _metaChip(theme,
                                                  'Port ${rule.targetPort}'),
                                            if (rule.expiresAt != null)
                                              _metaChip(
                                                theme,
                                                rule.isExpired
                                                    ? 'Expired'
                                                    : 'Expires ${timeago.format(rule.expiresAt!)}',
                                              ),
                                          ],
                                        ),
                                      ],
                                    ),
                                  ),
                                  if (isAdmin)
                                    IconButton(
                                      icon: const Icon(Icons.delete_outline,
                                          color: Colors.red, size: 20),
                                      onPressed: () => _deleteRule(rule.id),
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

  Widget _statusBanner(ThemeData theme, String mode, String? reason) {
    final color = mode == 'enforcing'
        ? theme.colorScheme.primary
        : mode == 'simulation'
            ? Colors.orange
            : Colors.red;
    final title = mode == 'enforcing'
        ? 'Firewall enforcement active'
        : mode == 'simulation'
            ? 'Firewall in simulation mode'
            : 'Firewall enforcement degraded';
    return GlassyContainer(
      borderRadius: 22,
      padding: const EdgeInsets.all(18),
      color: color.withOpacity(0.08),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.security_outlined, color: color, size: 28),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: GoogleFonts.spaceGrotesk(
                    color: theme.colorScheme.onSurface,
                    fontWeight: FontWeight.w700,
                    fontSize: 18,
                  ),
                ),
                const SizedBox(height: 6),
                Text(
                  reason ??
                      'Dynamic containment rules are being applied automatically when needed.',
                  style: TextStyle(
                    color: theme.colorScheme.onSurface.withOpacity(0.65),
                    height: 1.5,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _summaryPill(ThemeData theme, String label, String value,
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
                color: color, fontWeight: FontWeight.w700),
          ),
        ],
      ),
    );
  }

  Widget _metaChip(ThemeData theme, String label) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: theme.colorScheme.primary.withOpacity(0.08),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: theme.colorScheme.onSurface.withOpacity(0.68),
          fontSize: 11,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }

  int _toInt(dynamic value) {
    if (value is int) return value;
    if (value is num) return value.toInt();
    return 0;
  }
}
