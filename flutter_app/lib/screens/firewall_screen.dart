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

class _FirewallScreenState extends State<FirewallScreen>
    with SingleTickerProviderStateMixin {
  List<FirewallRuleModel> _activeRules = [];
  List<FirewallRuleModel> _allRules = [];
  Map<String, dynamic>? _status;
  bool _loadingActive = true;
  bool _loadingHistory = true;
  String? _error;
  String _query = '';
  DateTime? _lastSyncedAt;
  late TabController _tabController;
  int _historyTotal = 0;
  int _historyPage = 1;
  final int _historyPageSize = 50;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _fetchAll();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _fetchAll() async {
    await Future.wait([_fetchActiveRules(), _fetchHistory()]);
  }

  Future<void> _fetchActiveRules() async {
    setState(() {
      _loadingActive = true;
      _error = null;
    });
    try {
      final api = context.read<AuthService>().api;
      final responses = await Future.wait([
        api.get('/firewall/rules'),
        api.get('/firewall/status'),
      ]);
      setState(() {
        _activeRules = (responses[0].data as List)
            .map((item) =>
                FirewallRuleModel.fromJson(item as Map<String, dynamic>))
            .toList();
        _status = responses[1].data as Map<String, dynamic>;
        _loadingActive = false;
        _lastSyncedAt = DateTime.now();
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _loadingActive = false;
      });
    }
  }

  Future<void> _fetchHistory({int page = 1}) async {
    setState(() => _loadingHistory = true);
    try {
      final api = context.read<AuthService>().api;
      final resp = await api.get('/firewall/rules/history', params: {
        'page': page,
        'page_size': _historyPageSize,
      });
      final data = resp.data as Map<String, dynamic>;
      setState(() {
        _allRules = (data['items'] as List)
            .map((item) =>
                FirewallRuleModel.fromJson(item as Map<String, dynamic>))
            .toList();
        _historyTotal = data['total'] ?? 0;
        _historyPage = page;
        _loadingHistory = false;
      });
    } catch (e) {
      setState(() => _loadingHistory = false);
    }
  }

  Future<void> _showAddRuleDialog() async {
    final ipCtrl = TextEditingController();
    final portCtrl = TextEditingController();
    final reasonCtrl = TextEditingController();
    String ruleType = 'block';
    final created = await showDialog<bool>(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: const Text('Add Firewall Rule'),
          content: SizedBox(
            width: 420,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                DropdownButtonFormField<String>(
                  value: ruleType,
                  decoration: const InputDecoration(labelText: 'Action'),
                  items: const [
                    DropdownMenuItem(value: 'block', child: Text('Block')),
                    DropdownMenuItem(
                        value: 'rate_limit', child: Text('Rate limit')),
                    DropdownMenuItem(
                        value: 'redirect', child: Text('Redirect to honeypot')),
                  ],
                  onChanged: (value) =>
                      setDialogState(() => ruleType = value ?? 'block'),
                ),
                TextField(
                  controller: ipCtrl,
                  decoration: const InputDecoration(labelText: 'Target IP'),
                ),
                TextField(
                  controller: portCtrl,
                  keyboardType: TextInputType.number,
                  decoration: InputDecoration(
                    labelText: ruleType == 'redirect'
                        ? 'Original destination port'
                        : 'Target port optional',
                  ),
                ),
                TextField(
                  controller: reasonCtrl,
                  decoration: const InputDecoration(labelText: 'Reason'),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('Cancel')),
            FilledButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('Create')),
          ],
        ),
      ),
    );
    if (created != true) return;
    try {
      final data = {
        'rule_type': ruleType,
        'target_ip': ipCtrl.text.trim(),
        if (portCtrl.text.trim().isNotEmpty)
          'target_port': int.tryParse(portCtrl.text.trim()),
        if (reasonCtrl.text.trim().isNotEmpty) 'reason': reasonCtrl.text.trim(),
      };
      await context.read<AuthService>().api.post('/firewall/rules', data);
      await _fetchAll();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
            content: Text('Firewall rule added'),
            backgroundColor: Colors.green),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
            content: Text('Add rule failed: $e'), backgroundColor: Colors.red),
      );
    }
  }

  Future<void> _deleteRule(String ruleId) async {
    try {
      final api = context.read<AuthService>().api;
      await api.delete('/firewall/rules/$ruleId');
      _fetchAll();
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
        _fetchAll();
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

  List<FirewallRuleModel> _filterRules(List<FirewallRuleModel> rules) {
    if (_query.trim().isEmpty) return rules;
    final q = _query.trim().toLowerCase();
    return rules.where((rule) {
      return [
        rule.targetIp,
        rule.matchDstIp,
        rule.ruleType,
        rule.reason,
        rule.protocol,
        rule.createdBy,
      ].whereType<String>().any((value) => value.toLowerCase().contains(q));
    }).toList();
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
    final blockCount =
        _activeRules.where((rule) => rule.ruleType == 'block').length;
    final redirectCount =
        _activeRules.where((rule) => rule.ruleType == 'redirect').length;
    final rateLimitCount =
        _activeRules.where((rule) => rule.ruleType == 'rate_limit').length;
    final totalHistoryRules = _status?['total_rules_seen'] ?? _historyTotal;

    return Scaffold(
      drawer: const AppShellDrawer(),
      appBar: AppBar(
        title: Text(
            'Firewall (${_activeRules.length} active, $totalHistoryRules total)'),
        actions: [
          if (isAdmin)
            IconButton(
              icon: const Icon(Icons.add_circle_outline),
              tooltip: 'Add rule',
              onPressed: _showAddRuleDialog,
            ),
          if (isAdmin)
            IconButton(
              icon: const Icon(Icons.warning_amber, color: Colors.red),
              tooltip: 'Emergency Flush',
              onPressed: _emergencyFlush,
            ),
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchAll),
        ],
        bottom: TabBar(
          controller: _tabController,
          tabs: [
            Tab(
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(Icons.shield_outlined, size: 16),
                  const SizedBox(width: 6),
                  Text('Active (${_activeRules.length})'),
                ],
              ),
            ),
            Tab(
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(Icons.history, size: 16),
                  const SizedBox(width: 6),
                  Text('History ($totalHistoryRules)'),
                ],
              ),
            ),
          ],
        ),
      ),
      body: Column(
        children: [
          // Status banner + stats
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              children: [
                _statusBanner(theme, mode, reason),
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
                          _summaryPill(theme, 'Blocks', '$blockCount',
                              color: Colors.red),
                          _summaryPill(
                              theme, 'Redirects', '$redirectCount',
                              color: Colors.blue),
                          _summaryPill(
                              theme, 'Rate limits', '$rateLimitCount',
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
                          _summaryPill(
                            theme,
                            'Attempted blocks',
                            '${_toInt(attempted?['block'])}',
                            color: Colors.red,
                          ),
                          _summaryPill(
                            theme,
                            'Attempted redirects',
                            '${_toInt(attempted?['honeypot'])}',
                            color: Colors.blue,
                          ),
                          _summaryPill(
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
                const SizedBox(height: 12),
                TextField(
                  onChanged: (value) => setState(() => _query = value),
                  style: TextStyle(color: theme.colorScheme.onSurface),
                  decoration: InputDecoration(
                    hintText:
                        'Filter by attacker IP, victim IP, rule type, or reason',
                    hintStyle: TextStyle(
                      color:
                          theme.colorScheme.onSurface.withOpacity(0.45),
                    ),
                    prefixIcon: const Icon(Icons.search),
                    suffixIcon: _query.isEmpty
                        ? null
                        : IconButton(
                            icon: const Icon(Icons.close),
                            onPressed: () => setState(() => _query = ''),
                          ),
                  ),
                ),
              ],
            ),
          ),
          // Tabbed content
          Expanded(
            child: TabBarView(
              controller: _tabController,
              children: [
                // Tab 1: Active rules
                _buildRulesList(
                  _filterRules(_activeRules),
                  _loadingActive,
                  theme,
                  isDark,
                  isAdmin,
                  mode,
                  reason,
                  showStatus: true,
                ),
                // Tab 2: Full history
                _buildRulesList(
                  _filterRules(_allRules),
                  _loadingHistory,
                  theme,
                  isDark,
                  isAdmin,
                  mode,
                  reason,
                  showStatus: false,
                  showPagination: true,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRulesList(
    List<FirewallRuleModel> rules,
    bool loading,
    ThemeData theme,
    bool isDark,
    bool isAdmin,
    String mode,
    String? reason, {
    bool showStatus = false,
    bool showPagination = false,
  }) {
    if (loading) {
      return Center(
          child: CircularProgressIndicator(color: theme.colorScheme.primary));
    }
    if (rules.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.security_outlined,
                size: 48,
                color: theme.colorScheme.onSurface.withOpacity(0.3)),
            const SizedBox(height: 12),
            Text(
              showStatus
                  ? 'No active containment rules right now'
                  : 'No firewall rule history found',
              style: TextStyle(
                color: theme.colorScheme.onSurface.withOpacity(0.6),
              ),
            ),
          ],
        ),
      );
    }

    return Column(
      children: [
        Expanded(
          child: RefreshIndicator(
            onRefresh: _fetchAll,
            child: ListView.builder(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              itemCount: rules.length,
              itemBuilder: (_, i) {
                final rule = rules[i];
                return _buildRuleCard(rule, theme, isDark, isAdmin);
              },
            ),
          ),
        ),
        if (showPagination && _historyTotal > _historyPageSize)
          _buildPagination(theme),
      ],
    );
  }

  Widget _buildRuleCard(
      FirewallRuleModel rule, ThemeData theme, bool isDark, bool isAdmin) {
    final color = _ruleColor(rule.ruleType);
    final isExpired = rule.isExpired;
    final isInactive = !rule.isActive;

    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: GlassyContainer(
        padding: const EdgeInsets.all(16),
        borderRadius: 18,
        color: isInactive || isExpired
            ? theme.colorScheme.onSurface.withOpacity(0.03)
            : null,
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Status + type badge column
            Column(
              children: [
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  decoration: BoxDecoration(
                    color:
                        color.withOpacity(isDark ? 0.15 : 0.1),
                    borderRadius: BorderRadius.circular(999),
                    border: Border.all(color: color.withOpacity(0.5)),
                  ),
                  child: Text(
                    rule.ruleType.toUpperCase(),
                    style: TextStyle(
                      color: isInactive ? color.withOpacity(0.5) : color,
                      fontSize: 10,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
                const SizedBox(height: 6),
                // Active/Expired indicator
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: (rule.isActive && !isExpired
                            ? Colors.green
                            : Colors.grey)
                        .withOpacity(0.12),
                    borderRadius: BorderRadius.circular(999),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 6,
                        height: 6,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: rule.isActive && !isExpired
                              ? Colors.green
                              : Colors.grey,
                        ),
                      ),
                      const SizedBox(width: 4),
                      Text(
                        rule.isActive && !isExpired ? 'LIVE' : 'EXPIRED',
                        style: TextStyle(
                          color: rule.isActive && !isExpired
                              ? Colors.green
                              : Colors.grey,
                          fontSize: 9,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    _ruleHeadline(rule),
                    style: TextStyle(
                      color: isInactive
                          ? theme.colorScheme.onSurface.withOpacity(0.5)
                          : theme.colorScheme.onSurface,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    rule.reason ?? 'No reason attached to this rule.',
                    style: TextStyle(
                      color:
                          theme.colorScheme.onSurface.withOpacity(0.62),
                      fontSize: 12,
                      height: 1.4,
                    ),
                  ),
                  const SizedBox(height: 10),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      _metaChip(theme, 'Attacker ${rule.targetIp}'),
                      if (rule.matchDstIp != null)
                        _metaChip(
                          theme,
                          rule.matchDstPort != null
                              ? 'Victim ${rule.matchDstIp}:${rule.matchDstPort}'
                              : 'Victim ${rule.matchDstIp}',
                        ),
                      if (rule.ruleType == 'redirect' &&
                          rule.targetPort != null)
                        _metaChip(theme, 'Honeypot ${rule.targetPort}'),
                      _metaChip(theme,
                          'Created ${timeago.format(rule.createdAt)}'),
                      if (rule.protocol != null)
                        _metaChip(theme, rule.protocol!.toUpperCase()),
                      if (rule.targetPort != null &&
                          rule.ruleType != 'redirect')
                        _metaChip(theme, 'Port ${rule.targetPort}'),
                      if (rule.expiresAt != null)
                        _metaChip(
                          theme,
                          rule.isExpired
                              ? 'Expired ${timeago.format(rule.expiresAt!)}'
                              : 'Expires ${timeago.format(rule.expiresAt!)}',
                        ),
                      if (rule.createdBy != null)
                        _metaChip(theme, 'By ${rule.createdBy}'),
                    ],
                  ),
                ],
              ),
            ),
            if (isAdmin && rule.isActive && !isExpired)
              IconButton(
                icon: const Icon(Icons.delete_outline,
                    color: Colors.red, size: 20),
                onPressed: () => _deleteRule(rule.id),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildPagination(ThemeData theme) {
    final totalPages = (_historyTotal / _historyPageSize).ceil();
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 12),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          IconButton(
            icon: const Icon(Icons.chevron_left),
            onPressed:
                _historyPage > 1 ? () => _fetchHistory(page: _historyPage - 1) : null,
          ),
          Text(
            'Page $_historyPage of $totalPages',
            style: TextStyle(
              color: theme.colorScheme.onSurface.withOpacity(0.7),
              fontWeight: FontWeight.w600,
            ),
          ),
          IconButton(
            icon: const Icon(Icons.chevron_right),
            onPressed: _historyPage < totalPages
                ? () => _fetchHistory(page: _historyPage + 1)
                : null,
          ),
        ],
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

  String _ruleHeadline(FirewallRuleModel rule) {
    if (rule.ruleType == 'redirect') {
      final victim = rule.matchDstIp ?? 'unknown victim';
      final port = rule.matchDstPort != null ? ':${rule.matchDstPort}' : '';
      final target =
          rule.targetPort != null ? 'honeypot:${rule.targetPort}' : 'honeypot';
      return '${rule.targetIp} -> $victim$port -> $target';
    }
    if (rule.targetPort != null) {
      return '${rule.targetIp}:${rule.targetPort}';
    }
    return rule.targetIp;
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
