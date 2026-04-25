import 'dart:async';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../core/auth_service.dart';
import '../widgets/app_shell_drawer.dart';
import '../widgets/glassy_container.dart';

/// Packet Inspector screen — browse, filter, and inspect captured network packets.
class PacketInspectorScreen extends StatefulWidget {
  const PacketInspectorScreen({super.key});

  @override
  State<PacketInspectorScreen> createState() => _PacketInspectorScreenState();
}

class _PacketInspectorScreenState extends State<PacketInspectorScreen> {
  List<Map<String, dynamic>> _packets = [];
  Map<String, dynamic>? _stats;
  bool _loading = true;
  int _page = 1;
  int _total = 0;
  static const int _pageSize = 50;

  // Filters
  String? _filterSrcIp;
  String? _filterDstIp;
  String? _filterProtocol;
  String? _filterThreatType;
  bool _onlyThreats = false;

  final _srcIpController = TextEditingController();
  final _dstIpController = TextEditingController();

  Timer? _refreshTimer;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _fetchAll();
    });
    _refreshTimer =
        Timer.periodic(const Duration(seconds: 15), (_) => _fetchPackets());
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    _srcIpController.dispose();
    _dstIpController.dispose();
    super.dispose();
  }

  Future<void> _fetchAll() async {
    await Future.wait([_fetchPackets(), _fetchStats()]);
  }

  Future<void> _fetchPackets() async {
    try {
      final api = context.read<AuthService>().api;
      final params = <String, dynamic>{
        'page': _page,
        'page_size': _pageSize,
      };
      if (_filterSrcIp != null && _filterSrcIp!.isNotEmpty) {
        params['src_ip'] = _filterSrcIp;
      }
      if (_filterDstIp != null && _filterDstIp!.isNotEmpty) {
        params['dst_ip'] = _filterDstIp;
      }
      if (_filterProtocol != null && _filterProtocol!.isNotEmpty) {
        params['protocol'] = _filterProtocol;
      }
      if (_filterThreatType != null && _filterThreatType!.isNotEmpty) {
        params['threat_type'] = _filterThreatType;
      }
      if (_onlyThreats) params['only_threats'] = true;

      final resp = await api.get('/packets', params: params);
      if (!mounted) return;
      final data = resp.data as Map<String, dynamic>;
      setState(() {
        _packets = (data['items'] as List).cast<Map<String, dynamic>>();
        _total = data['total'] as int? ?? 0;
        _loading = false;
      });
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _fetchStats() async {
    try {
      final api = context.read<AuthService>().api;
      final resp = await api.get('/packets/stats');
      if (!mounted) return;
      setState(() => _stats = resp.data as Map<String, dynamic>);
    } catch (_) {}
  }

  void _applyFilters() {
    _filterSrcIp = _srcIpController.text.trim();
    _filterDstIp = _dstIpController.text.trim();
    _page = 1;
    _fetchPackets();
  }

  void _clearFilters() {
    _srcIpController.clear();
    _dstIpController.clear();
    _filterSrcIp = null;
    _filterDstIp = null;
    _filterProtocol = null;
    _filterThreatType = null;
    _onlyThreats = false;
    _page = 1;
    _fetchPackets();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final totalPages = (_total / _pageSize).ceil().clamp(1, 999);

    return Scaffold(
      drawer: const AppShellDrawer(),
      appBar: AppBar(
        title: const Text('Packet Inspector'),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchAll),
        ],
      ),
      body: Container(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: isDark
                ? const [Color(0xFF07111F), Color(0xFF0A162A), Color(0xFF07111F)]
                : const [Color(0xFFF4F8FC), Color(0xFFEAF2FB), Color(0xFFF5F8FC)],
          ),
        ),
        child: _loading
            ? Center(
                child: CircularProgressIndicator(
                    color: theme.colorScheme.primary))
            : RefreshIndicator(
                onRefresh: _fetchAll,
                child: ListView(
                  padding: const EdgeInsets.all(20),
                  children: [
                    // Stats banner
                    _buildStatsBanner(theme),
                    const SizedBox(height: 16),

                    // Filter bar
                    _buildFilterBar(theme),
                    const SizedBox(height: 16),

                    // Packet table
                    _buildPacketTable(theme),
                    const SizedBox(height: 12),

                    // Pagination
                    _buildPagination(theme, totalPages),
                  ],
                ),
              ),
      ),
    );
  }

  Widget _buildStatsBanner(ThemeData theme) {
    final totalCaptured = _stats?['total_captured'] ?? 0;
    final threatPkts = _stats?['threat_packets'] ?? 0;
    final normalPkts = _stats?['normal_packets'] ?? 0;
    final byProtocol =
        (_stats?['by_protocol'] as Map<String, dynamic>?) ?? {};

    return GlassyContainer(
      borderRadius: 20,
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Capture Statistics',
            style: GoogleFonts.spaceGrotesk(
              fontSize: 20,
              fontWeight: FontWeight.w700,
              color: theme.colorScheme.onSurface,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            'Packets are stored for forensic inspection. '
            'Threat packets are captured automatically. Normal traffic is sampled at 1%.',
            style: TextStyle(
              fontSize: 12,
              color: theme.colorScheme.onSurface.withOpacity(0.6),
              height: 1.5,
            ),
          ),
          const SizedBox(height: 16),
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              _statChip(theme, 'Total', '$totalCaptured',
                  theme.colorScheme.primary),
              _statChip(theme, 'Threats', '$threatPkts',
                  const Color(0xFFD14343)),
              _statChip(theme, 'Normal', '$normalPkts',
                  const Color(0xFF0F9D7A)),
              ...byProtocol.entries.map((e) => _statChip(
                  theme,
                  e.key.toUpperCase(),
                  '${e.value}',
                  const Color(0xFF6366F1))),
            ],
          ),
        ],
      ),
    );
  }

  Widget _statChip(ThemeData theme, String label, String value, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: color.withOpacity(0.08),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label,
              style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: theme.colorScheme.onSurface.withOpacity(0.5))),
          const SizedBox(height: 2),
          Text(value,
              style: GoogleFonts.spaceGrotesk(
                fontSize: 18,
                fontWeight: FontWeight.w700,
                color: color,
              )),
        ],
      ),
    );
  }

  Widget _buildFilterBar(ThemeData theme) {
    return GlassyContainer(
      borderRadius: 16,
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Filters',
              style: TextStyle(
                fontWeight: FontWeight.w700,
                color: theme.colorScheme.onSurface,
              )),
          const SizedBox(height: 12),
          Wrap(
            spacing: 10,
            runSpacing: 10,
            children: [
              SizedBox(
                width: 160,
                child: TextField(
                  controller: _srcIpController,
                  decoration: InputDecoration(
                    labelText: 'Source IP',
                    isDense: true,
                    border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10)),
                    contentPadding:
                        const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  ),
                  style: const TextStyle(fontSize: 13),
                  onSubmitted: (_) => _applyFilters(),
                ),
              ),
              SizedBox(
                width: 160,
                child: TextField(
                  controller: _dstIpController,
                  decoration: InputDecoration(
                    labelText: 'Dest IP',
                    isDense: true,
                    border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10)),
                    contentPadding:
                        const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  ),
                  style: const TextStyle(fontSize: 13),
                  onSubmitted: (_) => _applyFilters(),
                ),
              ),
              _dropdownFilter(
                theme,
                label: 'Protocol',
                value: _filterProtocol,
                items: const ['tcp', 'udp', 'icmp', 'other'],
                onChanged: (v) {
                  setState(() => _filterProtocol = v);
                  _applyFilters();
                },
              ),
              _dropdownFilter(
                theme,
                label: 'Threat',
                value: _filterThreatType,
                items: const [
                  'port_scan',
                  'syn_flood',
                  'brute_force',
                  'anomaly',
                  'suspicious'
                ],
                onChanged: (v) {
                  setState(() => _filterThreatType = v);
                  _applyFilters();
                },
              ),
              FilterChip(
                label: const Text('Threats only'),
                selected: _onlyThreats,
                onSelected: (v) {
                  setState(() => _onlyThreats = v);
                  _applyFilters();
                },
                selectedColor: const Color(0xFFD14343).withOpacity(0.15),
                checkmarkColor: const Color(0xFFD14343),
              ),
              IconButton(
                icon: const Icon(Icons.search),
                onPressed: _applyFilters,
                tooltip: 'Apply filters',
              ),
              IconButton(
                icon: const Icon(Icons.clear_all),
                onPressed: _clearFilters,
                tooltip: 'Clear filters',
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _dropdownFilter(
    ThemeData theme, {
    required String label,
    required String? value,
    required List<String> items,
    required ValueChanged<String?> onChanged,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
            color: theme.colorScheme.onSurface.withOpacity(0.2)),
      ),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<String?>(
          hint: Text(label, style: const TextStyle(fontSize: 13)),
          value: value,
          isDense: true,
          style: TextStyle(
              fontSize: 13, color: theme.colorScheme.onSurface),
          items: [
            DropdownMenuItem<String?>(
              value: null,
              child: Text('All $label',
                  style: TextStyle(
                      color: theme.colorScheme.onSurface.withOpacity(0.5))),
            ),
            ...items.map((i) => DropdownMenuItem(
                  value: i,
                  child: Text(i.toUpperCase()),
                )),
          ],
          onChanged: onChanged,
        ),
      ),
    );
  }

  Widget _buildPacketTable(ThemeData theme) {
    if (_packets.isEmpty) {
      return GlassyContainer(
        borderRadius: 16,
        padding: const EdgeInsets.all(32),
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.inventory_2_outlined,
                  size: 56,
                  color: theme.colorScheme.onSurface.withOpacity(0.2)),
              const SizedBox(height: 16),
              Text(
                'No captured packets matching filters',
                style: TextStyle(
                    color: theme.colorScheme.onSurface.withOpacity(0.5)),
              ),
              const SizedBox(height: 8),
              Text(
                'Packets are captured during monitoring mode. '
                'Start the sniffer and generate some traffic.',
                style: TextStyle(
                  fontSize: 12,
                  color: theme.colorScheme.onSurface.withOpacity(0.35),
                ),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      );
    }

    return GlassyContainer(
      borderRadius: 16,
      padding: const EdgeInsets.all(12),
      child: SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        child: DataTable(
          columnSpacing: 14,
          headingRowHeight: 40,
          dataRowMinHeight: 36,
          dataRowMaxHeight: 44,
          headingTextStyle: GoogleFonts.inter(
            fontSize: 11,
            fontWeight: FontWeight.w700,
            color: theme.colorScheme.onSurface.withOpacity(0.6),
          ),
          dataTextStyle: GoogleFonts.jetBrainsMono(
            fontSize: 12,
            color: theme.colorScheme.onSurface.withOpacity(0.85),
          ),
          columns: const [
            DataColumn(label: Text('#')),
            DataColumn(label: Text('TIME')),
            DataColumn(label: Text('PROTO')),
            DataColumn(label: Text('SOURCE')),
            DataColumn(label: Text('DEST')),
            DataColumn(label: Text('PORT')),
            DataColumn(label: Text('FLAGS')),
            DataColumn(label: Text('SIZE')),
            DataColumn(label: Text('THREAT')),
            DataColumn(label: Text('RISK')),
            DataColumn(label: Text('ACTION')),
          ],
          rows: _packets
              .map((pkt) => DataRow(
                    color: MaterialStateProperty.resolveWith((_) {
                      if (pkt['threat_type'] != null) {
                        return const Color(0xFFD14343).withOpacity(0.04);
                      }
                      return null;
                    }),
                    cells: [
                      DataCell(Text('${pkt['id'] ?? ''}')),
                      DataCell(Text(_formatTime(pkt['captured_at']))),
                      DataCell(_protoBadge(pkt['protocol'] ?? '')),
                      DataCell(Text('${pkt['src_ip'] ?? ''}:${pkt['src_port'] ?? ''}')),
                      DataCell(Text('${pkt['dst_ip'] ?? ''}')),
                      DataCell(Text('${pkt['dst_port'] ?? ''}')),
                      DataCell(Text('${pkt['flags'] ?? ''}')),
                      DataCell(Text('${pkt['pkt_len'] ?? ''}B')),
                      DataCell(_threatBadge(theme, pkt['threat_type'])),
                      DataCell(Text(
                        pkt['risk_score'] != null
                            ? (pkt['risk_score'] as num).toStringAsFixed(2)
                            : '',
                        style: TextStyle(
                          color: _riskColor(pkt['risk_score']),
                          fontWeight: FontWeight.w600,
                        ),
                      )),
                      DataCell(_actionBadge(theme, pkt['action_taken'])),
                    ],
                  ))
              .toList(),
        ),
      ),
    );
  }

  Widget _protoBadge(String proto) {
    final color = switch (proto) {
      'tcp' => const Color(0xFF6366F1),
      'udp' => const Color(0xFF0F9D7A),
      'icmp' => const Color(0xFFF59E0B),
      _ => Colors.grey,
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withOpacity(0.12),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(proto.toUpperCase(),
          style: TextStyle(
              color: color, fontSize: 10, fontWeight: FontWeight.w700)),
    );
  }

  Widget _threatBadge(ThemeData theme, String? threatType) {
    if (threatType == null) {
      return Text('—',
          style: TextStyle(
              color: theme.colorScheme.onSurface.withOpacity(0.3)));
    }
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: const Color(0xFFD14343).withOpacity(0.12),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        threatType.replaceAll('_', ' ').toUpperCase(),
        style: const TextStyle(
            color: Color(0xFFD14343),
            fontSize: 9,
            fontWeight: FontWeight.w700),
      ),
    );
  }

  Widget _actionBadge(ThemeData theme, String? action) {
    if (action == null) {
      return Text('—',
          style: TextStyle(
              color: theme.colorScheme.onSurface.withOpacity(0.3)));
    }
    final color = switch (action) {
      'block' => const Color(0xFFD14343),
      'honeypot' => const Color(0xFF6366F1),
      'rate_limit' => const Color(0xFFF59E0B),
      _ => const Color(0xFF0F9D7A),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withOpacity(0.12),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        action.toUpperCase(),
        style: TextStyle(
            color: color, fontSize: 9, fontWeight: FontWeight.w700),
      ),
    );
  }

  Color _riskColor(dynamic score) {
    if (score == null) return Colors.grey;
    final s = (score as num).toDouble();
    if (s >= 0.8) return const Color(0xFFD14343);
    if (s >= 0.5) return const Color(0xFFF59E0B);
    if (s > 0) return const Color(0xFF0F9D7A);
    return Colors.grey;
  }

  String _formatTime(String? iso) {
    if (iso == null) return '';
    try {
      final dt = DateTime.parse(iso);
      return '${dt.hour.toString().padLeft(2, '0')}:'
          '${dt.minute.toString().padLeft(2, '0')}:'
          '${dt.second.toString().padLeft(2, '0')}';
    } catch (_) {
      return iso.length > 19 ? iso.substring(11, 19) : iso;
    }
  }

  Widget _buildPagination(ThemeData theme, int totalPages) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        IconButton(
          icon: const Icon(Icons.chevron_left),
          onPressed: _page > 1
              ? () {
                  setState(() => _page--);
                  _fetchPackets();
                }
              : null,
        ),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          decoration: BoxDecoration(
            color: theme.colorScheme.primary.withOpacity(0.08),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Text(
            'Page $_page of $totalPages  ($_total packets)',
            style: TextStyle(
              fontWeight: FontWeight.w600,
              color: theme.colorScheme.onSurface.withOpacity(0.7),
            ),
          ),
        ),
        IconButton(
          icon: const Icon(Icons.chevron_right),
          onPressed: _page < totalPages
              ? () {
                  setState(() => _page++);
                  _fetchPackets();
                }
              : null,
        ),
      ],
    );
  }
}
