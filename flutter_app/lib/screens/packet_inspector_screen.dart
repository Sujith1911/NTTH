import 'dart:async';
import 'dart:convert';
// ignore: avoid_web_libraries_in_flutter
import 'dart:html' as html;
import 'package:flutter/material.dart';
import 'package:dio/dio.dart';
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
  String? _filterService;
  String? _filterDirection;
  String? _filterThreatType;
  String? _filterDateFrom;
  String? _filterDateTo;
  bool _onlyThreats = false;

  final _srcIpController = TextEditingController();
  final _dstIpController = TextEditingController();
  final _searchController = TextEditingController();
  final _dateFromController = TextEditingController();
  final _dateToController = TextEditingController();

  Timer? _refreshTimer;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _fetchAll();
    });
    _refreshTimer =
        Timer.periodic(const Duration(seconds: 3), (_) => _fetchAll());
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    _srcIpController.dispose();
    _dstIpController.dispose();
    _searchController.dispose();
    _dateFromController.dispose();
    _dateToController.dispose();
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
      if (_filterService != null && _filterService!.isNotEmpty) {
        params['service'] = _filterService;
      }
      if (_filterDirection != null && _filterDirection!.isNotEmpty) {
        params['direction'] = _filterDirection;
      }
      if (_filterThreatType != null && _filterThreatType!.isNotEmpty) {
        params['threat_type'] = _filterThreatType;
      }
      if (_filterDateFrom != null && _filterDateFrom!.isNotEmpty) {
        params['captured_from'] = _filterDateFrom;
      }
      if (_filterDateTo != null && _filterDateTo!.isNotEmpty) {
        params['captured_to'] = _filterDateTo;
      }
      if (_onlyThreats) params['only_threats'] = true;
      final search = _searchController.text.trim();
      if (search.isNotEmpty) params['search'] = search;

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
    _filterDateFrom = _dateFromController.text.trim();
    _filterDateTo = _dateToController.text.trim();
    _page = 1;
    _fetchAll();
  }

  void _clearFilters() {
    _srcIpController.clear();
    _dstIpController.clear();
    _dateFromController.clear();
    _dateToController.clear();
    _searchController.clear();
    _filterSrcIp = null;
    _filterDstIp = null;
    _filterProtocol = null;
    _filterService = null;
    _filterDirection = null;
    _filterThreatType = null;
    _filterDateFrom = null;
    _filterDateTo = null;
    _onlyThreats = false;
    _page = 1;
    _fetchAll();
  }

  Future<void> _pickDate(TextEditingController controller) async {
    final now = DateTime.now();
    final picked = await showDatePicker(
      context: context,
      initialDate: now,
      firstDate: DateTime(now.year - 2),
      lastDate: DateTime(now.year + 1),
    );
    if (picked == null) return;
    controller.text = _dateParam(picked);
    _applyFilters();
  }

  String _dateParam(DateTime date) => '${date.year.toString().padLeft(4, '0')}-'
      '${date.month.toString().padLeft(2, '0')}-'
      '${date.day.toString().padLeft(2, '0')}';

  Map<String, dynamic> _currentFilterPayload() {
    return {
      if ((_filterSrcIp ?? '').isNotEmpty) 'src_ip': _filterSrcIp,
      if ((_filterDstIp ?? '').isNotEmpty) 'dst_ip': _filterDstIp,
      if ((_filterProtocol ?? '').isNotEmpty) 'protocol': _filterProtocol,
      if ((_filterService ?? '').isNotEmpty) 'service': _filterService,
      if ((_filterDirection ?? '').isNotEmpty) 'direction': _filterDirection,
      if ((_filterThreatType ?? '').isNotEmpty)
        'threat_type': _filterThreatType,
      if ((_filterDateFrom ?? '').isNotEmpty) 'captured_from': _filterDateFrom,
      if ((_filterDateTo ?? '').isNotEmpty) 'captured_to': _filterDateTo,
      if (_onlyThreats) 'only_threats': true,
      if (_searchController.text.trim().isNotEmpty)
        'search': _searchController.text.trim(),
    };
  }

  Future<void> _exportPackets(String format) async {
    try {
      final api = context.read<AuthService>().api;
      final resp = await api.dio.post(
        '/packets/export',
        queryParameters: {'format': format},
        data: _currentFilterPayload(),
        options: Options(responseType: ResponseType.bytes),
      );
      final bytes = (resp.data as List<int>);
      final mime = switch (format) {
        'pcap' => 'application/vnd.tcpdump.pcap',
        'json' => 'application/json',
        _ => 'text/csv',
      };
      final ext = format == 'pcap' ? 'pcap' : format;
      final blob = html.Blob([bytes], mime);
      final url = html.Url.createObjectUrlFromBlob(blob);
      html.AnchorElement(href: url)
        ..download = 'ntth_packets.$ext'
        ..click();
      html.Url.revokeObjectUrl(url);
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
            content: Text('Export failed: $e'), backgroundColor: Colors.red),
      );
    }
  }

  Future<void> _deletePacket(int packetId) async {
    if (!context.read<AuthService>().isAdmin) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Admin access required'),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }
    try {
      await context.read<AuthService>().api.delete('/packets/$packetId');
      await _fetchAll();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
            content: Text('Delete failed: $e'), backgroundColor: Colors.red),
      );
    }
  }

  Future<void> _deleteFiltered() async {
    if (!context.read<AuthService>().isAdmin) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Admin access required'),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete filtered packets?'),
        content:
            const Text('This removes all packets matching the active filters.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      final resp = await context
          .read<AuthService>()
          .api
          .post('/packets/delete-filtered', _currentFilterPayload());
      await _fetchAll();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Deleted ${resp.data['deleted'] ?? 0} packets'),
          backgroundColor: Colors.green,
        ),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
            content: Text('Delete failed: $e'), backgroundColor: Colors.red),
      );
    }
  }

  Future<void> _cleanupNoise() async {
    if (!context.read<AuthService>().isAdmin) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Admin access required'),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }
    try {
      final resp = await context
          .read<AuthService>()
          .api
          .post('/packets/cleanup-noise', {});
      await _fetchAll();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
              'Removed ${resp.data['deleted'] ?? 0} scan/broadcast packets and demo rows'),
          backgroundColor: Colors.green,
        ),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
            content: Text('Cleanup failed: $e'), backgroundColor: Colors.red),
      );
    }
  }

  Future<void> _openPacketDetails(Map<String, dynamic> packet) async {
    Map<String, dynamic> detail = packet;
    try {
      final id = packet['id'];
      if (id != null) {
        final resp = await context.read<AuthService>().api.get('/packets/$id');
        detail = (resp.data as Map<String, dynamic>);
      }
    } catch (_) {}
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (context) => Dialog(
        insetPadding: const EdgeInsets.all(24),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 920, maxHeight: 720),
          child: _PacketDetailView(packet: detail),
        ),
      ),
    );
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
        child: _loading
            ? Center(
                child:
                    CircularProgressIndicator(color: theme.colorScheme.primary))
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
    final byProtocol = (_stats?['by_protocol'] as Map<String, dynamic>?) ?? {};

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
            'Scan artifacts and broadcast traffic are filtered out automatically.',
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
              _statChip(
                  theme, 'Total', '$totalCaptured', theme.colorScheme.primary),
              _statChip(
                  theme, 'Threats', '$threatPkts', const Color(0xFFD14343)),
              _statChip(
                  theme, 'Normal', '$normalPkts', const Color(0xFF0F9D7A)),
              ...byProtocol.entries.map((e) => _statChip(theme,
                  e.key.toUpperCase(), '${e.value}', const Color(0xFF6366F1))),
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
                    contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 10),
                  ),
                  style: const TextStyle(fontSize: 13),
                  onSubmitted: (_) => _applyFilters(),
                ),
              ),
              SizedBox(
                width: 220,
                child: TextField(
                  controller: _searchController,
                  decoration: InputDecoration(
                    labelText: 'Payload / domain search',
                    isDense: true,
                    border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10)),
                    contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 10),
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
                    contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 10),
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
                label: 'Service',
                value: _filterService,
                items: const [
                  'http',
                  'https',
                  'dns',
                  'ssh',
                  'ftp',
                  'telnet',
                  'ntp',
                  'smb',
                  'dns_tls',
                  'mysql',
                  'rdp',
                  'ipsec',
                  'vnc',
                  'redis',
                  'mongodb'
                ],
                onChanged: (v) {
                  setState(() => _filterService = v);
                  _applyFilters();
                },
              ),
              _dropdownFilter(
                theme,
                label: 'Direction',
                value: _filterDirection,
                items: const ['outbound', 'inbound', 'local', 'unknown'],
                onChanged: (v) {
                  setState(() => _filterDirection = v);
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
              SizedBox(
                width: 150,
                child: TextField(
                  controller: _dateFromController,
                  readOnly: true,
                  decoration: InputDecoration(
                    labelText: 'From date',
                    isDense: true,
                    suffixIcon: IconButton(
                      icon: const Icon(Icons.calendar_month_outlined, size: 16),
                      onPressed: () => _pickDate(_dateFromController),
                    ),
                    border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10)),
                    contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 10),
                  ),
                  style: const TextStyle(fontSize: 13),
                ),
              ),
              SizedBox(
                width: 150,
                child: TextField(
                  controller: _dateToController,
                  readOnly: true,
                  decoration: InputDecoration(
                    labelText: 'To date',
                    isDense: true,
                    suffixIcon: IconButton(
                      icon: const Icon(Icons.calendar_month_outlined, size: 16),
                      onPressed: () => _pickDate(_dateToController),
                    ),
                    border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10)),
                    contentPadding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 10),
                  ),
                  style: const TextStyle(fontSize: 13),
                ),
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
              IconButton(
                icon: const Icon(Icons.cleaning_services_outlined),
                onPressed: _cleanupNoise,
                tooltip: 'Remove scan/broadcast packets',
              ),
              IconButton(
                icon: const Icon(Icons.delete_sweep_outlined),
                onPressed: _deleteFiltered,
                tooltip: 'Delete filtered packets',
              ),
              IconButton(
                icon: const Icon(Icons.table_chart_outlined),
                onPressed: () => _exportPackets('csv'),
                tooltip: 'Export filtered CSV',
              ),
              IconButton(
                icon: const Icon(Icons.data_object),
                onPressed: () => _exportPackets('json'),
                tooltip: 'Export filtered JSON',
              ),
              IconButton(
                icon: const Icon(Icons.file_download_outlined),
                onPressed: () => _exportPackets('pcap'),
                tooltip: 'Export filtered PCAP',
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
        border: Border.all(color: theme.colorScheme.onSurface.withOpacity(0.2)),
      ),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<String?>(
          hint: Text(label, style: const TextStyle(fontSize: 13)),
          value: value,
          isDense: true,
          style: TextStyle(fontSize: 13, color: theme.colorScheme.onSurface),
          items: [
            DropdownMenuItem<String?>(
              value: null,
              child: Text('All $label',
                  style: TextStyle(
                      color: theme.colorScheme.onSurface.withOpacity(0.5))),
            ),
            ...items.map((i) => DropdownMenuItem(
                  value: i,
                  child: Text(i.replaceAll('_', '-').toUpperCase()),
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
            DataColumn(label: Text('DATE')),
            DataColumn(label: Text('TIME')),
            DataColumn(label: Text('DIR')),
            DataColumn(label: Text('PROTO')),
            DataColumn(label: Text('SOURCE')),
            DataColumn(label: Text('DEST')),
            DataColumn(label: Text('PORTS')),
            DataColumn(label: Text('SERVICE')),
            DataColumn(label: Text('FLAGS')),
            DataColumn(label: Text('SIZE')),
            DataColumn(label: Text('THREAT')),
            DataColumn(label: Text('RISK')),
            DataColumn(label: Text('ACTION')),
            DataColumn(label: Text('DELETE')),
          ],
          rows: _packets
              .map((pkt) => DataRow(
                    onSelectChanged: (_) => _openPacketDetails(pkt),
                    color: MaterialStateProperty.resolveWith((_) {
                      if (pkt['threat_type'] != null) {
                        return const Color(0xFFD14343).withOpacity(0.04);
                      }
                      return null;
                    }),
                    cells: [
                      DataCell(Text('${pkt['id'] ?? ''}')),
                      DataCell(Text(_formatDate(pkt['captured_at']))),
                      DataCell(Text(_formatTime(pkt['captured_at']))),
                      DataCell(Text('${pkt['direction'] ?? ''}')),
                      DataCell(_protoBadge(pkt['protocol'] ?? '')),
                      DataCell(Text(_endpoint(pkt['src_ip'], pkt['src_port']))),
                      DataCell(Text(_endpoint(pkt['dst_ip'], pkt['dst_port']))),
                      DataCell(Text(
                          '${pkt['src_port'] ?? ''} → ${pkt['dst_port'] ?? ''}')),
                      DataCell(Text(_serviceName(pkt['dst_port']))),
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
                      DataCell(IconButton(
                        icon: const Icon(Icons.delete_outline, size: 16),
                        tooltip: 'Delete packet',
                        onPressed: () => _deletePacket(pkt['id'] as int),
                      )),
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
          style:
              TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.3)));
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
            color: Color(0xFFD14343), fontSize: 9, fontWeight: FontWeight.w700),
      ),
    );
  }

  Widget _actionBadge(ThemeData theme, String? action) {
    if (action == null) {
      return Text('—',
          style:
              TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.3)));
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
        style:
            TextStyle(color: color, fontSize: 9, fontWeight: FontWeight.w700),
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

  String _endpoint(dynamic ip, dynamic port) {
    final p = port?.toString() ?? '';
    return p.isEmpty || p == 'null' ? '${ip ?? ''}' : '${ip ?? ''}:$p';
  }

  String _serviceName(dynamic port) {
    return switch (port) {
      21 => 'FTP',
      22 => 'SSH',
      23 => 'TELNET',
      53 => 'DNS',
      80 => 'HTTP',
      123 => 'NTP',
      443 => 'HTTPS',
      445 => 'SMB',
      500 => 'IPSEC',
      853 => 'DNS-TLS',
      8080 => 'HTTP',
      8443 => 'HTTPS',
      3306 => 'MYSQL',
      3389 => 'RDP',
      4500 => 'IPSEC',
      5900 => 'VNC',
      6379 => 'REDIS',
      8888 => 'HTTP-ALT',
      27017 => 'MONGODB',
      _ => '—',
    };
  }

  String _formatTime(String? iso) {
    if (iso == null) return '';
    try {
      final dt = DateTime.parse(iso).toLocal();
      return '${dt.hour.toString().padLeft(2, '0')}:'
          '${dt.minute.toString().padLeft(2, '0')}:'
          '${dt.second.toString().padLeft(2, '0')}';
    } catch (_) {
      return iso.length > 19 ? iso.substring(11, 19) : iso;
    }
  }

  String _formatDate(String? iso) {
    if (iso == null) return '';
    try {
      final dt = DateTime.parse(iso).toLocal();
      return '${dt.year.toString().padLeft(4, '0')}-'
          '${dt.month.toString().padLeft(2, '0')}-'
          '${dt.day.toString().padLeft(2, '0')}';
    } catch (_) {
      return iso.length >= 10 ? iso.substring(0, 10) : iso;
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

class _PacketDetailView extends StatelessWidget {
  final Map<String, dynamic> packet;

  const _PacketDetailView({required this.packet});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  'Packet #${packet['id'] ?? ''}',
                  style: GoogleFonts.spaceGrotesk(
                    fontSize: 22,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
              IconButton(
                icon: const Icon(Icons.close),
                onPressed: () => Navigator.pop(context),
              ),
            ],
          ),
          if ((packet['flow_id'] ?? '').toString().isNotEmpty)
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                icon: const Icon(Icons.account_tree_outlined, size: 16),
                label: const Text('Open conversation'),
                onPressed: () => _openConversation(context),
              ),
            ),
          const SizedBox(height: 8),
          Text(
            '${packet['captured_at'] ?? ''}  ·  ${packet['direction'] ?? 'unknown'}',
            style:
                TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.65)),
          ),
          const SizedBox(height: 16),
          Expanded(
            child: SingleChildScrollView(
              child: Column(
                children: [
                  _section('Frame', {
                    'Length': '${packet['pkt_len'] ?? '—'} bytes',
                    'Payload': '${packet['payload_len'] ?? 0} bytes',
                    'Source MAC': packet['src_mac'],
                    'Destination MAC': packet['dst_mac'],
                  }),
                  _section('Internet Protocol', {
                    'Source': packet['src_ip'],
                    'Destination': packet['dst_ip'],
                    'Version': packet['ip_version'],
                    'TTL': packet['ip_ttl'],
                    'TOS': packet['ip_tos'],
                    'Identification': packet['ip_id'],
                    'Flags': packet['ip_flags'],
                    'Fragment offset': packet['frag_offset'],
                  }),
                  _section(
                      '${packet['protocol'] ?? 'Transport'}'.toUpperCase(), {
                    'Source port': packet['src_port'],
                    'Destination port': packet['dst_port'],
                    'TCP flags': packet['flags'],
                    'TCP sequence': packet['tcp_seq'],
                    'TCP acknowledgement': packet['tcp_ack'],
                    'TCP window': packet['tcp_window'],
                    'TCP options': packet['tcp_options'],
                    'UDP length': packet['udp_len'],
                    'ICMP type': packet['icmp_type'],
                    'ICMP code': packet['icmp_code'],
                    'Flow ID': packet['flow_id'],
                  }),
                  _section('TLS / QUIC', {
                    'SNI / domain': packet['tls_sni'],
                    'ALPN': packet['tls_alpn'],
                    'TLS version': packet['tls_version'],
                    'TLS record type': packet['tls_record_type'],
                    'QUIC hint': packet['quic_hint'],
                  }),
                  _section('Detection', {
                    'Threat': packet['threat_type'] ?? 'none',
                    'Risk': packet['risk_score'],
                    'Action': packet['action_taken'] ?? 'none',
                    'SYN': packet['is_syn'],
                    'ACK': packet['is_ack'],
                    'RST': packet['is_rst'],
                  }),
                  _httpSection(packet),
                  _payloadSection(packet['payload_preview']),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _openConversation(BuildContext context) async {
    final flowId = packet['flow_id']?.toString();
    if (flowId == null || flowId.isEmpty) return;
    try {
      final resp = await context.read<AuthService>().api.get(
        '/packets/flows/${Uri.encodeComponent(flowId)}',
        params: {'limit': 200},
      );
      final items = ((resp.data as Map<String, dynamic>)['items'] as List)
          .cast<Map<String, dynamic>>();
      if (!context.mounted) return;
      await showDialog<void>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Conversation'),
          content: SizedBox(
            width: 760,
            height: 460,
            child: ListView.separated(
              itemCount: items.length,
              separatorBuilder: (_, __) => const Divider(height: 1),
              itemBuilder: (context, index) {
                final pkt = items[index];
                return ListTile(
                  dense: true,
                  title: Text(
                    '${pkt['src_ip']}:${pkt['src_port']} -> ${pkt['dst_ip']}:${pkt['dst_port']}',
                    style: GoogleFonts.jetBrainsMono(fontSize: 12),
                  ),
                  subtitle: Text(
                    '${pkt['captured_at']}  ${pkt['protocol']}  ${pkt['flags'] ?? ''}  ${pkt['pkt_len']}B',
                  ),
                );
              },
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Close'),
            ),
          ],
        ),
      );
    } catch (e) {
      if (!context.mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
            content: Text('Conversation failed: $e'),
            backgroundColor: Colors.red),
      );
    }
  }

  Widget _section(String title, Map<String, dynamic> rows) {
    final visible = rows.entries
        .where((e) => e.value != null && '${e.value}'.isNotEmpty)
        .toList();
    if (visible.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(bottom: 14),
      child: ExpansionTile(
        initiallyExpanded: true,
        tilePadding: EdgeInsets.zero,
        title: Text(title, style: const TextStyle(fontWeight: FontWeight.w700)),
        children: visible
            .map((e) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: 4),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      SizedBox(
                        width: 180,
                        child: Text(e.key,
                            style:
                                const TextStyle(fontWeight: FontWeight.w600)),
                      ),
                      Expanded(
                        child: SelectableText(
                          '${e.value}',
                          style: GoogleFonts.jetBrainsMono(fontSize: 12),
                        ),
                      ),
                    ],
                  ),
                ))
            .toList(),
      ),
    );
  }

  Widget _payloadSection(dynamic payloadPreview) {
    final text = payloadPreview?.toString();
    if (text == null || text.isEmpty) return const SizedBox.shrink();
    return _section('Payload Preview', {
      'Hex': _spacedHex(text),
      'ASCII': _hexToAscii(text),
    });
  }

  Widget _httpSection(Map<String, dynamic> packet) {
    final formFields = _decodeFormFields(packet['http_form_fields']);
    return _section('HTTP', {
      'Method': packet['http_method'],
      'Host': packet['http_host'],
      'Path': packet['http_path'],
      'Content-Type': packet['http_content_type'],
      'User-Agent': packet['http_user_agent'],
      if (formFields.isNotEmpty) 'Form fields': formFields,
      'Body preview': packet['http_body_preview'],
      'Decoded payload': packet['payload_text'],
    });
  }

  String _decodeFormFields(dynamic raw) {
    final text = raw?.toString();
    if (text == null || text.isEmpty) return '';
    try {
      final decoded = jsonDecode(text);
      if (decoded is Map) {
        return decoded.entries
            .map((entry) => '${entry.key}: ${entry.value}')
            .join('\n');
      }
    } catch (_) {}
    return text;
  }

  String _spacedHex(String hex) {
    final clean = hex.replaceAll(RegExp(r'\s+'), '');
    final chunks = <String>[];
    for (var i = 0; i < clean.length; i += 2) {
      chunks
          .add(clean.substring(i, i + 2 > clean.length ? clean.length : i + 2));
    }
    return chunks.join(' ');
  }

  String _hexToAscii(String hex) {
    final clean = hex.replaceAll(RegExp(r'\s+'), '');
    final buffer = StringBuffer();
    for (var i = 0; i + 1 < clean.length; i += 2) {
      final value = int.tryParse(clean.substring(i, i + 2), radix: 16);
      if (value == null) continue;
      buffer.write(
          value >= 32 && value <= 126 ? String.fromCharCode(value) : '.');
    }
    return buffer.toString();
  }
}
