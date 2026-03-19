import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../core/auth_service.dart';
import '../models/device_model.dart';
import '../widgets/device_tile.dart';

class DevicesScreen extends StatefulWidget {
  const DevicesScreen({super.key});

  @override
  State<DevicesScreen> createState() => _DevicesScreenState();
}

class _DevicesScreenState extends State<DevicesScreen> {
  List<DeviceModel> _devices = [];
  bool _loading = true;
  String? _error;
  int _page = 1;
  int _total = 0;

  @override
  void initState() {
    super.initState();
    _fetchDevices();
  }

  Future<void> _fetchDevices() async {
    setState(() { _loading = true; _error = null; });
    try {
      final api = context.read<AuthService>().api;
      final resp = await api.get('/devices', params: {'page': _page, 'page_size': 50});
      final data = resp.data as Map<String, dynamic>;
      setState(() {
        _devices = (data['items'] as List).map((j) => DeviceModel.fromJson(j)).toList();
        _total = data['total'];
        _loading = false;
      });
    } catch (e) {
      setState(() { _error = e.toString(); _loading = false; });
    }
  }

  Future<void> _toggleTrust(DeviceModel device) async {
    final isAdmin = context.read<AuthService>().isAdmin;
    if (!isAdmin) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Admin access required'), backgroundColor: Colors.red),
      );
      return;
    }
    try {
      final api = context.read<AuthService>().api;
      await api.put('/devices/${device.id}/trust', {'is_trusted': !device.isTrusted});
      _fetchDevices();
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(device.isTrusted ? 'Device untrusted' : 'Device trusted'),
          backgroundColor: const Color(0xFF00FF88),
        ),
      );
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Error: $e'), backgroundColor: Colors.red),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Devices ($_total total)'),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _fetchDevices),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: Color(0xFF00FF88)))
          : _error != null
              ? Center(
                  child: Column(mainAxisSize: MainAxisSize.min, children: [
                    Text(_error!, style: const TextStyle(color: Colors.red)),
                    const SizedBox(height: 12),
                    ElevatedButton(onPressed: _fetchDevices, child: const Text('Retry')),
                  ]),
                )
              : _devices.isEmpty
                  ? const Center(
                      child: Column(mainAxisSize: MainAxisSize.min, children: [
                        Icon(Icons.devices_outlined, color: Colors.white24, size: 64),
                        SizedBox(height: 12),
                        Text('No devices discovered yet', style: TextStyle(color: Colors.white38)),
                        SizedBox(height: 4),
                        Text('Packet sniffer will populate devices automatically',
                            style: TextStyle(color: Colors.white24, fontSize: 12)),
                      ]),
                    )
                  : ListView.separated(
                      padding: const EdgeInsets.all(16),
                      itemCount: _devices.length,
                      separatorBuilder: (_, __) => const SizedBox(height: 8),
                      itemBuilder: (_, i) => DeviceTile(
                        device: _devices[i],
                        onToggleTrust: () => _toggleTrust(_devices[i]),
                      ),
                    ),
    );
  }
}
