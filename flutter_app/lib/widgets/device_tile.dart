import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../models/device_model.dart';

class DeviceTile extends StatelessWidget {
  final DeviceModel device;
  final VoidCallback? onToggleTrust;

  const DeviceTile({super.key, required this.device, this.onToggleTrust});

  @override
  Widget build(BuildContext context) {
    final riskColor = device.riskScore > 0.85
        ? Colors.red
        : device.riskScore > 0.5
            ? Colors.orange
            : const Color(0xFF00FF88);

    return Container(
      decoration: BoxDecoration(
        color: const Color(0xFF111827),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: device.isTrusted
              ? const Color(0xFF00FF88).withOpacity(0.3)
              : const Color(0xFF1F2937),
        ),
      ),
      child: ExpansionTile(
        backgroundColor: Colors.transparent,
        collapsedBackgroundColor: Colors.transparent,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        collapsedShape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        leading: Stack(children: [
          Container(
            width: 40, height: 40,
            decoration: BoxDecoration(
              color: riskColor.withOpacity(0.1),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(Icons.computer_outlined, color: riskColor, size: 22),
          ),
          if (device.isTrusted)
            Positioned(right: 0, bottom: 0, child: Container(
              width: 14, height: 14,
              decoration: BoxDecoration(
                color: const Color(0xFF00FF88),
                shape: BoxShape.circle,
                border: Border.all(color: const Color(0xFF111827), width: 1.5),
              ),
              child: const Icon(Icons.check, size: 8, color: Color(0xFF080C18)),
            )),
        ]),
        title: Text(
          device.ipAddress,
          style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600, fontSize: 14),
        ),
        subtitle: Text(
          device.hostname ?? device.vendor ?? 'Unknown device',
          style: const TextStyle(color: Colors.white38, fontSize: 12),
        ),
        trailing: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
          Text(
            '${(device.riskScore * 100).toInt()}%',
            style: TextStyle(color: riskColor, fontWeight: FontWeight.w700, fontSize: 13),
          ),
          Text('risk', style: const TextStyle(color: Colors.white24, fontSize: 10)),
        ]),
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const Divider(color: Color(0xFF1F2937)),
              const SizedBox(height: 8),
              Wrap(spacing: 24, runSpacing: 8, children: [
                _info('MAC', device.macAddress ?? '—'),
                _info('Vendor', device.vendor ?? '—'),
                _info('First seen', timeago.format(device.firstSeen)),
                _info('Last seen', timeago.format(device.lastSeen)),
              ]),
              const SizedBox(height: 12),
              // Risk bar
              Row(children: [
                const Text('Risk score', style: TextStyle(color: Colors.white38, fontSize: 12)),
                const SizedBox(width: 12),
                Expanded(
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(4),
                    child: LinearProgressIndicator(
                      value: device.riskScore,
                      backgroundColor: const Color(0xFF1F2937),
                      color: riskColor,
                      minHeight: 6,
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                Text('${(device.riskScore * 100).toInt()}%',
                    style: TextStyle(color: riskColor, fontSize: 12, fontWeight: FontWeight.w600)),
              ]),
              const SizedBox(height: 12),
              if (onToggleTrust != null)
                OutlinedButton.icon(
                  icon: Icon(
                    device.isTrusted ? Icons.shield_outlined : Icons.shield,
                    size: 16,
                    color: device.isTrusted ? Colors.orange : const Color(0xFF00FF88),
                  ),
                  label: Text(device.isTrusted ? 'Remove Trust' : 'Mark as Trusted'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: device.isTrusted ? Colors.orange : const Color(0xFF00FF88),
                    side: BorderSide(
                      color: device.isTrusted
                          ? Colors.orange.withOpacity(0.5)
                          : const Color(0xFF00FF88).withOpacity(0.5),
                    ),
                  ),
                  onPressed: onToggleTrust,
                ),
            ]),
          ),
        ],
      ),
    );
  }

  Widget _info(String label, String value) {
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(label, style: const TextStyle(color: Colors.white38, fontSize: 11)),
      Text(value, style: const TextStyle(color: Colors.white, fontSize: 13)),
    ]);
  }
}
