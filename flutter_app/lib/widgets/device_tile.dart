import 'package:flutter/material.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../models/device_model.dart';
import '../widgets/glassy_container.dart';

class DeviceTile extends StatelessWidget {
  final DeviceModel device;
  final VoidCallback? onToggleTrust;

  const DeviceTile({super.key, required this.device, this.onToggleTrust});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final riskColor = device.riskScore > 0.85
        ? Colors.red
        : device.riskScore > 0.5
            ? Colors.orange
            : theme.colorScheme.primary;

    return GlassyContainer(
      borderRadius: 12,
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
                color: theme.colorScheme.primary,
                shape: BoxShape.circle,
                border: Border.all(color: theme.scaffoldBackgroundColor, width: 1.5),
              ),
              child: Icon(Icons.check, size: 8, color: theme.scaffoldBackgroundColor),
            )),
        ]),
        title: Text(
          device.ipAddress,
          style: TextStyle(color: theme.colorScheme.onSurface, fontWeight: FontWeight.w600, fontSize: 14),
        ),
        subtitle: Text(
          device.hostname ?? device.vendor ?? 'Unknown device',
          style: TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.6), fontSize: 12),
        ),
        trailing: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
          Text(
            '${(device.riskScore * 100).toInt()}%',
            style: TextStyle(color: riskColor, fontWeight: FontWeight.w700, fontSize: 13),
          ),
          Text('risk', style: TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.4), fontSize: 10)),
        ]),
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Divider(color: theme.dividerColor),
              const SizedBox(height: 8),
              Wrap(spacing: 24, runSpacing: 8, children: [
                _info('MAC', device.macAddress ?? '—', theme),
                _info('Vendor', device.vendor ?? '—', theme),
                _info('First seen', timeago.format(device.firstSeen), theme),
                _info('Last seen', timeago.format(device.lastSeen), theme),
              ]),
              const SizedBox(height: 12),
              // Risk bar
              Row(children: [
                Text('Risk score', style: TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.5), fontSize: 12)),
                const SizedBox(width: 12),
                Expanded(
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(4),
                    child: LinearProgressIndicator(
                      value: device.riskScore,
                      backgroundColor: theme.dividerColor.withOpacity(0.2),
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
                    color: device.isTrusted ? Colors.orange : theme.colorScheme.primary,
                  ),
                  label: Text(device.isTrusted ? 'Remove Trust' : 'Mark as Trusted'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: device.isTrusted ? Colors.orange : theme.colorScheme.primary,
                    side: BorderSide(
                      color: device.isTrusted
                          ? Colors.orange.withOpacity(0.5)
                          : theme.colorScheme.primary.withOpacity(0.5),
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

  Widget _info(String label, String value, ThemeData theme) {
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(label, style: TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.4), fontSize: 11)),
      Text(value, style: TextStyle(color: theme.colorScheme.onSurface, fontSize: 13)),
    ]);
  }
}
