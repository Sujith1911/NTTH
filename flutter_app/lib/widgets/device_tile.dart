import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:timeago/timeago.dart' as timeago;

import '../models/device_model.dart';
import '../widgets/glassy_container.dart';

class DeviceTile extends StatelessWidget {
  final DeviceModel device;
  final VoidCallback? onToggleTrust;
  final VoidCallback? onClearRisk;

  const DeviceTile({
    super.key,
    required this.device,
    this.onToggleTrust,
    this.onClearRisk,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final riskPct = (device.riskScore * 100).toInt();
    final riskColor = device.riskScore > 0.85
        ? Colors.red
        : device.riskScore > 0.5
            ? Colors.orange
            : device.riskScore > 0.2
                ? Colors.amber.shade700
                : Colors.green;
    final displayName =
        device.hostname ?? device.vendor ?? 'Unknown Device';

    return GlassyContainer(
      borderRadius: 16,
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Row 1: Icon + Name + Risk Badge ──
          Row(
            children: [
              // Device icon with trust indicator
              Container(
                width: 44,
                height: 44,
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [
                      riskColor.withOpacity(0.15),
                      riskColor.withOpacity(0.05),
                    ],
                  ),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(
                    color: riskColor.withOpacity(0.3),
                    width: 1,
                  ),
                ),
                child: Stack(
                  children: [
                    Center(
                      child: Icon(
                        device.isTrusted
                            ? Icons.verified_user_outlined
                            : Icons.computer_outlined,
                        color: riskColor,
                        size: 22,
                      ),
                    ),
                    if (device.isTrusted)
                      Positioned(
                        right: 2,
                        bottom: 2,
                        child: Container(
                          width: 12,
                          height: 12,
                          decoration: BoxDecoration(
                            color: Colors.green,
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: theme.scaffoldBackgroundColor,
                              width: 1.5,
                            ),
                          ),
                          child: const Icon(
                            Icons.check,
                            size: 7,
                            color: Colors.white,
                          ),
                        ),
                      ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              // Name + IP
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      displayName,
                      style: GoogleFonts.spaceGrotesk(
                        fontSize: 15,
                        fontWeight: FontWeight.w700,
                        color: theme.colorScheme.onSurface,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                    const SizedBox(height: 2),
                    Text(
                      device.ipAddress,
                      style: TextStyle(
                        color:
                            theme.colorScheme.onSurface.withOpacity(0.55),
                        fontSize: 12,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ],
                ),
              ),
              // Risk badge
              Container(
                padding: const EdgeInsets.symmetric(
                    horizontal: 12, vertical: 6),
                decoration: BoxDecoration(
                  color: riskColor.withOpacity(0.12),
                  borderRadius: BorderRadius.circular(20),
                  border:
                      Border.all(color: riskColor.withOpacity(0.3)),
                ),
                child: Text(
                  '$riskPct%',
                  style: GoogleFonts.spaceGrotesk(
                    color: riskColor,
                    fontWeight: FontWeight.w800,
                    fontSize: 14,
                  ),
                ),
              ),
            ],
          ),

          const SizedBox(height: 12),

          // ── Row 2: MAC + Last Seen ──
          Row(
            children: [
              Icon(Icons.memory_outlined,
                  size: 13,
                  color:
                      theme.colorScheme.onSurface.withOpacity(0.4)),
              const SizedBox(width: 6),
              Text(
                device.macAddress ?? '—',
                style: TextStyle(
                  color:
                      theme.colorScheme.onSurface.withOpacity(0.6),
                  fontSize: 12,
                  fontFamily: 'monospace',
                ),
              ),
              const Spacer(),
              Icon(Icons.access_time_outlined,
                  size: 13,
                  color:
                      theme.colorScheme.onSurface.withOpacity(0.4)),
              const SizedBox(width: 4),
              Text(
                timeago.format(device.lastSeen),
                style: TextStyle(
                  color:
                      theme.colorScheme.onSurface.withOpacity(0.5),
                  fontSize: 11,
                ),
              ),
            ],
          ),

          const SizedBox(height: 10),

          // ── Row 3: Risk bar ──
          ClipRRect(
            borderRadius: BorderRadius.circular(4),
            child: LinearProgressIndicator(
              value: device.riskScore,
              backgroundColor: isDark
                  ? Colors.white.withOpacity(0.06)
                  : Colors.black.withOpacity(0.06),
              color: riskColor,
              minHeight: 5,
            ),
          ),

          const SizedBox(height: 12),

          // ── Row 4: Action buttons ──
          Row(
            children: [
              // Trust / Untrust button
              if (onToggleTrust != null)
                Expanded(
                  child: _ActionButton(
                    icon: device.isTrusted
                        ? Icons.remove_moderator_outlined
                        : Icons.shield_outlined,
                    label: device.isTrusted ? 'Untrust' : 'Trust',
                    color: device.isTrusted
                        ? Colors.orange
                        : Colors.green,
                    onPressed: onToggleTrust!,
                  ),
                ),
              if (onToggleTrust != null && onClearRisk != null && device.riskScore > 0)
                const SizedBox(width: 8),
              // Clear Risk button (only when risk > 0)
              if (onClearRisk != null && device.riskScore > 0)
                Expanded(
                  child: _ActionButton(
                    icon: Icons.lock_open_outlined,
                    label: 'Clear Risk',
                    color: Colors.blue,
                    onPressed: onClearRisk!,
                  ),
                ),
            ],
          ),
        ],
      ),
    );
  }
}

class _ActionButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  final VoidCallback onPressed;

  const _ActionButton({
    required this.icon,
    required this.label,
    required this.color,
    required this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    return Material(
      color: color.withOpacity(0.1),
      borderRadius: BorderRadius.circular(10),
      child: InkWell(
        onTap: onPressed,
        borderRadius: BorderRadius.circular(10),
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 10),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: color.withOpacity(0.25)),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(icon, size: 16, color: color),
              const SizedBox(width: 6),
              Text(
                label,
                style: TextStyle(
                  color: color,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
