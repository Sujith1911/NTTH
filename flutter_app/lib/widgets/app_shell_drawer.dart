import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../core/auth_service.dart';
import '../core/websocket_service.dart';
import 'glassy_container.dart';

class AppShellDrawer extends StatelessWidget {
  const AppShellDrawer({super.key});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final auth = context.watch<AuthService>();
    final ws = context.watch<WebSocketService>();
    final currentPath = GoRouterState.of(context).uri.path;

    final items = const [
      _DrawerItem('Dashboard', Icons.dashboard_outlined, '/dashboard'),
      _DrawerItem('Devices', Icons.devices_outlined, '/devices'),
      _DrawerItem('Threat Map', Icons.public_outlined, '/threats'),
      _DrawerItem('Topology', Icons.hub_outlined, '/topology'),
      _DrawerItem('Firewall', Icons.security_outlined, '/firewall'),
      _DrawerItem('Honeypot', Icons.bug_report_outlined, '/honeypot'),
      _DrawerItem('System', Icons.monitor_heart_outlined, '/system'),
      _DrawerItem('Settings', Icons.settings_outlined, '/settings'),
    ];

    return Drawer(
      backgroundColor: Colors.transparent,
      child: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: GlassyContainer(
            borderRadius: 28,
            padding: const EdgeInsets.fromLTRB(16, 18, 16, 16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Container(
                      width: 44,
                      height: 44,
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(16),
                        color: theme.colorScheme.primary.withOpacity(0.12),
                      ),
                      child: Icon(
                        Icons.shield_outlined,
                        color: theme.colorScheme.primary,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'NO TIME TO HACK',
                            style: GoogleFonts.spaceGrotesk(
                              fontWeight: FontWeight.w700,
                              color: theme.colorScheme.onSurface,
                            ),
                          ),
                          Text(
                            auth.username.isEmpty ? 'Workspace' : auth.username,
                            style: TextStyle(
                              color:
                                  theme.colorScheme.onSurface.withOpacity(0.6),
                              fontSize: 12,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 18),
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                  decoration: BoxDecoration(
                    color:
                        (ws.connected ? theme.colorScheme.primary : Colors.red)
                            .withOpacity(0.10),
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Row(
                    children: [
                      Container(
                        width: 8,
                        height: 8,
                        decoration: BoxDecoration(
                          color: ws.connected
                              ? theme.colorScheme.primary
                              : Colors.red,
                          shape: BoxShape.circle,
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          ws.connected
                              ? 'Realtime connected'
                              : 'Realtime offline',
                          style: TextStyle(
                            color:
                                theme.colorScheme.onSurface.withOpacity(0.72),
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 18),
                Expanded(
                  child: ListView(
                    padding: EdgeInsets.zero,
                    children: items.map((item) {
                      final selected = currentPath == item.path;
                      return Padding(
                        padding: const EdgeInsets.only(bottom: 6),
                        child: ListTile(
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(16),
                          ),
                          tileColor: selected
                              ? theme.colorScheme.primary.withOpacity(0.12)
                              : Colors.transparent,
                          leading: Icon(
                            item.icon,
                            color: selected
                                ? theme.colorScheme.primary
                                : theme.colorScheme.onSurface.withOpacity(0.65),
                          ),
                          title: Text(
                            item.label,
                            style: TextStyle(
                              color: selected
                                  ? theme.colorScheme.primary
                                  : theme.colorScheme.onSurface,
                              fontWeight:
                                  selected ? FontWeight.w700 : FontWeight.w500,
                            ),
                          ),
                          onTap: () {
                            Navigator.of(context).pop();
                            if (!selected) {
                              context.go(item.path);
                            }
                          },
                        ),
                      );
                    }).toList(),
                  ),
                ),
                const SizedBox(height: 8),
                OutlinedButton.icon(
                  icon: const Icon(Icons.logout, size: 16),
                  label: const Text('Logout'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: Colors.red,
                    side: const BorderSide(color: Colors.red),
                    minimumSize: const Size(double.infinity, 48),
                  ),
                  onPressed: () async {
                    Navigator.of(context).pop();
                    context
                        .read<WebSocketService>()
                        .disconnect(clearEvents: true);
                    await context.read<AuthService>().logout();
                    if (context.mounted) context.go('/login');
                  },
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _DrawerItem {
  final String label;
  final IconData icon;
  final String path;

  const _DrawerItem(this.label, this.icon, this.path);
}
