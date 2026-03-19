import 'package:flutter/material.dart';
import 'package:flutter_map/flutter_map.dart';
import 'package:latlong2/latlong.dart';

import '../models/threat_model.dart';

class AttackMapWidget extends StatelessWidget {
  final List<ThreatModel> threats;

  const AttackMapWidget({super.key, required this.threats});

  @override
  Widget build(BuildContext context) {
    return FlutterMap(
      options: MapOptions(
        initialCenter: const LatLng(20, 0),
        initialZoom: 2.0,
        backgroundColor: const Color(0xFF080C18),
      ),
      children: [
        TileLayer(
          urlTemplate: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
          userAgentPackageName: 'com.ntth.app',
          tileBuilder: (context, child, tile) => ColorFiltered(
            colorFilter: const ColorFilter.matrix([
              -0.2126, -0.7152, -0.0722, 0, 180,
              -0.2126, -0.7152, -0.0722, 0, 180,
              -0.2126, -0.7152, -0.0722, 0, 180,
              0,       0,       0,       1, 0,
            ]),
            child: child,
          ),
        ),
        CircleLayer(
          circles: threats.map((t) {
            final color = _threatColor(t.riskScore);
            return CircleMarker(
              point: LatLng(t.latitude!, t.longitude!),
              radius: 8 + (t.riskScore * 12),
              color: color.withOpacity(0.3),
              borderColor: color,
              borderStrokeWidth: 1.5,
            );
          }).toList(),
        ),
        MarkerLayer(
          markers: threats.map((t) => Marker(
            point: LatLng(t.latitude!, t.longitude!),
            width: 24,
            height: 24,
            child: Tooltip(
              message: '${t.srcIp}\n${t.country ?? ""}\nRisk: ${(t.riskScore * 100).toInt()}%',
              child: Icon(
                Icons.location_on,
                color: _threatColor(t.riskScore),
                size: 20,
              ),
            ),
          )).toList(),
        ),
      ],
    );
  }

  Color _threatColor(double score) {
    if (score > 0.85) return Colors.red;
    if (score > 0.5) return Colors.orange;
    return const Color(0xFF00FF88);
  }
}
