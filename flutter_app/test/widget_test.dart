import 'package:flutter_test/flutter_test.dart';

import 'package:no_time_to_hack/models/device_model.dart';
import 'package:no_time_to_hack/models/threat_model.dart';

void main() {
  test('DeviceModel parses API payloads', () {
    final model = DeviceModel.fromJson({
      'id': 'dev-1',
      'ip_address': '192.168.1.10',
      'mac_address': 'aa:bb:cc:dd:ee:ff',
      'hostname': 'camera',
      'vendor': 'Acme',
      'first_seen': '2026-03-19T00:00:00Z',
      'last_seen': '2026-03-19T00:05:00Z',
      'is_trusted': true,
      'risk_score': 0.2,
    });

    expect(model.id, 'dev-1');
    expect(model.ipAddress, '192.168.1.10');
    expect(model.isTrusted, isTrue);
    expect(model.riskScore, 0.2);
  });

  test('ThreatModel parses realtime payload fields', () {
    final model = ThreatModel.fromJson({
      'id': 'thr-1',
      'src_ip': '203.0.113.77',
      'dst_ip': '192.168.1.1',
      'dst_port': 22,
      'protocol': 'tcp',
      'threat_type': 'port_scan',
      'risk_score': 0.6,
      'action_taken': 'log',
      'country': 'Testland',
      'city': 'Example City',
      'asn': 'AS64500',
      'latitude': 12.34,
      'longitude': 56.78,
      'detected_at': '2026-03-19T00:00:00Z',
      'acknowledged': false,
    });

    expect(model.id, 'thr-1');
    expect(model.srcIp, '203.0.113.77');
    expect(model.actionTaken, 'log');
    expect(model.latitude, 12.34);
    expect(model.acknowledged, isFalse);
  });
}
