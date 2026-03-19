class DeviceModel {
  final String id;
  final String ipAddress;
  final String? macAddress;
  final String? hostname;
  final String? vendor;
  final DateTime firstSeen;
  final DateTime lastSeen;
  final bool isTrusted;
  final double riskScore;

  const DeviceModel({
    required this.id,
    required this.ipAddress,
    this.macAddress,
    this.hostname,
    this.vendor,
    required this.firstSeen,
    required this.lastSeen,
    required this.isTrusted,
    required this.riskScore,
  });

  factory DeviceModel.fromJson(Map<String, dynamic> j) => DeviceModel(
        id: j['id'],
        ipAddress: j['ip_address'],
        macAddress: j['mac_address'],
        hostname: j['hostname'],
        vendor: j['vendor'],
        firstSeen: DateTime.parse(j['first_seen']),
        lastSeen: DateTime.parse(j['last_seen']),
        isTrusted: j['is_trusted'] ?? false,
        riskScore: (j['risk_score'] as num).toDouble(),
      );
}
