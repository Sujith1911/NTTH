class ThreatModel {
  final String id;
  final String srcIp;
  final String? dstIp;
  final int? dstPort;
  final String? protocol;
  final String threatType;
  final double riskScore;
  final String? actionTaken;
  final String? country;
  final String? city;
  final String? asn;
  final double? latitude;
  final double? longitude;
  final DateTime detectedAt;
  final bool acknowledged;

  const ThreatModel({
    required this.id,
    required this.srcIp,
    this.dstIp,
    this.dstPort,
    this.protocol,
    required this.threatType,
    required this.riskScore,
    this.actionTaken,
    this.country,
    this.city,
    this.asn,
    this.latitude,
    this.longitude,
    required this.detectedAt,
    required this.acknowledged,
  });

  factory ThreatModel.fromJson(Map<String, dynamic> j) => ThreatModel(
        id: j['id'],
        srcIp: j['src_ip'],
        dstIp: j['dst_ip'],
        dstPort: j['dst_port'],
        protocol: j['protocol'],
        threatType: j['threat_type'],
        riskScore: (j['risk_score'] as num).toDouble(),
        actionTaken: j['action_taken'],
        country: j['country'],
        city: j['city'],
        asn: j['asn'],
        latitude: j['latitude'] != null ? (j['latitude'] as num).toDouble() : null,
        longitude: j['longitude'] != null ? (j['longitude'] as num).toDouble() : null,
        detectedAt: DateTime.parse(j['detected_at']),
        acknowledged: j['acknowledged'] ?? false,
      );
}
