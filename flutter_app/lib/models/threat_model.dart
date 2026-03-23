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
  final String? org;
  final double? latitude;
  final double? longitude;
  final DateTime detectedAt;
  final bool acknowledged;
  final String? sourceTag;
  final String? victimIp;
  final String? responseMode;
  final String? locationAccuracy;
  final String? locationSummary;
  final String? networkOrigin;
  final bool targetHidden;
  final bool quarantineTarget;
  final int? honeypotPort;
  final String? notes;

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
    this.org,
    this.latitude,
    this.longitude,
    required this.detectedAt,
    required this.acknowledged,
    this.sourceTag,
    this.victimIp,
    this.responseMode,
    this.locationAccuracy,
    this.locationSummary,
    this.networkOrigin,
    this.targetHidden = false,
    this.quarantineTarget = false,
    this.honeypotPort,
    this.notes,
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
        org: j['org'],
        latitude: j['latitude'] != null ? (j['latitude'] as num).toDouble() : null,
        longitude: j['longitude'] != null ? (j['longitude'] as num).toDouble() : null,
        detectedAt: DateTime.parse(j['detected_at']),
        acknowledged: j['acknowledged'] ?? false,
        sourceTag: j['source_tag'],
        victimIp: j['victim_ip'],
        responseMode: j['response_mode'],
        locationAccuracy: j['location_accuracy'],
        locationSummary: j['location_summary'],
        networkOrigin: j['network_origin'],
        targetHidden: j['target_hidden'] ?? false,
        quarantineTarget: j['quarantine_target'] ?? false,
        honeypotPort: j['honeypot_port'],
        notes: j['notes'],
      );
}
