class HoneypotModel {
  final String id;
  final String sessionId;
  final String attackerIp;
  final String? observedAttackerIp;
  final String honeypotType;
  final String? victimIp;
  final int? victimPort;
  final String? usernameTried;
  final String? passwordTried;
  final String? commandsRun;
  final double? durationSeconds;
  final bool sourceMasked;
  final String? sourceMaskReason;
  final String? country;
  final String? city;
  final String? asn;
  final String? org;
  final double? latitude;
  final double? longitude;
  final String? locationAccuracy;
  final String? locationSummary;
  final DateTime startedAt;
  final DateTime? endedAt;

  const HoneypotModel({
    required this.id,
    required this.sessionId,
    required this.attackerIp,
    this.observedAttackerIp,
    required this.honeypotType,
    this.victimIp,
    this.victimPort,
    this.usernameTried,
    this.passwordTried,
    this.commandsRun,
    this.durationSeconds,
    this.sourceMasked = false,
    this.sourceMaskReason,
    this.country,
    this.city,
    this.asn,
    this.org,
    this.latitude,
    this.longitude,
    this.locationAccuracy,
    this.locationSummary,
    required this.startedAt,
    this.endedAt,
  });

  factory HoneypotModel.fromJson(Map<String, dynamic> j) => HoneypotModel(
        id: j['id'],
        sessionId: j['session_id'],
        attackerIp: j['attacker_ip'],
        observedAttackerIp: j['observed_attacker_ip'],
        honeypotType: j['honeypot_type'],
        victimIp: j['victim_ip'],
        victimPort: j['victim_port'],
        usernameTried: j['username_tried'],
        passwordTried: j['password_tried'],
        commandsRun: j['commands_run'],
        durationSeconds: j['duration_seconds'] != null ? (j['duration_seconds'] as num).toDouble() : null,
        sourceMasked: j['source_masked'] == true,
        sourceMaskReason: j['source_mask_reason'],
        country: j['country'],
        city: j['city'],
        asn: j['asn'],
        org: j['org'],
        latitude: j['latitude'] != null ? (j['latitude'] as num).toDouble() : null,
        longitude: j['longitude'] != null ? (j['longitude'] as num).toDouble() : null,
        locationAccuracy: j['location_accuracy'],
        locationSummary: j['location_summary'],
        startedAt: DateTime.parse(j['started_at']),
        endedAt: j['ended_at'] != null ? DateTime.parse(j['ended_at']) : null,
      );
}
