class HoneypotModel {
  final String id;
  final String sessionId;
  final String attackerIp;
  final String honeypotType;
  final String? usernameTried;
  final String? passwordTried;
  final String? commandsRun;
  final double? durationSeconds;
  final String? country;
  final String? city;
  final double? latitude;
  final double? longitude;
  final DateTime startedAt;
  final DateTime? endedAt;

  const HoneypotModel({
    required this.id,
    required this.sessionId,
    required this.attackerIp,
    required this.honeypotType,
    this.usernameTried,
    this.passwordTried,
    this.commandsRun,
    this.durationSeconds,
    this.country,
    this.city,
    this.latitude,
    this.longitude,
    required this.startedAt,
    this.endedAt,
  });

  factory HoneypotModel.fromJson(Map<String, dynamic> j) => HoneypotModel(
        id: j['id'],
        sessionId: j['session_id'],
        attackerIp: j['attacker_ip'],
        honeypotType: j['honeypot_type'],
        usernameTried: j['username_tried'],
        passwordTried: j['password_tried'],
        commandsRun: j['commands_run'],
        durationSeconds: j['duration_seconds'] != null ? (j['duration_seconds'] as num).toDouble() : null,
        country: j['country'],
        city: j['city'],
        latitude: j['latitude'] != null ? (j['latitude'] as num).toDouble() : null,
        longitude: j['longitude'] != null ? (j['longitude'] as num).toDouble() : null,
        startedAt: DateTime.parse(j['started_at']),
        endedAt: j['ended_at'] != null ? DateTime.parse(j['ended_at']) : null,
      );
}
