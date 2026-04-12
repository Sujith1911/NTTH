class FirewallRuleModel {
  final String id;
  final String ruleType;
  final String targetIp;
  final int? targetPort;
  final String? matchDstIp;
  final int? matchDstPort;
  final String? protocol;
  final String? nftHandle;
  final bool isActive;
  final String? createdBy;
  final DateTime? expiresAt;
  final DateTime createdAt;
  final String? reason;

  const FirewallRuleModel({
    required this.id,
    required this.ruleType,
    required this.targetIp,
    this.targetPort,
    this.matchDstIp,
    this.matchDstPort,
    this.protocol,
    this.nftHandle,
    required this.isActive,
    this.createdBy,
    this.expiresAt,
    required this.createdAt,
    this.reason,
  });

  factory FirewallRuleModel.fromJson(Map<String, dynamic> j) => FirewallRuleModel(
        id: j['id'],
        ruleType: j['rule_type'],
        targetIp: j['target_ip'],
        targetPort: j['target_port'],
        matchDstIp: j['match_dst_ip'],
        matchDstPort: j['match_dst_port'],
        protocol: j['protocol'],
        nftHandle: j['nft_handle'],
        isActive: j['is_active'] ?? true,
        createdBy: j['created_by'],
        expiresAt: j['expires_at'] != null ? DateTime.parse(j['expires_at']) : null,
        createdAt: DateTime.parse(j['created_at']),
        reason: j['reason'],
      );

  bool get isExpired =>
      expiresAt != null && DateTime.now().isAfter(expiresAt!);
}
