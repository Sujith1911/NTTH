import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

class WebSocketService extends ChangeNotifier {
  // localhost default for dev
  static const _defaultWsBase = 'ws://localhost:8000/ws/live';

  String _wsBase = _defaultWsBase;
  WebSocketChannel? _channel;
  StreamSubscription? _sub;
  Timer? _reconnectTimer;
  final List<Map<String, dynamic>> _events = [];
  bool _connected = false;
  bool _shouldReconnect = true;
  int _reconnectAttempts = 0;
  DateTime? _lastConnectedAt;
  DateTime? _lastEventAt;
  String? _lastError;
  String? _activeToken;

  bool get connected => _connected;
  List<Map<String, dynamic>> get events => List.unmodifiable(_events);
  int get reconnectAttempts => _reconnectAttempts;
  DateTime? get lastConnectedAt => _lastConnectedAt;
  DateTime? get lastEventAt => _lastEventAt;
  String? get lastError => _lastError;

  void setWsBase(String wsUrl) {
    // wsUrl comes from AppSettings.wsUrl (e.g. ws://localhost:8000)
    final next = wsUrl.endsWith('/ws/live') ? wsUrl : '$wsUrl/ws/live';
    if (next == _wsBase) return;
    _wsBase = next;
    final token = _activeToken;
    if (token != null && _shouldReconnect) {
      unawaited(connect(token));
    }
  }

  Future<void> ensureConnected(String token) async {
    _activeToken = token;
    if (_connected && _reconnectAttempts == 0) return;
    if (_reconnectTimer != null) return;
    await connect(token);
  }

  Future<void> connect(String token) async {
    _activeToken = token;
    _shouldReconnect = true;
    disconnect();
    _shouldReconnect = true;
    final uri = Uri.parse('$_wsBase?token=$token');
    try {
      _channel = WebSocketChannel.connect(uri);
      await _channel!.ready;
      _reconnectTimer?.cancel();
      _reconnectAttempts = 0;
      _lastError = null;
      _lastConnectedAt = DateTime.now();
      _sub = _channel!.stream.listen(
        _onMessage,
        onError: (error) => _handleDisconnect(token, error: error),
        onDone: () => _handleDisconnect(token),
      );
      _setConnected(true);
    } catch (error) {
      _lastError = error.toString();
      _setConnected(false);
      _scheduleReconnect(token);
    }
  }

  void _handleDisconnect(String token, {Object? error}) {
    if (error != null) {
      _lastError = error.toString();
    }
    _setConnected(false);
    if (_shouldReconnect) {
      _scheduleReconnect(token);
    }
  }

  void _scheduleReconnect(String token) {
    _reconnectTimer?.cancel();
    _reconnectAttempts += 1;
    final seconds = (_reconnectAttempts * 2).clamp(2, 30);
    notifyListeners();
    _reconnectTimer = Timer(Duration(seconds: seconds), () => connect(token));
  }

  void _onMessage(dynamic raw) {
    try {
      final data = jsonDecode(raw as String) as Map<String, dynamic>;
      if (data['type'] == 'ping') return;
      _lastEventAt = DateTime.now();
      _events.insert(0, data);
      if (_events.length > 200) _events.removeLast();
      notifyListeners();
    } catch (_) {}
  }

  void _setConnected(bool v) {
    if (_connected == v) return;
    _connected = v;
    notifyListeners();
  }

  void disconnect({bool clearEvents = false}) {
    _shouldReconnect = false;
    _reconnectTimer?.cancel();
    _sub?.cancel();
    _channel?.sink.close();
    _sub = null;
    _channel = null;
    final wasConnected = _connected;
    _connected = false;
    if (clearEvents) {
      _events.clear();
      _activeToken = null;
    }
    if (!clearEvents) {
      _lastError ??= 'Disconnected';
    }
    if (wasConnected || clearEvents) {
      notifyListeners();
    }
  }

  @override
  void dispose() {
    disconnect();
    super.dispose();
  }
}
