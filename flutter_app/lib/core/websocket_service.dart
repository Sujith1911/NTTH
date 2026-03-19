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

  bool get connected => _connected;
  List<Map<String, dynamic>> get events => List.unmodifiable(_events);

  void setWsBase(String wsUrl) {
    // wsUrl comes from AppSettings.wsUrl (e.g. ws://localhost:8000)
    _wsBase = wsUrl.endsWith('/ws/live') ? wsUrl : '$wsUrl/ws/live';
  }

  Future<void> connect(String token) async {
    disconnect();
    final uri = Uri.parse('$_wsBase?token=$token');
    try {
      _channel = WebSocketChannel.connect(uri);
      await _channel!.ready;
      _sub = _channel!.stream.listen(
        _onMessage,
        onError: (_) => _handleDisconnect(token),
        onDone: () => _handleDisconnect(token),
      );
      _setConnected(true);
    } catch (_) {
      _setConnected(false);
      _scheduleReconnect(token);
    }
  }

  void _handleDisconnect(String token) {
    _setConnected(false);
    _scheduleReconnect(token);
  }

  void _scheduleReconnect(String token) {
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(const Duration(seconds: 5), () => connect(token));
  }

  void _onMessage(dynamic raw) {
    try {
      final data = jsonDecode(raw as String) as Map<String, dynamic>;
      if (data['type'] == 'ping') return;
      _events.insert(0, data);
      if (_events.length > 200) _events.removeLast();
      notifyListeners();
    } catch (_) {}
  }

  void _setConnected(bool v) {
    _connected = v;
    notifyListeners();
  }

  void disconnect() {
    _reconnectTimer?.cancel();
    _sub?.cancel();
    _channel?.sink.close();
    _channel = null;
    _connected = false;
  }

  @override
  void dispose() {
    disconnect();
    super.dispose();
  }
}
