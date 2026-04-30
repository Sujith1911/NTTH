import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Manages the server base URL and persists it via secure storage.
/// Defaults to localhost for local development.
class AppSettings extends ChangeNotifier {
  static const _storage = FlutterSecureStorage();
  static const _keyBaseUrl = 'server_base_url';
  static const _keyWsUrl = 'server_ws_url';

  // localhost defaults — works for Flutter Web and Desktop on dev machine
  String _baseUrl = 'http://localhost:8001';
  String _wsUrl = 'ws://localhost:8001';

  String get baseUrl => _baseUrl;
  String get wsUrl => _wsUrl;
  String get apiBase => '$_baseUrl/api/v1';

  AppSettings() {
    _load();
  }

  Future<void> _load() async {
    _baseUrl = await _storage.read(key: _keyBaseUrl) ?? _baseUrl;
    _wsUrl = await _storage.read(key: _keyWsUrl) ?? _wsUrl;
    notifyListeners();
  }

  Future<void> setServerUrl(String baseUrl) async {
    _baseUrl = baseUrl.trimRight().replaceAll(RegExp(r'/$'), '');
    _wsUrl = _baseUrl.replaceAll('http://', 'ws://').replaceAll('https://', 'wss://');
    await _storage.write(key: _keyBaseUrl, value: _baseUrl);
    await _storage.write(key: _keyWsUrl, value: _wsUrl);
    notifyListeners();
  }
}
