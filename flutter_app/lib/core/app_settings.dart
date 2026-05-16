import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Manages the server base URL and persists it via secure storage.
/// Defaults to localhost for local development.
class AppSettings extends ChangeNotifier {
  static const _storage = FlutterSecureStorage();
  static const _keyBaseUrl = 'server_base_url';
  static const _keyWsUrl = 'server_ws_url';

  String _baseUrl = _defaultServerUrl();
  String _wsUrl = _toWsUrl(_defaultServerUrl());

  String get baseUrl => _baseUrl;
  String get wsUrl => _wsUrl;
  String get apiBase => '$_baseUrl/api/v1';

  AppSettings() {
    _load();
  }

  Future<void> _load() async {
    final storedBaseUrl = await _storage.read(key: _keyBaseUrl);
    final storedWsUrl = await _storage.read(key: _keyWsUrl);
    _baseUrl = _normalizeStoredUrl(storedBaseUrl) ?? _baseUrl;
    _wsUrl = storedWsUrl == null ? _toWsUrl(_baseUrl) : _normalizeStoredWsUrl(storedWsUrl);
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

String _defaultServerUrl() {
  final current = Uri.base;
  if (current.hasScheme && current.host.isNotEmpty) {
    final port = current.hasPort ? ':${current.port}' : '';
    return '${current.scheme}://${current.host}$port';
  }
  return 'http://localhost:8001';
}

String _toWsUrl(String baseUrl) {
  return baseUrl.replaceAll('http://', 'ws://').replaceAll('https://', 'wss://');
}

String? _normalizeStoredUrl(String? stored) {
  if (stored == null) return null;
  final currentDefault = _defaultServerUrl();
  final storedUri = Uri.tryParse(stored);
  final currentUri = Uri.tryParse(currentDefault);
  if (storedUri == null || currentUri == null) return stored;

  final storedIsLocalhost =
      storedUri.host == 'localhost' || storedUri.host == '127.0.0.1';
  final currentIsRemote =
      currentUri.host.isNotEmpty &&
      currentUri.host != 'localhost' &&
      currentUri.host != '127.0.0.1';
  if (storedIsLocalhost && currentIsRemote) {
    return currentDefault;
  }
  return stored;
}

String _normalizeStoredWsUrl(String stored) {
  final normalizedBase = _normalizeStoredUrl(
    stored.replaceAll('ws://', 'http://').replaceAll('wss://', 'https://'),
  );
  return _toWsUrl(normalizedBase ?? _defaultServerUrl());
}
