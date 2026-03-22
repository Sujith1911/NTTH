import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'api_client.dart';

class AuthService extends ChangeNotifier {
  final FlutterSecureStorage _storage;
  late final ApiClient _api;

  String? _accessToken;
  String? _username;
  String? _role;
  bool _isAuthenticated = false;

  AuthService(this._storage) {
    _api = ApiClient(_storage, onTokensRefreshed: _updateTokens);
    _tryRestoreSession();
  }

  bool get isAuthenticated => _isAuthenticated;
  String get username => _username ?? '';
  String get role => _role ?? 'user';
  bool get isAdmin => _role == 'admin';
  String? get accessToken => _accessToken;
  ApiClient get api => _api;

  Future<void> _tryRestoreSession() async {
    final token = await _storage.read(key: 'access_token');
    if (token != null) {
      _accessToken = token;
      _username = await _storage.read(key: 'username');
      _role = _decodeRole(token) ?? await _storage.read(key: 'role');
      _isAuthenticated = true;
      notifyListeners();
    }
  }

  Future<String?> login(String username, String password) async {
    try {
      final resp = await _api.post('/auth/login', {
        'username': username,
        'password': password,
      });
      final data = resp.data as Map<String, dynamic>;
      await _updateTokens(
        data['access_token'] as String,
        data['refresh_token'] as String,
        notify: false,
      );
      await _storage.write(key: 'username', value: username);

      _username = username;
      _isAuthenticated = true;
      notifyListeners();
      return null;
    } catch (e) {
      return e.toString();
    }
  }

  Future<void> logout() async {
    await _storage.deleteAll();
    _accessToken = null;
    _username = null;
    _role = null;
    _isAuthenticated = false;
    notifyListeners();
  }

  Future<void> _updateTokens(
    String accessToken,
    String refreshToken, {
    bool notify = true,
  }) async {
    _accessToken = accessToken;
    _role = _decodeRole(accessToken) ?? _role ?? 'user';
    await _storage.write(key: 'access_token', value: accessToken);
    await _storage.write(key: 'refresh_token', value: refreshToken);
    await _storage.write(key: 'role', value: _role ?? 'user');
    if (notify) {
      notifyListeners();
    }
  }

  String? _decodeRole(String token) {
    try {
      final parts = token.split('.');
      if (parts.length != 3) return 'user';
      final normalized = base64Url.normalize(parts[1]);
      final decoded = utf8.decode(base64Url.decode(normalized));
      final payload = jsonDecode(decoded) as Map<String, dynamic>;
      return payload['role']?.toString() ?? 'user';
    } catch (_) {
      return 'user';
    }
  }
}
