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
    _api = ApiClient(_storage);
    _tryRestoreSession();
  }

  bool get isAuthenticated => _isAuthenticated;
  String get username => _username ?? '';
  String get role => _role ?? 'user';
  bool get isAdmin => _role == 'admin';
  ApiClient get api => _api;

  Future<void> _tryRestoreSession() async {
    final token = await _storage.read(key: 'access_token');
    if (token != null) {
      _accessToken = token;
      _username = await _storage.read(key: 'username');
      _role = await _storage.read(key: 'role');
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
      _accessToken = data['access_token'];

      await _storage.write(key: 'access_token', value: data['access_token']);
      await _storage.write(key: 'refresh_token', value: data['refresh_token']);
      await _storage.write(key: 'username', value: username);

      // Decode role from JWT payload (simple base64 decode)
      _role = _decodeRole(data['access_token']);
      await _storage.write(key: 'role', value: _role ?? 'user');

      _username = username;
      _isAuthenticated = true;
      notifyListeners();
      return null; // success
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

  String? _decodeRole(String token) {
    try {
      final parts = token.split('.');
      if (parts.length != 3) return 'user';
      final payload = parts[1];
      final padded = payload + '=' * ((4 - payload.length % 4) % 4);
      final decoded = String.fromCharCodes(
        Uri.parse('data:application/octet-stream;base64,$padded')
            .data!
            .contentAsBytes(),
      );
      final map = RegExp(r'"role"\s*:\s*"(\w+)"').firstMatch(decoded);
      return map?.group(1) ?? 'user';
    } catch (_) {
      return 'user';
    }
  }
}
