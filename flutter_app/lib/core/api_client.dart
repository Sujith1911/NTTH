import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class ApiClient {
  static const String _defaultBaseUrl = 'http://localhost:8000/api/v1';

  late Dio _dio;
  final FlutterSecureStorage _storage;
  final Future<void> Function(String accessToken, String refreshToken)?
      _onTokensRefreshed;
  String _baseUrl;

  ApiClient(
    this._storage, {
    String? baseUrl,
    Future<void> Function(String accessToken, String refreshToken)?
        onTokensRefreshed,
  })  : _onTokensRefreshed = onTokensRefreshed,
        _baseUrl = baseUrl ?? _defaultBaseUrl {
    _buildDio();
  }

  void updateBaseUrl(String newUrl) {
    _baseUrl = '$newUrl/api/v1';
    _buildDio();
  }

  void _buildDio() {
    _dio = Dio(BaseOptions(
      baseUrl: _baseUrl,
      connectTimeout: const Duration(seconds: 10),
      receiveTimeout: const Duration(seconds: 30),
      headers: {'Content-Type': 'application/json'},
    ));

    _dio.interceptors.add(InterceptorsWrapper(
      onRequest: (options, handler) async {
        final token = await _storage.read(key: 'access_token');
        if (token != null) {
          options.headers['Authorization'] = 'Bearer $token';
        }
        handler.next(options);
      },
      onError: (error, handler) async {
        if (error.response?.statusCode == 401) {
          final refreshed = await _refreshToken();
          if (refreshed) {
            final token = await _storage.read(key: 'access_token');
            error.requestOptions.headers['Authorization'] = 'Bearer $token';
            final cloned = await _dio.fetch(error.requestOptions);
            return handler.resolve(cloned);
          }
        }
        handler.next(error);
      },
    ));
  }

  Future<bool> _refreshToken() async {
    try {
      final refresh = await _storage.read(key: 'refresh_token');
      if (refresh == null) return false;
      final plainDio = Dio(BaseOptions(baseUrl: _baseUrl));
      final resp = await plainDio.post(
        '/auth/refresh',
        data: {'refresh_token': refresh},
      );
      final accessToken = resp.data['access_token'] as String;
      final refreshToken = resp.data['refresh_token'] as String;
      await _storage.write(key: 'access_token', value: accessToken);
      await _storage.write(key: 'refresh_token', value: refreshToken);
      if (_onTokensRefreshed != null) {
        await _onTokensRefreshed(accessToken, refreshToken);
      }
      return true;
    } catch (_) {
      return false;
    }
  }

  Dio get dio => _dio;

  Future<Response> get(String path, {Map<String, dynamic>? params}) =>
      _dio.get(path, queryParameters: params);

  Future<Response> post(String path, dynamic data) =>
      _dio.post(path, data: data);

  Future<Response> put(String path, dynamic data) =>
      _dio.put(path, data: data);

  Future<Response> delete(String path) => _dio.delete(path);
}
