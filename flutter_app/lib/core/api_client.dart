import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class ApiClient {
  // Default to localhost for dev — user can override in Settings screen
  static const String _defaultBaseUrl = 'http://localhost:8000/api/v1';

  late Dio _dio;
  final FlutterSecureStorage _storage;
  String _baseUrl;

  ApiClient(this._storage, {String? baseUrl})
      : _baseUrl = baseUrl ?? _defaultBaseUrl {
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

  /// Token refresh sends the refresh_token in the REQUEST BODY (not query param).
  Future<bool> _refreshToken() async {
    try {
      final refresh = await _storage.read(key: 'refresh_token');
      if (refresh == null) return false;
      // Create a bare Dio to avoid interceptor loops
      final plainDio = Dio(BaseOptions(baseUrl: _baseUrl));
      final resp = await plainDio.post(
        '/auth/refresh',
        data: {'refresh_token': refresh},
      );
      await _storage.write(key: 'access_token', value: resp.data['access_token']);
      await _storage.write(key: 'refresh_token', value: resp.data['refresh_token']);
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
