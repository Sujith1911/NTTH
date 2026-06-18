import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class ApiClient {
  static String get _defaultBaseUrl => '${_defaultServerUrl()}/api/v1';

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

  /// GET with automatic retry on connection/timeout errors.
  /// Retries up to [maxRetries] times with exponential backoff.
  Future<Response> get(String path,
      {Map<String, dynamic>? params, int maxRetries = 2}) async {
    return _withRetry(
      () => _dio.get(path, queryParameters: params),
      maxRetries: maxRetries,
    );
  }

  Future<Response> post(String path, dynamic data) =>
      _dio.post(path, data: data);

  Future<Response> put(String path, dynamic data) =>
      _dio.put(path, data: data);

  Future<Response> delete(String path) => _dio.delete(path);

  /// Retry wrapper for transient network errors.
  /// Only retries on connection errors and timeouts, never on 4xx/5xx.
  Future<Response> _withRetry(
    Future<Response> Function() request, {
    int maxRetries = 2,
  }) async {
    int attempt = 0;
    while (true) {
      try {
        return await request();
      } on DioException catch (e) {
        final isRetryable = e.type == DioExceptionType.connectionError ||
            e.type == DioExceptionType.connectionTimeout ||
            e.type == DioExceptionType.receiveTimeout ||
            e.type == DioExceptionType.sendTimeout;
        if (!isRetryable || attempt >= maxRetries) rethrow;
        attempt++;
        // Exponential backoff: 500ms, 1500ms
        await Future.delayed(Duration(milliseconds: 300 + (attempt * 500)));
      }
    }
  }
}

/// Format a DioException into a short, user-friendly message.
String formatApiError(Object error) {
  if (error is DioException) {
    switch (error.type) {
      case DioExceptionType.connectionError:
      case DioExceptionType.connectionTimeout:
        return 'Cannot reach the server. Check your connection.';
      case DioExceptionType.receiveTimeout:
      case DioExceptionType.sendTimeout:
        return 'Server is taking too long to respond.';
      case DioExceptionType.badResponse:
        final code = error.response?.statusCode;
        final msg = error.response?.data?['detail'];
        if (msg != null) return '$msg (HTTP $code)';
        return 'Server error (HTTP $code)';
      case DioExceptionType.cancel:
        return 'Request was cancelled.';
      default:
        return 'Network error. Please retry.';
    }
  }
  return error.toString();
}

String _defaultServerUrl() {
  final current = Uri.base;
  if (current.hasScheme && current.host.isNotEmpty) {
    final port = current.hasPort ? ':${current.port}' : '';
    return '${current.scheme}://${current.host}$port';
  }
  return 'http://localhost:8001';
}
