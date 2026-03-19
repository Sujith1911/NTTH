# NO TIME TO HACK — Flutter App

## Setup

```bash
flutter pub get
flutter analyze
```

## Run

```bash
# Android
flutter run -d android

# Windows Desktop
flutter run -d windows
```

## Configuration

Edit `lib/core/api_client.dart` and `lib/core/websocket_service.dart`:

```dart
static const String _baseUrl = 'http://<your-server-ip>:8000/api/v1';
// and
static const String _wsBase = 'ws://<your-server-ip>:8000/ws/live';
```

## Screens

| Screen | Route | Description |
|---|---|---|
| Login | `/login` | JWT authentication |
| Dashboard | `/dashboard` | Live event feed + stats |
| Devices | `/devices` | Discovered LAN devices |
| Threat Map | `/threats` | World map of attacks |
| Firewall | `/firewall` | Active rules management |
| Honeypot | `/honeypot` | Session log + Cowrie control |
| System | `/system` | Health status |
