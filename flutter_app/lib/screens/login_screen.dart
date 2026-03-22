import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:provider/provider.dart';

import '../core/auth_service.dart';
import '../widgets/glassy_container.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen>
    with SingleTickerProviderStateMixin {
  final _formKey = GlobalKey<FormState>();
  final _userCtrl = TextEditingController();
  final _passCtrl = TextEditingController();
  bool _loading = false;
  bool _obscure = true;
  String? _error;
  late AnimationController _animCtrl;
  late Animation<double> _fadeAnim;

  @override
  void initState() {
    super.initState();
    _animCtrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 900),
    );
    _fadeAnim = CurvedAnimation(parent: _animCtrl, curve: Curves.easeOutCubic);
    _animCtrl.forward();
  }

  @override
  void dispose() {
    _animCtrl.dispose();
    _userCtrl.dispose();
    _passCtrl.dispose();
    super.dispose();
  }

  Future<void> _login() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() {
      _loading = true;
      _error = null;
    });
    final auth = context.read<AuthService>();
    final err = await auth.login(_userCtrl.text.trim(), _passCtrl.text);
    if (!mounted) return;
    if (err != null) {
      setState(() {
        _error = 'Invalid credentials';
        _loading = false;
      });
    } else {
      context.go('/dashboard');
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;
    final width = MediaQuery.of(context).size.width;
    final isCompact = width < 900;

    return Scaffold(
      body: Container(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: isDark
                ? const [Color(0xFF07111F), Color(0xFF0B1830), Color(0xFF07111F)]
                : const [Color(0xFFF4F8FC), Color(0xFFE7F0FB), Color(0xFFF8FBFE)],
          ),
        ),
        child: Stack(
          children: [
            Positioned(
              top: -120,
              left: -60,
              child: _GlowOrb(
                size: 320,
                color: theme.colorScheme.primary.withOpacity(isDark ? 0.16 : 0.12),
              ),
            ),
            Positioned(
              right: -90,
              bottom: -100,
              child: _GlowOrb(
                size: 360,
                color: theme.colorScheme.secondary.withOpacity(isDark ? 0.12 : 0.10),
              ),
            ),
            SafeArea(
              child: Center(
                child: FadeTransition(
                  opacity: _fadeAnim,
                  child: Padding(
                    padding: const EdgeInsets.all(24),
                    child: ConstrainedBox(
                      constraints: const BoxConstraints(maxWidth: 1180),
                      child: Flex(
                        direction: isCompact ? Axis.vertical : Axis.horizontal,
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          Expanded(
                            flex: isCompact ? 0 : 11,
                            child: Padding(
                              padding: EdgeInsets.only(
                                right: isCompact ? 0 : 24,
                                bottom: isCompact ? 24 : 0,
                              ),
                              child: _buildIntroPanel(theme, isDark, isCompact),
                            ),
                          ),
                          Expanded(
                            flex: 9,
                            child: Align(
                              alignment: Alignment.center,
                              child: ConstrainedBox(
                                constraints: const BoxConstraints(maxWidth: 460),
                                child: GlassyContainer(
                                  padding: const EdgeInsets.all(32),
                                  blur: 20,
                                  borderRadius: 32,
                                  child: Column(
                                    mainAxisSize: MainAxisSize.min,
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      Container(
                                        padding: const EdgeInsets.all(18),
                                        decoration: BoxDecoration(
                                          borderRadius: BorderRadius.circular(24),
                                          color: theme.colorScheme.primary.withOpacity(
                                            isDark ? 0.18 : 0.12,
                                          ),
                                        ),
                                        child: Icon(
                                          Icons.shield_outlined,
                                          color: theme.colorScheme.primary,
                                          size: 34,
                                        ),
                                      ),
                                      const SizedBox(height: 24),
                                      Text(
                                        'Control room access',
                                        style: GoogleFonts.spaceGrotesk(
                                          fontSize: 28,
                                          fontWeight: FontWeight.w700,
                                          color: theme.colorScheme.onSurface,
                                        ),
                                      ),
                                      const SizedBox(height: 10),
                                      Text(
                                        'Sign in to monitor devices, inspect live telemetry, and manage honeypot activity from one console.',
                                        style: TextStyle(
                                          fontSize: 14,
                                          height: 1.6,
                                          color: theme.colorScheme.onSurface.withOpacity(0.68),
                                        ),
                                      ),
                                      const SizedBox(height: 28),
                                      Form(
                                        key: _formKey,
                                        child: Column(
                                          children: [
                                            _buildField(
                                              controller: _userCtrl,
                                              label: 'Username',
                                              icon: Icons.person_outline,
                                              theme: theme,
                                              validator: (v) => v!.isEmpty ? 'Required' : null,
                                            ),
                                            const SizedBox(height: 16),
                                            _buildField(
                                              controller: _passCtrl,
                                              label: 'Password',
                                              icon: Icons.lock_outline,
                                              theme: theme,
                                              obscure: _obscure,
                                              suffix: IconButton(
                                                icon: Icon(
                                                  _obscure
                                                      ? Icons.visibility_off
                                                      : Icons.visibility,
                                                  color: theme.colorScheme.onSurface.withOpacity(0.5),
                                                  size: 20,
                                                ),
                                                onPressed: () {
                                                  setState(() => _obscure = !_obscure);
                                                },
                                              ),
                                              validator: (v) => v!.isEmpty ? 'Required' : null,
                                            ),
                                            if (_error != null) ...[
                                              const SizedBox(height: 14),
                                              Container(
                                                width: double.infinity,
                                                padding: const EdgeInsets.symmetric(
                                                  horizontal: 16,
                                                  vertical: 12,
                                                ),
                                                decoration: BoxDecoration(
                                                  color: Colors.red.withOpacity(0.1),
                                                  borderRadius: BorderRadius.circular(16),
                                                  border: Border.all(
                                                    color: Colors.red.withOpacity(0.28),
                                                  ),
                                                ),
                                                child: Row(
                                                  children: [
                                                    const Icon(
                                                      Icons.error_outline,
                                                      color: Colors.red,
                                                      size: 18,
                                                    ),
                                                    const SizedBox(width: 10),
                                                    Text(
                                                      _error!,
                                                      style: const TextStyle(
                                                        color: Colors.red,
                                                        fontSize: 13,
                                                      ),
                                                    ),
                                                  ],
                                                ),
                                              ),
                                            ],
                                            const SizedBox(height: 22),
                                            SizedBox(
                                              width: double.infinity,
                                              height: 56,
                                              child: ElevatedButton(
                                                onPressed: _loading ? null : _login,
                                                child: _loading
                                                    ? const SizedBox(
                                                        width: 20,
                                                        height: 20,
                                                        child: CircularProgressIndicator(
                                                          strokeWidth: 2,
                                                        ),
                                                      )
                                                    : const Text('Enter Workspace'),
                                              ),
                                            ),
                                          ],
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildIntroPanel(ThemeData theme, bool isDark, bool isCompact) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          decoration: BoxDecoration(
            color: theme.colorScheme.primary.withOpacity(isDark ? 0.18 : 0.10),
            borderRadius: BorderRadius.circular(999),
          ),
          child: Text(
            'Realtime network defense',
            style: GoogleFonts.spaceGrotesk(
              fontWeight: FontWeight.w700,
              letterSpacing: 0.5,
              color: theme.colorScheme.primary,
            ),
          ),
        ),
        const SizedBox(height: 24),
        Text(
          'A calmer, clearer operations view for live device telemetry.',
          style: GoogleFonts.spaceGrotesk(
            fontSize: isCompact ? 34 : 52,
            height: 1.05,
            fontWeight: FontWeight.w700,
            color: theme.colorScheme.onSurface,
          ),
        ),
        const SizedBox(height: 18),
        ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 620),
          child: Text(
            'Track your active network, inspect threats, and review honeypot activity in a responsive console designed for phones, tablets, laptops, and large displays.',
            style: TextStyle(
              fontSize: 16,
              height: 1.7,
              color: theme.colorScheme.onSurface.withOpacity(0.72),
            ),
          ),
        ),
        const SizedBox(height: 28),
        Wrap(
          spacing: 14,
          runSpacing: 14,
          children: const [
            _FeaturePill(icon: Icons.wifi_tethering, label: 'Live topology updates'),
            _FeaturePill(icon: Icons.hub_outlined, label: 'Responsive control room'),
            _FeaturePill(icon: Icons.bug_report_outlined, label: 'Honeypot telemetry'),
          ],
        ),
      ],
    );
  }

  Widget _buildField({
    required TextEditingController controller,
    required String label,
    required IconData icon,
    required ThemeData theme,
    bool obscure = false,
    Widget? suffix,
    String? Function(String?)? validator,
  }) {
    return TextFormField(
      controller: controller,
      obscureText: obscure,
      style: TextStyle(color: theme.colorScheme.onSurface),
      validator: validator,
      decoration: InputDecoration(
        labelText: label,
        labelStyle: TextStyle(color: theme.colorScheme.onSurface.withOpacity(0.54)),
        prefixIcon: Icon(icon, color: theme.colorScheme.primary, size: 20),
        suffixIcon: suffix,
      ),
    );
  }
}

class _FeaturePill extends StatelessWidget {
  final IconData icon;
  final String label;

  const _FeaturePill({required this.icon, required this.label});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return GlassyContainer(
      borderRadius: 999,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 18, color: theme.colorScheme.primary),
          const SizedBox(width: 10),
          Text(
            label,
            style: TextStyle(
              color: theme.colorScheme.onSurface.withOpacity(0.76),
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }
}

class _GlowOrb extends StatelessWidget {
  final double size;
  final Color color;

  const _GlowOrb({required this.size, required this.color});

  @override
  Widget build(BuildContext context) {
    return IgnorePointer(
      child: Container(
        width: size,
        height: size,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          gradient: RadialGradient(colors: [color, color.withOpacity(0)]),
        ),
      ),
    );
  }
}
