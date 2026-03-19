import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class RiskCard extends StatelessWidget {
  final String title;
  final String value;
  final IconData icon;
  final Color color;

  const RiskCard({
    super.key,
    required this.title,
    required this.value,
    required this.icon,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: const Color(0xFF111827),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0xFF1F2937)),
      ),
      child: Row(children: [
        Container(
          width: 44, height: 44,
          decoration: BoxDecoration(
            color: color.withOpacity(0.12),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, color: color, size: 22),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(
              value,
              style: GoogleFonts.inter(
                fontSize: 26, fontWeight: FontWeight.w800, color: Colors.white),
            ),
            Text(
              title,
              style: const TextStyle(color: Colors.white38, fontSize: 12),
            ),
          ]),
        ),
      ]),
    );
  }
}
