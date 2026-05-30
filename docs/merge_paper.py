#!/usr/bin/env python3
"""Merge NTTH Springer paper parts 1-3 into a single HTML file."""
import re

def extract_body(html):
    """Extract content between <body> and </body>."""
    m = re.search(r'<body>(.*?)</body>', html, re.DOTALL)
    return m.group(1).strip() if m else ''

# Read all parts
with open('/home/ubuntu/NTTH/docs/NTTH_SPRINGER_PAPER_PART1.html') as f:
    p1 = f.read()
with open('/home/ubuntu/NTTH/docs/NTTH_SPRINGER_PAPER_PART2.html') as f:
    p2 = f.read()
with open('/home/ubuntu/NTTH/docs/NTTH_SPRINGER_PAPER_PART3.html') as f:
    p3 = f.read()

# Extract body content from parts 2 and 3
body2 = extract_body(p2)
body3 = extract_body(p3)

# Remove "End of Part" notices
body2 = re.sub(r'<p style="text-align: center.*?</p>', '', body2, flags=re.DOTALL)

# Remove closing tags from part 1
merged = p1.replace('</body>', '').replace('</html>', '')

# Remove the "End of Part 1" notice from part 1
merged = re.sub(r'<p style="text-align: center.*?</p>', '', merged, flags=re.DOTALL)

# Fix title
merged = merged.replace('NTTH: Springer LNCS Research Paper \u2014 Part 1',
                        'NTTH: An Event-Driven Security Gateway for Transparent Risk Scoring')

# Combine
merged = merged.rstrip() + '\n\n' + body2 + '\n\n' + body3 + '\n\n</body>\n</html>\n'

# Write merged file
with open('/home/ubuntu/NTTH/docs/NTTH_SPRINGER_PAPER_FULL.html', 'w') as f:
    f.write(merged)

print(f"Merged paper: {len(merged):,} characters")
print(f"Sections: Introduction through References")
print("Output: /home/ubuntu/NTTH/docs/NTTH_SPRINGER_PAPER_FULL.html")
