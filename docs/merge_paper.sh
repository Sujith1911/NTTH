#!/bin/bash
# Merge 3 paper parts into single HTML with images
cd /home/ubuntu/NTTH/docs

# Copy images
IMG_DIR="/home/ubuntu/.gemini/antigravity/brain/5caeccb5-a257-43a2-aa35-b8d534f48ad5"
cp "$IMG_DIR"/fig1_topology_*.png ./fig1_topology.png 2>/dev/null
cp "$IMG_DIR"/fig2_pipeline_*.png ./fig2_pipeline.png 2>/dev/null
cp "$IMG_DIR"/fig3_dashboard_*.png ./fig3_dashboard.png 2>/dev/null
cp "$IMG_DIR"/fig4_testbed_*.png ./fig4_testbed.png 2>/dev/null
cp "$IMG_DIR"/fig5_latency_*.png ./fig5_latency.png 2>/dev/null
cp "$IMG_DIR"/fig6_radar_*.png ./fig6_radar.png 2>/dev/null

python3 -c "
import re

with open('NTTH_SPRINGER_PAPER_PART1.html') as f: p1 = f.read()
with open('NTTH_SPRINGER_PAPER_PART2.html') as f: p2 = f.read()
with open('NTTH_SPRINGER_PAPER_PART3.html') as f: p3 = f.read()

def body(h):
    m = re.search(r'<body>(.*?)</body>', h, re.DOTALL)
    return m.group(1).strip() if m else ''

b2 = body(p2)
b3 = body(p3)

# Remove end-of-part notices
b2 = re.sub(r'<p style=\"text-align: center.*?</p>', '', b2, flags=re.DOTALL)
merged = p1.replace('</body>','').replace('</html>','')
merged = re.sub(r'<p style=\"text-align: center.*?</p>', '', merged, flags=re.DOTALL)
merged = merged.replace('Part 1', 'Springer LNCS Conference Paper')

# Replace figure placeholders with actual images
fig_map = {
    'Figure 1: NTTH Gateway Deployment Topology': ('fig1_topology.png', 'Fig. 1'),
    'Figure 2: Event-Driven Processing Pipeline': ('fig2_pipeline.png', 'Fig. 2'),
    'Figure 3: Dashboard Interface': ('fig3_dashboard.png', 'Fig. 3'),
    'Figure 4: Experimental Testbed Layout': ('fig4_testbed.png', 'Fig. 4'),
    'Figure 5: Capture-to-Enforcement Latency': ('fig5_latency.png', 'Fig. 5'),
    'Figure 6: Feature Coverage Comparison': ('fig6_radar.png', 'Fig. 6'),
}

full = merged + '\n\n' + b2 + '\n\n' + b3 + '\n\n</body>\n</html>'

for key, (img, _) in fig_map.items():
    # Replace placeholder divs with img tags
    pattern = r'<div class=\"figure-placeholder\">.*?' + re.escape(key) + r'.*?</div>'
    replacement = f'<div style=\"text-align:center;margin:10pt 0;\"><img src=\"{img}\" style=\"max-width:100%;max-height:400px;\" alt=\"{key}\"></div>'
    full = re.sub(pattern, replacement, full, flags=re.DOTALL)

with open('NTTH_SPRINGER_PAPER_FULL.html', 'w') as f:
    f.write(full)
print(f'Done! Merged paper: {len(full):,} chars')
print('Output: NTTH_SPRINGER_PAPER_FULL.html')
"
echo "Images copied and paper merged!"
