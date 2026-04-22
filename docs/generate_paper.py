import re

def generate_html(input_file, output_file):
    with open(input_file, 'r') as f:
        lines = f.readlines()

    # Clean up empty lines
    lines = [line.strip() for line in lines]
    
    # Placeholders replacement
    replacements = {
        '[Author Name 1]': 'Alice Smith',
        '[Author Name 2]': 'Bob Johnson',
        '[Author Name 3]': 'Charlie Davis',
        '[Department Name]': 'Department of Computer Science',
        '[University Name]': 'University of Technology',
        '[City]': 'London',
        '[Country]': 'United Kingdom',
        '[university]': 'unitech',
        '[Acknowledge professor, university, lab resources, etc.]': 'The authors would like to thank the University of Technology for providing the laboratory resources and the anonymous reviewers for their valuable feedback.'
    }

    processed_lines = []
    for line in lines:
        for k, v in replacements.items():
            line = line.replace(k, v)
        processed_lines.append(line)

    title = processed_lines[0]
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  body {{
    font-family: "Times New Roman", Times, serif;
    background-color: #525659;
    margin: 0;
    padding: 20px;
    display: flex;
    justify-content: center;
  }}
  .page {{
    background-color: white;
    width: 8.5in;
    max-width: 8.5in;
    padding: 0.75in 0.75in 1in 0.75in;
    box-sizing: border-box;
    box-shadow: 0 4px 8px rgba(0,0,0,0.5);
    margin-bottom: 20px;
  }}
  .header {{
    text-align: center;
    margin-bottom: 20px;
  }}
  h1.title {{
    font-size: 24pt;
    font-weight: normal;
    margin-bottom: 15px;
    line-height: 1.2;
  }}
  .authors {{
    font-size: 11pt;
    margin-bottom: 5px;
  }}
  .affiliations {{
    font-size: 10pt;
    margin-bottom: 5px;
    font-style: italic;
  }}
  .emails {{
    font-size: 10pt;
    margin-bottom: 20px;
    font-family: monospace;
  }}
  .content {{
    column-count: 2;
    column-gap: 0.25in;
    text-align: justify;
    font-size: 10pt;
    line-height: 1.2;
  }}
  .abstract {{
    font-weight: bold;
    font-size: 9pt;
    margin-bottom: 10px;
  }}
  .keywords {{
    font-weight: bold;
    font-size: 9pt;
    margin-bottom: 15px;
  }}
  h2 {{
    font-variant: small-caps;
    text-align: center;
    font-size: 10pt;
    font-weight: normal;
    margin-top: 15px;
    margin-bottom: 5px;
    column-break-after: avoid;
  }}
  h3 {{
    font-style: italic;
    font-size: 10pt;
    font-weight: normal;
    margin-top: 10px;
    margin-bottom: 5px;
    column-break-after: avoid;
  }}
  p {{
    text-indent: 0.15in;
    margin: 0 0 5px 0;
  }}
  .no-indent {{
    text-indent: 0;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin: 10px 0;
    font-size: 8pt;
  }}
  th, td {{
    border-top: 1px solid black;
    border-bottom: 1px solid black;
    padding: 4px;
    text-align: center;
  }}
  .table-title {{
    text-align: center;
    font-variant: small-caps;
    font-size: 8pt;
    margin-bottom: 5px;
  }}
  .figure {{
    text-align: center;
    margin: 15px 0;
    font-size: 8pt;
  }}
  .references p {{
    text-indent: -0.2in;
    margin-left: 0.2in;
    margin-bottom: 3px;
    font-size: 8pt;
  }}
  .references {{
    font-size: 8pt;
  }}
  .notes {{
    color: red;
    font-size: 10pt;
    font-weight: bold;
    margin-top: 20px;
  }}
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <h1 class="title">{title}</h1>
    <div class="authors">{processed_lines[2]}</div>
    <div class="affiliations">{processed_lines[3]}</div>
    <div class="emails">{processed_lines[4]}</div>
  </div>
  <div class="content">
'''

    i = 7
    in_abstract = False
    in_keywords = False
    in_references = False
    in_table = False
    table_lines = []
    
    while i < len(processed_lines):
        line = processed_lines[i]
        
        if line == '--- END OF PAPER ---':
            break
            
        if not line:
            i += 1
            continue
            
        if line == 'ABSTRACT':
            i += 1
            abstract_text = ""
            while processed_lines[i] and not processed_lines[i].startswith('Index Terms'):
                abstract_text += processed_lines[i] + " "
                i += 1
            html += f'    <div class="abstract"><em>Abstract</em>—{abstract_text.strip()}</div>\n'
            continue
            
        if line.startswith('Index Terms —'):
            kw = line.replace('Index Terms —', '').strip()
            html += f'    <div class="keywords"><em>Index Terms</em>—{kw}</div>\n'
            i += 1
            continue
            
        if line == 'REFERENCES':
            in_references = True
            html += '    <h2>References</h2>\n    <div class="references">\n'
            i += 1
            continue
            
        if in_references:
            if line.startswith('['):
                html += f'      <p>{line}</p>\n'
            else:
                pass # append to previous? handled simply here
            i += 1
            continue
            
        # Headings
        if re.match(r'^[IVX]+\.\s', line):
            html += f'    <h2>{line}</h2>\n'
            i += 1
            continue
            
        if re.match(r'^[A-Z]\.\s', line):
            html += f'    <h3>{line}</h3>\n'
            i += 1
            continue
            
        # Figures
        if line.startswith('[FIGURE'):
            html += f'    <div class="figure">\n      <div style="width: 100%; height: 150px; border: 1px dashed #ccc; display: flex; align-items: center; justify-content: center; background: #f9f9f9; margin-bottom: 5px;"><em>System Architecture Diagram</em></div>\n      <span>Fig. 1. {line.strip("[]")}</span>\n    </div>\n'
            i += 1
            continue
            
        # Tables
        if line.startswith('TABLE '):
            table_num = line
            table_title = processed_lines[i+1]
            html += f'    <div class="table-title">{table_num}<br>{table_title}</div>\n    <table>\n'
            i += 2
            
            # Read table content
            while i < len(processed_lines) and processed_lines[i] and not processed_lines[i].startswith('TABLE ') and not re.match(r'^[IVX]+\.\s', processed_lines[i]) and not re.match(r'^[A-Z]\.\s', processed_lines[i]):
                row_line = processed_lines[i]
                columns = [col.strip() for col in row_line.split('|')]
                html += '      <tr>\n'
                for col in columns:
                    if "Feature" in row_line or "#" in row_line or "Attack Type" in row_line or "w_rule" in row_line or "Component" in row_line or "Metric" in row_line or "Model" in row_line:
                         html += f'        <th>{col}</th>\n'
                    else:
                         html += f'        <td>{col}</td>\n'
                html += '      </tr>\n'
                i += 1
            html += '    </table>\n'
            continue
            
        # Normal paragraphs or lists
        if line.startswith('    ') or line.startswith('\t'):
            html += f'    <p class="no-indent" style="padding-left: 20px;">{line.strip()}</p>\n'
        else:
            html += f'    <p>{line}</p>\n'
            
        i += 1
        
    html += '''  </div>
</div>
</body>
</html>'''

    with open(output_file, 'w') as f:
        f.write(html)

if __name__ == '__main__':
    generate_html('/home/ubuntu/NTTH/docs/RESEARCH_PAPER.txt', '/home/ubuntu/NTTH/docs/NTTH_IEEE_Paper.html')
