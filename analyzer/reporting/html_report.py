import tempfile
import webbrowser
import os
import datetime
import html
import json
import re

def generate_html_report(analysis_data, text_report):
    """
    Generates a self-contained HTML report from the analysis data.
    """
    parsed_sections = _parse_to_sections(text_report)
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Elasticsearch Cluster Analysis Report</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <style>
            :root {{
                --primary-color: #0077CC;
                --secondary-color: #005599;
                --bg-color: #f4f7f9;
                --text-color: #334155;
                --warning-color: #e74c3c;
                --success-color: #2ecc71;
                --border-color: #e2e8f0;
                --header-height: 70px;
            }}

            body {{
                font-family: 'Inter', sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 0;
                background-color: var(--bg-color);
                color: var(--text-color);
            }}
            
            .header {{
                background: white;
                padding: 0 30px;
                height: var(--header-height);
                display: flex;
                align-items: center;
                position: sticky;
                top: 0;
                box-shadow: 0 1px 3px rgba(0,0,0,0.05);
                z-index: 100;
            }}

            .header h1 {{
                font-size: 22px;
                font-weight: 600;
                margin: 0;
            }}
            .header .timestamp {{
                font-size: 13px;
                color: #64748b;
                margin-left: auto;
            }}

            .main-layout {{
                display: flex;
                max-width: 1600px;
                margin: 20px auto;
                padding: 0 20px;
                gap: 20px;
            }}

            .side-nav {{
                flex: 0 0 240px;
                background: white;
                border-radius: 8px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.05);
                padding: 10px;
                height: calc(100vh - var(--header-height) - 40px);
                position: sticky;
                top: calc(var(--header-height) + 20px);
                overflow-y: auto;
            }}

            .main-content {{
                flex: 1;
                min-width: 0;
            }}

            .nav-tab {{
                display: block;
                padding: 10px 15px;
                cursor: pointer;
                border-radius: 6px;
                font-weight: 500;
                color: #475569;
                transition: all 0.2s ease;
                margin-bottom: 5px;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }}
            .nav-tab:hover {{
                background: #f1f5f9;
                color: var(--primary-color);
            }}
            .nav-tab.active {{
                background: var(--primary-color);
                color: white;
                font-weight: 600;
            }}
            
            .tab-content {{
                display: none;
                background: white;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }}
            .tab-content.active {{
                display: block;
            }}
            
            .tab-content-inner {{
                padding: 24px;
            }}
            
            .table-title {{
                font-size: 18px;
                font-weight: 600;
                margin-bottom: 12px;
                padding: 0 10px;
            }}
            .content-subheading {{
                font-weight: 600;
                font-size: 14px;
                margin-top: 16px;
                margin-bottom: 8px;
                color: #475569;
            }}

            .table-container {{
                margin: 20px 0;
                overflow-x: auto;
                border: 1px solid var(--border-color);
                border-radius: 8px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                padding: 12px 16px;
                text-align: left;
                border-bottom: 1px solid var(--border-color);
            }}
            th {{
                background: #f8fafc;
                font-weight: 600;
                color: var(--text-color);
            }}
            tr:last-child td {{ border-bottom: none; }}
            tbody tr:hover {{ background: #f8fafc; }}

            .metric-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }}
            
            .metric-card {{
                background: #ffffff;
                padding: 20px;
                border-radius: 12px;
                border: 1px solid var(--border-color);
                transition: transform 0.2s ease, box-shadow 0.2s ease;
                position: relative;
            }}
            .metric-card:hover {{
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            }}
            .metric-icon {{
                position: absolute; top: 16px; right: 16px; font-size: 24px; opacity: 0.2;
            }}
            .metric-value {{
                font-size: 28px; font-weight: 700; color: var(--primary-color); margin-bottom: 4px;
            }}
            .metric-label {{
                font-size: 14px; color: #64748b; font-weight: 500;
            }}

            .alerts-section, .content-section {{
                margin: 20px 0;
            }}
            .content-section {{
                background: #f8fafc; padding: 20px; border-radius: 8px;
            }}
            .content-line {{ padding: 4px 0; font-family: monospace; font-size: 13px; }}
            pre {{
                white-space: pre-wrap;
                word-wrap: break-word;
                font-family: monospace;
                font-size: 12px;
                padding: 15px;
                background: #f1f5f9;
                border-radius: 6px;
                border: 1px solid var(--border-color);
            }}
            
            .warning, .success {{
                padding: 15px 20px; border-radius: 8px; margin: 10px 0; font-size: 14px; font-weight: 500;
            }}
            .warning {{
                background: #fff1f2; border-left: 4px solid #ef4444; color: #9f1239;
            }}
            .success {{
                background: #f0fdf4; border-left: 4px solid #22c55e; color: #15803d;
            }}
            
            .hot-threads-container {{ margin: 20px 0; }}
            .hot-threads-node {{ border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 20px; padding: 16px; }}
            .hot-threads-node h4 {{ margin-top: 0; }}
            .hot-thread {{ border-bottom: 1px solid #f1f5f9; padding-bottom: 10px; margin-bottom: 10px; }}
            .hot-thread:last-child {{ border-bottom: none; margin-bottom: 0; }}
            .hot-thread-summary {{ cursor: pointer; font-weight: 500; position: relative; padding-right: 20px; }}
            .hot-thread-summary .toggler {{ position: absolute; right: 0; top: 0; font-weight: bold; }}
            .hot-thread-stack {{ display: none; margin-top: 10px; }}

        </style>
        <script>
            function toggleStackTrace(element) {{
                var stack = element.nextElementSibling;
                var toggler = element.querySelector('.toggler');
                if (stack.style.display === "block") {{
                    stack.style.display = "none";
                    toggler.textContent = '+';
                }} else {{
                    stack.style.display = "block";
                    toggler.textContent = '-';
                }}
            }}
            $(document).ready(function() {{
                $('.nav-tab').click(function() {{
                    $('.nav-tab').removeClass('active');
                    $('.tab-content').removeClass('active');
                    $(this).addClass('active');
                    $('#tab-' + $(this).data('tab')).addClass('active');
                }});
                $('.nav-tab').first().click();
            }});
        </script>
    </head>
    <body>
        <div class="header">
            <h1>Elasticsearch Cluster Analysis Report</h1>
            <div class="timestamp">Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        <div class="main-layout">
            <div class="side-nav">
                {_generate_tabs(parsed_sections)}
            </div>
            <div class="main-content">
                {_generate_tab_content(parsed_sections)}
            </div>
        </div>
    </body>
    </html>
    """
    
    emoji_map = {
        "✅": "&#9989;", "⚠️": "&#9888;", "❌": "&#10060;", "📊": "&#128202;",
        "🔥": "&#128293;", "📈": "&#128200;", "⚡": "&#9889;", "💡": "&#128161;",
        "🔄": "&#128260;", "🧵": "&#129525;", "🔍": "&#128269;", "📝": "&#128221;",
        "🎯": "&#127919;", "🛡️": "&#128737;", "🌐": "&#127760;"
    }
    
    for emoji, html_code in emoji_map.items():
        html_content = html_content.replace(emoji, html_code)
        
    return html_content

def open_in_browser(html_content, root_after):
    """Open analysis results in default web browser"""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.html', mode='w', encoding='utf-8') as f:
            f.write(html_content)
            temp_path = f.name
        
        webbrowser.open('file://' + os.path.realpath(temp_path))
        
        if root_after:
            root_after(5000, lambda: os.unlink(temp_path) if os.path.exists(temp_path) else None)
        
    except Exception as e:
        print(f"Failed to open in browser: {str(e)}")

def _parse_to_sections(results):
    """Parse analysis results into structured sections"""
    sections = {
        'overview': {'title': 'Cluster Overview', 'content': []},
        'pipeline': {'title': 'Pipeline Performance', 'content': []},
        'node': {'title': 'Node Resources', 'content': []},
        'threads': {'title': 'Thread Pools', 'content': []},
        'memory': {'title': 'Memory & GC', 'content': []},
        'breakers': {'title': 'Circuit Breakers', 'content': []},
        'search': {'title': 'Search & Cache', 'content': []},
        'io': {'title': 'I/O & Disk', 'content': []},
        'network': {'title': 'Network Traffic', 'content': []},
        'indexing': {'title': 'Index Operations', 'content': []},
        'indexing_delta': {'title': 'Indexing Delta', 'content': []},
        'segments': {'title': 'Segments & Allocation', 'content': []},
        'hotthreads': {'title': 'Hot Threads', 'content': []},
        'shards': {'title': 'Shard Distribution', 'content': []}
    }
    
    section_markers = {
        'overview': '📋 CLUSTER OVERVIEW',
        'pipeline': '⚡ PIPELINE PERFORMANCE ANALYSIS',
        'node': '📊 NODE RESOURCES',
        'threads': '🧵 COMPREHENSIVE THREAD POOL ANALYSIS',
        'memory': '🧠 MEMORY & GARBAGE COLLECTION ANALYSIS',
        'breakers': '🛡️ CIRCUIT BREAKER ANALYSIS',
        'search': '🔍 SEARCH PERFORMANCE & CACHE ANALYSIS',
        'io': '💾 I/O & DISK PERFORMANCE ANALYSIS',
        'network': '🌐 NETWORK TRAFFIC ANALYSIS',
        'indexing': '📝 INDEX OPERATIONS ANALYSIS',
        'indexing_delta': '📝 CURRENT INDEXING ACTIVITY (DELTA CHECK)',
        'segments': '🔧 SEGMENTS & ALLOCATION ANALYSIS',
        'hotthreads': '🔥 HOT THREADS ANALYSIS',
        'shards': '🔍 SHARD DISTRIBUTION ANALYSIS'
    }
    
    current_section = None
    current_lines = []
    
    for line in results.split('\n'):
        found_section = None
        for section, marker in section_markers.items():
            if marker in line:
                found_section = section
                break
        
        if found_section:
            if current_section and current_lines:
                sections[current_section]['content'] = current_lines
            
            current_section = found_section
            current_lines = [line]
        elif current_section:
            current_lines.append(line)
    
    if current_section and current_lines:
        sections[current_section]['content'] = current_lines
        
    return {k: v for k, v in sections.items() if v['content']}

def _generate_tabs(sections):
    """Generate HTML for navigation tabs"""
    tab_order = ['overview', 'pipeline', 'node', 'threads', 'memory', 'breakers', 'search', 'io', 'network', 'indexing', 'indexing_delta', 'segments', 'hotthreads', 'shards']
    tabs = []
    
    for key in tab_order:
        if key in sections:
            tabs.append(f"""
                <div class="nav-tab{' active' if key == 'overview' else ''}"
                     data-tab="{key}">
                    {sections[key]['title']}
                </div>
            """)
    
    return '\n'.join(tabs)

def _generate_tab_content(sections):
    """Generate HTML content for each tab"""
    tab_order = ['overview', 'pipeline', 'node', 'threads', 'memory', 'breakers', 'search', 'io', 'network', 'indexing', 'indexing_delta', 'segments', 'hotthreads', 'shards']
    tab_contents = []
    
    for key in tab_order:
        if key in sections:
            section_content = _process_section_content(sections[key]['content'])
            tab_contents.append(f'''
                <div class="tab-content{' active' if key == 'overview' else ''}"
                     id="tab-{key}">
                    <div class="tab-content-inner">{section_content}</div>
                </div>
            ''')
    
    return '\n'.join(tab_contents)

def _process_section_content(content_lines):
    """Process content lines and return formatted HTML by grouping content into blocks."""
    content_lines = [line.strip() for line in content_lines[1:] if line.strip()]
    
    blocks = []
    current_block_type = None
    current_block_lines = []
    in_special_block = None

    for line in content_lines:
        if line.strip() == '---HOT-THREADS-INTERACTIVE-START---':
            if current_block_lines and current_block_type: blocks.append({'type': current_block_type, 'lines': current_block_lines})
            current_block_type = 'hot-threads-interactive'
            current_block_lines = []
            in_special_block = 'hot-threads-interactive'
            continue
        
        if line.strip() == '---HOT-THREADS-INTERACTIVE-END---':
            if current_block_lines: blocks.append({'type': 'hot-threads-interactive', 'lines': current_block_lines})
            current_block_type = None
            current_block_lines = []
            in_special_block = None
            continue

        if in_special_block:
            current_block_lines.append(line)
            continue

        line_type = 'other'
        is_table_line = '|' in line or '-+-' in line
        
        if is_table_line:
            line_type = 'table'
        elif any(i in line for i in ['📊', '📈', '🔥', '💡', '⚡']):
            line_type = 'metric'
        elif '⚠️' in line:
            line_type = 'warning'
        elif '✅' in line:
            line_type = 'success'

        if line_type != current_block_type and current_block_lines:
            blocks.append({'type': current_block_type, 'lines': current_block_lines})
            current_block_lines = []
        
        current_block_type = line_type
        current_block_lines.append(line)

    if current_block_lines and current_block_type:
        blocks.append({'type': current_block_type, 'lines': current_block_lines})
        
    return _render_html_parts(blocks)

def _render_html_parts(blocks):
    """Render a list of content blocks to HTML."""
    html_parts = []
    
    for block in blocks:
        block_type = block['type']
        lines = block['lines']
        
        if block_type == 'table':
            html_parts.append(_convert_table_to_html(lines))
        
        elif block_type == 'metric':
            html_parts.append('<div class="metric-grid">')
            for line in lines:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    icon = next((i for i in ['📊', '📈', '🔥', '💡', '⚡'] if i in parts[0]), '')
                    label = parts[0].replace(icon, '').strip()
                    value = parts[1].strip()
                    html_parts.append(f'''
                        <div class="metric-card">
                            <div class="metric-icon">{icon}</div>
                            <div class="metric-value">{value}</div>
                            <div class="metric-label">{label}</div>
                        </div>
                    ''')
            html_parts.append('</div>')

        elif block_type == 'warning':
            html_parts.append('<div class="alerts-section">')
            for line in lines:
                html_parts.append(f'<div class="warning">{line}</div>')
            html_parts.append('</div>')
        
        elif block_type == 'success':
            html_parts.append('<div class="alerts-section">')
            for line in lines:
                html_parts.append(f'<div class="success">{line}</div>')
            html_parts.append('</div>')

        elif block_type == 'hot-threads-interactive':
            html_parts.append(_render_hot_threads_interactive(lines))
        
        elif block_type == 'other':
            html_parts.append('<div class="content-section">')
            for line in lines:
                if line.endswith(':') and len(line) < 60 and not any(c.isdigit() for c in line):
                     html_parts.append(f'<h4 class="content-subheading">{line}</h4>')
                else:
                     html_parts.append(f'<div class="content-line">{line}</div>')
            html_parts.append('</div>')

    return '\n'.join(html_parts)

def _render_hot_threads_interactive(json_lines):
    """Render parsed hot threads data into a collapsible HTML structure."""
    try:
        nodes_data = json.loads("".join(json_lines))
        if not nodes_data: return '<div class="content-section"><p>No hot threads data to display.</p></div>'
        
        html_parts = ['<div class="hot-threads-container">']
        for node in nodes_data:
            html_parts.append(f'<div class="hot-threads-node">')
            html_parts.append(f'<h4>Node: {html.escape(node["name"])}</h4>')
            for i, thread in enumerate(node["threads"]):
                summary_html = '<br>'.join(html.escape(s) for s in thread['summary'])
                stack_html = '<br>'.join(html.escape(s) for s in thread['stack'])
                
                html_parts.append(f'''
                    <div class="hot-thread">
                        <div class="hot-thread-summary" onclick="toggleStackTrace(this)">
                            {summary_html}
                            <span class="toggler">+</span>
                        </div>
                        <div class="hot-thread-stack">
                            <pre>{stack_html}</pre>
                        </div>
                    </div>
                ''')
            html_parts.append('</div>')
        html_parts.append('</div>')
        return ''.join(html_parts)
    except json.JSONDecodeError as e:
        return f'<div class="warning">Error parsing hot threads data: {html.escape(str(e))}</div>'
    except Exception as e:
        return f'<div class="warning">An unexpected error occurred while rendering hot threads: {html.escape(str(e))}</div>'

def _convert_table_to_html(table_lines):
    """Convert ASCII table to HTML table, handling optional title."""
    html_lines = ['<div class="table-container">']
    
    first_line = table_lines[0].strip()
    if '|' not in first_line and '-+-' not in first_line:
        html_lines.append(f'<h3 class="table-title">{first_line}</h3>')
        table_lines = table_lines[1:]

    html_lines.append('<table>')
    header_done = False
    
    for line in table_lines:
        if '-+-' in line:
            continue
        
        cells = [cell.strip() for cell in line.split('|')]
        
        if not header_done:
            html_lines.append('<thead><tr>')
            for cell in cells:
                html_lines.append(f'<th>{cell}</th>')
            html_lines.append('</tr></thead><tbody>')
            header_done = True
        else:
            html_lines.append('<tr>')
            for cell in cells:
                html_lines.append(f'<td>{cell}</td>')
            html_lines.append('</tr>')
    
    html_lines.append('</tbody></table></div>')
    return '\n'.join(html_lines)