import re
import json

def analyze_hot_threads(es_client):
    """
    Analyzes hot threads in the cluster.

    :param es_client: An instance of the Elasticsearch client.
    :return: A dictionary containing the structured analysis data.
    """
    section_data = {'summary': {}, 'raw_output': '', 'warnings': [], 'parsed_nodes': []}

    try:
        hot_threads_response = es_client.nodes.hot_threads(threads=10, interval='500ms', snapshots=3, ignore_idle_threads=True)
        hot_threads_text = str(hot_threads_response)
        section_data['raw_output'] = hot_threads_text
        
        # Parsing logic
        parsed_nodes = []
        text_to_parse = hot_threads_text.strip()
        if not text_to_parse.startswith(':::'):
            text_to_parse = ':::' + text_to_parse

        node_reports = text_to_parse.split('\n:::')
        for report in node_reports:
            if not report.strip(): continue
            
            lines = report.strip().split('\n')
            node_header = lines[0]
            node_name_match = re.search(r'\{([^}]+)\}', node_header)
            node_name = node_name_match.group(1) if node_name_match else 'Unknown Node'
            
            node_data = {'name': node_name, 'threads': []}
            current_thread = None
            
            start_line = 0
            for i, line in enumerate(lines):
                if "Hot threads at" in line:
                    start_line = i + 1
                    break
            
            for line in lines[start_line:]:
                if re.match(r'\s*\d+\.\d+%', line): # Start of a new thread
                    if current_thread: node_data['threads'].append(current_thread)
                    current_thread = {'summary': [line.strip()], 'stack': []}
                elif current_thread:
                    if 'snapshots sharing' in line:
                        current_thread['summary'].append(line.strip())
                    else:
                        current_thread['stack'].append(line)
            if current_thread: node_data['threads'].append(current_thread)
            
            if node_data['threads']: parsed_nodes.append(node_data)
        
        section_data['parsed_nodes'] = parsed_nodes
        total_hot_threads = sum(len(n['threads']) for n in parsed_nodes)
        section_data['summary']['total_hot_threads'] = total_hot_threads
        if total_hot_threads > 0: section_data['warnings'].append(f"{total_hot_threads} hot threads detected.")

    except Exception as e:
        section_data['error'] = f"Could not retrieve hot threads info: {str(e)}"
        
    return section_data