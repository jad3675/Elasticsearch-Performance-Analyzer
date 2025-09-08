def analyze_node_resources(es_client):
    """
    Analyzes node resources like CPU, RAM, and load.

    :param es_client: An instance of the Elasticsearch client.
    :return: A dictionary containing the structured analysis data.
    """
    node_resources_data = {'summary': {}, 'details_by_node': []}
    role_map = {
        'c': 'cold', 'd': 'data', 'f': 'frozen', 'h': 'hot',
        'i': 'ingest', 'l': 'ml', 'm': 'master', 'r': 'remote_cluster_client',
        's': 'content', 't': 'transform', 'v': 'voting_only', 'w': 'warm'
    }
    try:
        nodes_info = es_client.nodes.info(metric=['os', 'jvm'])
        nodes_stats = es_client.nodes.stats(metric=['os', 'process'])
        cat_nodes = es_client.cat.nodes(h='name,node.role,load_1m,heap.percent,heap.max,ram.max', format='json')

        cat_nodes_map = {n['name']: n for n in cat_nodes}
        total_vcpus = sum(d.get('os', {}).get('available_processors', 0) for d in nodes_info.get('nodes', {}).values())
        
        for node_id, node_data in nodes_info.get('nodes', {}).items():
            node_name = node_data.get('name', 'Unknown')
            cat_node_info = cat_nodes_map.get(node_name, {})
            stats_node_info = nodes_stats.get('nodes', {}).get(node_id, {})
            
            cpu_usage = stats_node_info.get('process', {}).get('cpu', {}).get('percent', 0)
            load = float(cat_node_info.get('load_1m', '0') or '0')
            
            roles_str = cat_node_info.get('node.role', 'N/A')
            if roles_str and roles_str != 'N/A':
                full_roles = [role_map.get(role, role) for role in roles_str]
                formatted_roles = ', '.join(sorted(full_roles))
            else:
                formatted_roles = 'N/A'

            node_resources_data['details_by_node'].append({
                'node': node_name,
                'roles': formatted_roles,
                'cpus': f"{node_data.get('os', {}).get('available_processors', 'N/A')} vCPUs",
                'heap_size': cat_node_info.get('heap.max', 'N/A'),
                'ram': cat_node_info.get('ram.max', 'N/A'),
                'cpu_usage_percent': f"{cpu_usage}%",
                'load_1m': f"{load:.2f}"
            })

        node_resources_data['summary'] = {
            'total_cluster_vcpus': total_vcpus,
            'total_nodes': len(node_resources_data['details_by_node']),
            'avg_cpu_usage_percent': sum(float(n['cpu_usage_percent'][:-1]) for n in node_resources_data['details_by_node']) / len(node_resources_data['details_by_node']) if node_resources_data['details_by_node'] else 0,
            'avg_load_1m': sum(float(n['load_1m']) for n in node_resources_data['details_by_node']) / len(node_resources_data['details_by_node']) if node_resources_data['details_by_node'] else 0,
        }

    except Exception as e:
        node_resources_data['error'] = f"Could not retrieve node resources: {str(e)}"
        
    return node_resources_data