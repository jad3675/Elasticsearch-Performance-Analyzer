def analyze_circuit_breakers(es_client):
    """
    Analyzes circuit breaker statistics.

    :param es_client: An instance of the Elasticsearch client.
    :return: A dictionary containing the structured analysis data.
    """
    section_data = {
        'summary': {},
        'details': []
    }

    try:
        breaker_stats = es_client.nodes.stats(metric=['breaker'])
        
        total_tripped = 0
        
        sorted_node_ids = sorted(breaker_stats.get('nodes', {}).keys(), key=lambda x: breaker_stats['nodes'][x].get('name', ''))

        for node_id in sorted_node_ids:
            node_data = breaker_stats['nodes'][node_id]
            breakers = node_data.get('breakers', {})
            for breaker_name, stats in breakers.items():
                tripped_count = stats.get('tripped', 0)
                total_tripped += tripped_count
                limit_bytes = stats.get('limit_size_in_bytes', 0)
                
                if limit_bytes > 0 or stats.get('estimated_size_in_bytes', 0) > 0 or tripped_count > 0:
                    estimated_bytes = stats.get('estimated_size_in_bytes', 0)
                    usage_percent = (estimated_bytes / limit_bytes * 100) if limit_bytes > 0 else 0
                    
                    section_data['details'].append({
                        'node': node_data.get('name', 'Unknown'),
                        'breaker': breaker_name,
                        'limit_bytes': limit_bytes,
                        'estimated_bytes': estimated_bytes,
                        'usage_percent': usage_percent,
                        'tripped_count': tripped_count
                    })

        section_data['summary']['total_tripped'] = total_tripped
        
    except Exception as e:
        section_data['error'] = f"Could not retrieve circuit breaker info: {str(e)}"
    
    return section_data