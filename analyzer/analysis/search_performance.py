def analyze_search_performance(es_client):
    """
    Analyzes search performance and cache statistics.

    :param es_client: An instance of the Elasticsearch client.
    :return: A dictionary containing the structured analysis data.
    """
    section_data = {
        'summary': {},
        'cache_by_index': [],
        'performance_by_node': [],
        'warnings': []
    }

    try:
        indices_stats = es_client.indices.stats(metric=['search', 'query_cache', 'fielddata', 'request_cache'])
        nodes_stats = es_client.nodes.stats(metric=['indices'])
        
        total_cache_stats = {'query_cache_hits': 0, 'query_cache_misses': 0, 'fielddata_memory_bytes': 0, 'request_cache_hits': 0, 'request_cache_misses': 0}
        total_search_stats = {'query_total': 0, 'query_time_ms': 0, 'fetch_total': 0, 'fetch_time_ms': 0}
        
        for index_name, index_data in indices_stats.get('indices', {}).items():
            total = index_data.get('total', {})
            qc = total.get('query_cache', {}); rc = total.get('request_cache', {})
            qc_hits, qc_misses = qc.get('hit_count', 0), qc.get('miss_count', 0)
            rc_hits, rc_misses = rc.get('hit_count', 0), rc.get('miss_count', 0)
            fd_mem_bytes = total.get('fielddata', {}).get('memory_size_in_bytes', 0)
            
            total_cache_stats['query_cache_hits'] += qc_hits
            total_cache_stats['query_cache_misses'] += qc_misses
            total_cache_stats['request_cache_hits'] += rc_hits
            total_cache_stats['request_cache_misses'] += rc_misses
            total_cache_stats['fielddata_memory_bytes'] += fd_mem_bytes

            qc_total, rc_total = qc_hits + qc_misses, rc_hits + rc_misses
            if qc_total > 1000 or rc_total > 1000 or fd_mem_bytes > 10 * 1024 * 1024:
                section_data['cache_by_index'].append({
                    'index': index_name,
                    'query_cache_hit_rate': (qc_hits / qc_total * 100) if qc_total > 0 else 0,
                    'request_cache_hit_rate': (rc_hits / rc_total * 100) if rc_total > 0 else 0,
                    'query_cache_memory_bytes': qc.get('memory_size_in_bytes', 0),
                    'fielddata_memory_bytes': fd_mem_bytes
                })

        for node_id, node_data in nodes_stats.get('nodes', {}).items():
            search = node_data.get('indices', {}).get('search', {})
            query_total, query_time = search.get('query_total', 0), search.get('query_time_in_millis', 0)
            fetch_total, fetch_time = search.get('fetch_total', 0), search.get('fetch_time_in_millis', 0)
            
            total_search_stats['query_total'] += query_total
            total_search_stats['query_time_ms'] += query_time
            total_search_stats['fetch_total'] += fetch_total
            total_search_stats['fetch_time_ms'] += fetch_time

            avg_query_ms = query_time / query_total if query_total > 0 else 0
            avg_fetch_ms = fetch_time / fetch_total if fetch_total > 0 else 0
            
            section_data['performance_by_node'].append({
                'node': node_data.get('name', 'Unknown'),
                'query_total': query_total,
                'avg_query_ms': avg_query_ms,
                'fetch_total': fetch_total,
                'avg_fetch_ms': avg_fetch_ms,
                'query_current': search.get('query_current', 0)
            })
            
            if avg_query_ms > 100: 
                section_data['warnings'].append(f"High query latency on {node_data.get('name', 'Unknown')}: {avg_query_ms:.2f}ms")
            if search.get('query_current', 0) > 10: 
                section_data['warnings'].append(f"High concurrent queries on {node_data.get('name', 'Unknown')}: {search.get('query_current', 0)}")

        total_qc = total_cache_stats['query_cache_hits'] + total_cache_stats['query_cache_misses']
        total_rc = total_cache_stats['request_cache_hits'] + total_cache_stats['request_cache_misses']
        qc_hit_rate = (total_cache_stats['query_cache_hits'] / total_qc * 100) if total_qc > 0 else 0
        rc_hit_rate = (total_cache_stats['request_cache_hits'] / total_rc * 100) if total_rc > 0 else 0
        avg_cluster_query = total_search_stats['query_time_ms'] / total_search_stats['query_total'] if total_search_stats['query_total'] > 0 else 0
        
        section_data['summary'] = {
            'avg_query_latency_ms': avg_cluster_query,
            'total_queries': total_search_stats['query_total'],
            'query_cache_hit_rate': qc_hit_rate,
            'request_cache_hit_rate': rc_hit_rate,
            'fielddata_memory_bytes': total_cache_stats['fielddata_memory_bytes']
        }

        if qc_hit_rate < 50 and total_qc > 1000: 
            section_data['warnings'].append("Low query cache hit rate - consider query optimization")
        if rc_hit_rate < 80 and total_rc > 1000: 
            section_data['warnings'].append("Low request cache hit rate - check request patterns")
        if avg_cluster_query > 50: 
            section_data['warnings'].append("High average query latency detected")
            
    except Exception as e:
        section_data['error'] = f"Could not retrieve search performance info: {str(e)}"

    return section_data