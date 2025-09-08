def analyze_index_operations(es_client):
    """
    Analyzes index operation performance.

    :param es_client: An instance of the Elasticsearch client.
    :return: A dictionary containing the structured analysis data.
    """
    section_data = {'summary': {}, 'details_by_index': {}, 'warnings': []}

    try:
        indices_stats = es_client.indices.stats(metric=['indexing', 'refresh', 'merge', 'flush'])
        
        totals = {'index_total': 0, 'index_time_ms': 0, 'delete_total': 0, 'delete_time_ms': 0, 'refresh_total': 0, 'refresh_time_ms': 0, 'merge_total': 0, 'merge_time_ms': 0}

        for index_name, index_data in indices_stats.get('indices', {}).items():
            total = index_data.get('total', {})
            indexing = total.get('indexing', {}); refresh = total.get('refresh', {}); merge = total.get('merge', {})
            
            index_total, index_time = indexing.get('index_total', 0), indexing.get('index_time_in_millis', 0)
            delete_total, delete_time = indexing.get('delete_total', 0), indexing.get('delete_time_in_millis', 0)
            refresh_total, refresh_time = refresh.get('total', 0), refresh.get('total_time_in_millis', 0)
            merge_total, merge_time = merge.get('total', 0), merge.get('total_time_in_millis', 0)

            for key, val in [('index_total', index_total), ('index_time_ms', index_time), ('delete_total', delete_total), ('delete_time_ms', delete_time), ('refresh_total', refresh_total), ('refresh_time_ms', refresh_time), ('merge_total', merge_total), ('merge_time_ms', merge_time)]:
                totals[key] += val

            avg_index = index_time / index_total if index_total > 0 else 0
            avg_delete = delete_time / delete_total if delete_total > 0 else 0
            avg_refresh = refresh_time / refresh_total if refresh_total > 0 else 0
            avg_merge = merge_time / merge_total if merge_total > 0 else 0
            
            section_data['details_by_index'][index_name] = {
                'index_total': index_total, 'avg_index_ms': avg_index, 'index_current': indexing.get('index_current', 0),
                'delete_total': delete_total, 'avg_delete_ms': avg_delete,
                'refresh_total': refresh_total, 'avg_refresh_ms': avg_refresh,
                'merge_total': merge_total, 'avg_merge_ms': avg_merge, 'merge_current': merge.get('current', 0)
            }
            
            if avg_index > 50: section_data['warnings'].append(f"High indexing latency in {index_name[:20]}: {avg_index:.2f}ms")
            if merge.get('current', 0) > 2: section_data['warnings'].append(f"High concurrent merges in {index_name[:20]}: {merge.get('current', 0)}")
            if avg_merge > 1000: section_data['warnings'].append(f"Slow merge operations in {index_name[:20]}: {avg_merge:.2f}ms")

        avg_index_latency = totals['index_time_ms'] / totals['index_total'] if totals['index_total'] > 0 else 0
        avg_refresh_latency = totals['refresh_time_ms'] / totals['refresh_total'] if totals['refresh_total'] > 0 else 0
        avg_merge_latency = totals['merge_time_ms'] / totals['merge_total'] if totals['merge_total'] > 0 else 0
        
        section_data['summary'] = {**totals, 'avg_index_latency_ms': avg_index_latency, 'avg_refresh_latency_ms': avg_refresh_latency, 'avg_merge_latency_ms': avg_merge_latency}
        if avg_index_latency > 20: section_data['warnings'].append("High average indexing latency - consider optimizing mapping or bulk sizes")
        if avg_refresh_latency > 100: section_data['warnings'].append("Slow refresh operations - consider adjusting refresh intervals")
        if avg_merge_latency > 500: section_data['warnings'].append("Slow merge operations - check segment optimization settings")

    except Exception as e:
        section_data['error'] = f"Could not retrieve index operations info: {str(e)}"
        
    return section_data