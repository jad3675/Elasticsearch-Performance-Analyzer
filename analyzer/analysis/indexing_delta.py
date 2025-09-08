import time

def analyze_indexing_delta(es_client):
    """
    Analyzes the indexing delta over a short period.

    :param es_client: An instance of the Elasticsearch client.
    :return: A dictionary containing the structured analysis data.
    """
    section_data = {'summary': {}, 'active_indices': [], 'warnings': []}

    try:
        baseline_stats = es_client.cat.indices(h='index,pri.indexing.index_total', format='json')
        
        time.sleep(10)
        
        final_stats = es_client.cat.indices(h='index,pri.indexing.index_total', format='json')
        
        baseline_totals = {i['index']: int(i.get('pri.indexing.index_total', '0') or '0') for i in baseline_stats}
        final_totals = {i['index']: int(i.get('pri.indexing.index_total', '0') or '0') for i in final_stats}

        total_new_ops = 0
        for index, final_total in final_totals.items():
            baseline_total = baseline_totals.get(index, 0)
            if final_total > baseline_total:
                change = final_total - baseline_total
                total_new_ops += change
                section_data['active_indices'].append({'index': index, 'new_operations': change})

        section_data['summary']['active_index_count'] = len(section_data['active_indices'])
        section_data['summary']['total_new_operations'] = total_new_ops
        
        if not section_data['active_indices']:
            section_data['warnings'].append("NO ACTIVE INDEXING DETECTED in the last 10 seconds.")

    except Exception as e:
        section_data['error'] = f"Could not retrieve indexing delta stats: {str(e)}"
    
    return section_data