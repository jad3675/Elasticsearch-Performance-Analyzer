def analyze_thread_pools(es_client):
    """
    Analyzes thread pool statistics.

    :param es_client: An instance of the Elasticsearch client.
    :return: A dictionary containing the structured analysis data.
    """
    section_data = {
        'summary': {},
        'pools': {},
        'warnings': []
    }

    try:
        thread_pool_cat = es_client.cat.thread_pool(h='node_name,name,active,queue,rejected,size,max', format='json')
        
        for pool_entry in thread_pool_cat:
            pool_name = pool_entry.get('name')
            if pool_name not in section_data['pools']:
                section_data['pools'][pool_name] = {
                    'summary': {'active': 0, 'queue': 0, 'rejected': 0, 'available': 0},
                    'details': []
                }
            
            try:
                active = int(pool_entry.get('active', 0))
                queue = int(pool_entry.get('queue', 0))
                rejected = int(pool_entry.get('rejected', 0))
                size_str = pool_entry.get('size', '0')
                size_for_calc = int(size_str) if str(size_str).isdigit() else 0
                
            except (ValueError, TypeError):
                continue

            section_data['pools'][pool_name]['summary']['active'] += active
            section_data['pools'][pool_name]['summary']['queue'] += queue
            section_data['pools'][pool_name]['summary']['rejected'] += rejected
            section_data['pools'][pool_name]['summary']['available'] += size_for_calc
            section_data['pools'][pool_name]['details'].append({
                'node': pool_entry.get('node_name', 'Unknown'),
                'active': active,
                'queue': queue,
                'rejected': rejected,
                'size': pool_entry.get('size', 'N/A')
            })

        overall_totals = {'active': 0, 'queue': 0, 'rejected': 0, 'available': 0}
        for pool_name, data in section_data['pools'].items():
            for key in overall_totals:
                overall_totals[key] += data['summary'][key]
        
        overall_utilization = (overall_totals['active'] / overall_totals['available'] * 100) if overall_totals['available'] > 0 else 0
        section_data['summary'] = {**overall_totals, 'utilization_percent': overall_utilization}

        for pool_name, data in section_data['pools'].items():
            pool_totals = data['summary']
            if pool_totals['available'] > 0:
                utilization = (pool_totals['active'] / pool_totals['available']) * 100
                if utilization > 80:
                    section_data['warnings'].append(f"High {pool_name} thread utilization: {utilization:.1f}%")
            if pool_totals['queue'] > 50:
                section_data['warnings'].append(f"High {pool_name} queue length: {pool_totals['queue']}")
            if pool_totals['rejected'] > 0:
                section_data['warnings'].append(f"{pool_name.title()} rejections: {pool_totals['rejected']}")

    except Exception as e:
        section_data['error'] = f"Could not retrieve thread pool info: {str(e)}"
    
    return section_data