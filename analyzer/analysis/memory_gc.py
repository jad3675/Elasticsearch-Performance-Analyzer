def analyze_memory_and_gc(es_client):
    """
    Analyzes memory and garbage collection statistics.

    :param es_client: An instance of the Elasticsearch client.
    :return: A dictionary containing the structured analysis data.
    """
    section_data = {
        'summary': {},
        'memory_by_node': [],
        'gc_by_node': [],
        'warnings': []
    }

    try:
        jvm_stats = es_client.nodes.stats(metric=['jvm'])
        
        gc_totals = {'young_collections': 0, 'young_time_ms': 0, 'old_collections': 0, 'old_time_ms': 0}

        for node_id, node_data in jvm_stats.get('nodes', {}).items():
            node_name = node_data.get('name', 'Unknown')
            jvm = node_data.get('jvm', {})
            mem = jvm.get('mem', {})
            heap_used_percent = mem.get('heap_used_percent', 0)
            
            pools = mem.get('pools', {})
            old_gen = pools.get('old', {})
            old_gen_max_bytes = old_gen.get('max_in_bytes', 1)
            old_gen_used_bytes = old_gen.get('used_in_bytes', 0)
            old_gen_percent = (old_gen_used_bytes / old_gen_max_bytes * 100) if old_gen_max_bytes > 0 else 0
            
            section_data['memory_by_node'].append({
                'node': node_name,
                'heap_used_bytes': mem.get('heap_used_in_bytes', 0),
                'heap_max_bytes': mem.get('heap_max_in_bytes', 0),
                'heap_used_percent': heap_used_percent,
                'old_gen_used_bytes': old_gen_used_bytes,
                'old_gen_used_percent': old_gen_percent
            })
            
            gc = jvm.get('gc', {}).get('collectors', {})
            young = gc.get('young', {})
            old = gc.get('old', {})
            young_count, young_time = young.get('collection_count', 0), young.get('collection_time_in_millis', 0)
            old_count, old_time = old.get('collection_count', 0), old.get('collection_time_in_millis', 0)
            
            gc_totals['young_collections'] += young_count
            gc_totals['young_time_ms'] += young_time
            gc_totals['old_collections'] += old_count
            gc_totals['old_time_ms'] += old_time
            
            section_data['gc_by_node'].append({
                'node': node_name,
                'young_gc_count': young_count,
                'avg_young_gc_ms': young_time / young_count if young_count > 0 else 0,
                'old_gc_count': old_count,
                'avg_old_gc_ms': old_time / old_count if old_count > 0 else 0
            })
            
            if heap_used_percent > 85: 
                section_data['warnings'].append(f"High heap usage on {node_name}: {heap_used_percent:.1f}%")
            if old_gen_percent > 80: 
                section_data['warnings'].append(f"High old generation usage on {node_name}: {old_gen_percent:.1f}%")

        total_gc_time = gc_totals['young_time_ms'] + gc_totals['old_time_ms']
        total_collections = gc_totals['young_collections'] + gc_totals['old_collections']
        avg_gc_time = total_gc_time / total_collections if total_collections > 0 else 0
        
        section_data['summary'] = {
            'total_gc_collections': total_collections,
            'avg_gc_time_ms': avg_gc_time,
            'total_gc_time_s': total_gc_time / 1000
        }
        if avg_gc_time > 100: 
            section_data['warnings'].append("High average GC pause times detected")
        if gc_totals['old_collections'] > gc_totals['young_collections'] * 0.1: 
            section_data['warnings'].append("Frequent old generation GCs detected")
            
    except Exception as e:
        section_data['error'] = f"Could not retrieve memory/GC info: {str(e)}"
    
    return section_data