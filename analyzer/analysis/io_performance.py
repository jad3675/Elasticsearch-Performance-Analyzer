def analyze_io_performance(es_client):
    """
    Analyzes I/O and disk performance statistics.

    :param es_client: An instance of the Elasticsearch client.
    :return: A dictionary containing the structured analysis data.
    """
    section_data = {'summary': {}, 'details_by_node': [], 'warnings': []}

    try:
        fs_stats = es_client.nodes.stats(metric=['fs'])
        
        total_disk_stats = {'total_reads': 0, 'total_writes': 0, 'read_kb': 0, 'write_kb': 0, 'total_space_gb': 0, 'available_space_gb': 0}

        for node_id, node_data in fs_stats.get('nodes', {}).items():
            node_name = node_data.get('name', 'Unknown')
            fs = node_data.get('fs', {})
            total_space_bytes, available_space_bytes = 0, 0
            for data_path in fs.get('data', []):
                total_space_bytes += data_path.get('total_in_bytes', 0)
                available_space_bytes += data_path.get('available_in_bytes', 0)
            
            total_space_gb = total_space_bytes / (1024**3)
            available_space_gb = available_space_bytes / (1024**3)
            used_space_gb = total_space_gb - available_space_gb
            disk_used_percent = (used_space_gb / total_space_gb * 100) if total_space_gb > 0 else 0
            
            total_io = fs.get('io_stats', {}).get('total', {})
            read_ops, write_ops = total_io.get('read_operations', 0), total_io.get('write_operations', 0)
            read_kb, write_kb = total_io.get('read_kilobytes', 0), total_io.get('write_kilobytes', 0)
            
            section_data['details_by_node'].append({
                'node': node_name,
                'total_space_gb': total_space_gb,
                'used_space_gb': used_space_gb,
                'disk_used_percent': disk_used_percent,
                'read_ops': read_ops,
                'write_ops': write_ops,
                'read_mb': read_kb / 1024,
                'write_mb': write_kb / 1024
            })
            
            total_disk_stats['total_reads'] += read_ops; total_disk_stats['total_writes'] += write_ops
            total_disk_stats['read_kb'] += read_kb; total_disk_stats['write_kb'] += write_kb
            total_disk_stats['total_space_gb'] += total_space_gb; total_disk_stats['available_space_gb'] += available_space_gb
            
            if disk_used_percent > 85:
                section_data['warnings'].append(f"High disk usage on {node_name}: {disk_used_percent:.1f}%")
            if available_space_gb < 10:
                section_data['warnings'].append(f"Low disk space on {node_name}: {available_space_gb:.1f}GB remaining")

        cluster_used_percent = ((total_disk_stats['total_space_gb'] - total_disk_stats['available_space_gb']) / total_disk_stats['total_space_gb'] * 100) if total_disk_stats['total_space_gb'] > 0 else 0
        section_data['summary'] = {
            'total_cluster_storage_gb': total_disk_stats['total_space_gb'],
            'available_storage_gb': total_disk_stats['available_space_gb'],
            'cluster_storage_usage_percent': cluster_used_percent,
            'total_disk_reads': total_disk_stats['total_reads'],
            'total_disk_writes': total_disk_stats['total_writes']
        }
        if cluster_used_percent > 80:
            section_data['warnings'].append("High cluster storage utilization")
        if total_disk_stats['available_space_gb'] < 50:
            section_data['warnings'].append("Low available storage space")

    except Exception as e:
        section_data['error'] = f"Could not retrieve I/O performance info: {str(e)}"
    
    return section_data