def analyze_segments_and_allocation(es_client):
    """
    Analyzes segment and allocation statistics.

    :param es_client: An instance of the Elasticsearch client.
    :return: A dictionary containing the structured analysis data.
    """
    section_data = {'summary': {}, 'segments_by_index': [], 'allocation_by_node': [], 'warnings': []}

    try:
        segments_stats = es_client.indices.segments()
        allocation_data = es_client.cat.allocation(format='json', h='node,shards,disk.used,disk.avail,disk.percent')

        total_segments, total_segment_memory, total_shards = 0, 0, 0

        for index_name, index_data in segments_stats.get('indices', {}).items():
            index_segments, index_memory_bytes, max_segment_size = 0, 0, 0
            for shard_list in index_data.get('shards', {}).values():
                for shard in shard_list:
                    for seg_info in shard.get('segments', {}).values():
                        index_segments += 1
                        index_memory_bytes += seg_info.get('memory_in_bytes', 0)
                        max_segment_size = max(max_segment_size, seg_info.get('size_in_bytes', 0))

            if index_segments > 0:
                section_data['segments_by_index'].append({
                    'index': index_name,
                    'segment_count': index_segments,
                    'memory_bytes': index_memory_bytes,
                    'max_segment_size_bytes': max_segment_size
                })
                total_segments += index_segments
                total_segment_memory += index_memory_bytes
                if index_segments > 100: 
                    section_data['warnings'].append(f"High segment count in {index_name[:20]}: {index_segments}")
                if max_segment_size > 5 * 1024**3: 
                    section_data['warnings'].append(f"Large segment (>5GB) in {index_name[:20]}")

        for node_data in allocation_data:
            try:
                shards_count = int(node_data.get('shards', '0') or '0')
                disk_percent = float(node_data.get('disk.percent', '0') or '0')
                total_shards += shards_count
                
                section_data['allocation_by_node'].append({
                    'node': node_data.get('node', 'Unknown'),
                    'shards': shards_count,
                    'disk_used': node_data.get('disk.used', 'N/A'),
                    'disk_available': node_data.get('disk.avail', 'N/A'),
                    'disk_usage_percent': disk_percent
                })
                
                if shards_count > 1000: 
                    section_data['warnings'].append(f"High shard count on {node_data.get('node', 'Unknown')}: {shards_count}")
                if disk_percent > 85: 
                    section_data['warnings'].append(f"High disk usage on {node_data.get('node', 'Unknown')}")
            except (ValueError, TypeError):
                pass

        num_indices = len(section_data['segments_by_index'])
        avg_segments = total_segments / num_indices if num_indices > 0 else 0
        section_data['summary'] = {
            'total_segments': total_segments, 'total_segment_memory_bytes': total_segment_memory,
            'total_shards_on_data_nodes': total_shards, 'avg_segments_per_index': avg_segments
        }
        if avg_segments > 50: 
            section_data['warnings'].append("High average segments per index - consider force merge operations")
        if total_segment_memory > 1024**3: 
            section_data['warnings'].append("High segment memory usage (>1GB) - monitor heap pressure")

    except Exception as e:
        section_data['error'] = f"Could not retrieve segments/allocation info: {str(e)}"
        
    return section_data