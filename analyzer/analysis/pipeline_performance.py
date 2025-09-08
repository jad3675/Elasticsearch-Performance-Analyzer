def analyze_pipeline_performance(es_client):
    """
    Analyzes pipeline performance statistics.

    :param es_client: An instance of the Elasticsearch client.
    :return: A dictionary containing the structured analysis data.
    """
    pipeline_data = {'summary': {}, 'pipelines': {}, 'warnings': []}
    try:
        pipeline_stats = es_client.nodes.stats(metric=['ingest'])
        total_ingest_count, total_ingest_time_ms, total_ingest_failures = 0, 0, 0

        for node_id, node_data in pipeline_stats.get('nodes', {}).items():
            ingest_stats = node_data.get('ingest', {})
            total_ingest_count += ingest_stats.get('total', {}).get('count', 0)
            total_ingest_time_ms += ingest_stats.get('total', {}).get('time_in_millis', 0)
            total_ingest_failures += ingest_stats.get('total', {}).get('failed', 0)

            for pipeline_id, stats in ingest_stats.get('pipelines', {}).items():
                if pipeline_id not in pipeline_data['pipelines']:
                    pipeline_data['pipelines'][pipeline_id] = {'count': 0, 'time_ms': 0, 'failed': 0}
                pipeline_data['pipelines'][pipeline_id]['count'] += stats.get('count', 0)
                pipeline_data['pipelines'][pipeline_id]['time_ms'] += stats.get('time_in_millis', 0)
                pipeline_data['pipelines'][pipeline_id]['failed'] += stats.get('failed', 0)
        
        pipeline_data['summary'] = {
            'total_docs_processed': total_ingest_count,
            'avg_processing_time_ms': (total_ingest_time_ms / total_ingest_count) if total_ingest_count > 0 else 0,
            'total_failures': total_ingest_failures
        }
        if total_ingest_failures > 0: 
            pipeline_data['warnings'].append(f"{total_ingest_failures:,} failed ingest operations detected")

    except Exception as e:
        pipeline_data['error'] = f"Could not retrieve pipeline stats: {str(e)}"
        
    return pipeline_data