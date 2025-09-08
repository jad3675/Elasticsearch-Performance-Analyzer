def analyze_shard_distribution(es_client):
    """
    Analyzes shard distribution statistics.

    :param es_client: An instance of the Elasticsearch client.
    :return: A dictionary containing the structured analysis data.
    """
    section_data = {'summary': {}, 'warnings': []}

    try:
        shards_info = es_client.cat.shards(h='index,shard,prirep,node,state,docs,store', format='json')
        
        primary_shards = [s for s in shards_info if s.get('prirep') == 'p']
        replica_shards = [s for s in shards_info if s.get('prirep') == 'r']
        
        indices = set(s.get('index') for s in shards_info)
        total_docs = sum(int(s.get('docs', '0') or '0') for s in primary_shards if s.get('docs'))

        unassigned_shards = sum(1 for s in shards_info if s.get('state', '') != 'STARTED')
        if unassigned_shards > 0:
            section_data['warnings'].append(f"{unassigned_shards} unassigned shards detected")

        section_data['summary'] = {
            'total_indices': len(indices),
            'total_primary_shards': len(primary_shards),
            'total_replica_shards': len(replica_shards),
            'total_documents': total_docs,
            'unassigned_shards': unassigned_shards
        }

    except Exception as e:
        section_data['error'] = f"Could not analyze shard distribution: {str(e)}"
        
    return section_data