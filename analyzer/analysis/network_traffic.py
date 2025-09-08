def analyze_network_traffic(es_client):
    """
    Analyzes network transport statistics.

    :param es_client: An instance of the Elasticsearch client.
    :return: A dictionary containing the structured analysis data.
    """
    section_data = {'summary': {}, 'details_by_node': []}

    try:
        transport_stats = es_client.nodes.stats(metric=['transport'])
        total_rx_mb, total_tx_mb = 0, 0

        for node_id, node_data in transport_stats.get('nodes', {}).items():
            transport = node_data.get('transport', {})
            rx_mb = transport.get('rx_size_in_bytes', 0) / 1024**2
            tx_mb = transport.get('tx_size_in_bytes', 0) / 1024**2
            total_rx_mb += rx_mb
            total_tx_mb += tx_mb
            
            section_data['details_by_node'].append({
                'node': node_data.get('name', 'Unknown'),
                'rx_count': transport.get('rx_count', 0),
                'tx_count': transport.get('tx_count', 0),
                'rx_mb': rx_mb,
                'tx_mb': tx_mb,
                'server_connections_open': transport.get('server_open', 0)
            })
        
        section_data['summary'] = {'total_rx_mb': total_rx_mb, 'total_tx_mb': total_tx_mb}

    except Exception as e:
        section_data['error'] = f"Could not retrieve network traffic info: {str(e)}"
    
    return section_data