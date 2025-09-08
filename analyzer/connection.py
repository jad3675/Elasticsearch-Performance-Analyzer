from elasticsearch import Elasticsearch

def get_es_client(config):
    """
    Sets up and returns an Elasticsearch client based on the provided configuration.

    :param config: A dictionary containing connection parameters like
                   cloud_id, url, api_key, user, password, verify_ssl.
    :return: An instance of the Elasticsearch client.
    :raises ConnectionError: If the connection to Elasticsearch fails.
    :raises ValueError: If required configuration is missing.
    """
    try:
        es_kwargs = {
            'verify_certs': config.get('verify_ssl', True),
            'request_timeout': 30,
            'retry_on_timeout': True,
            'max_retries': 3
        }

        # Add connection details
        if config.get('cloud_id'):
            es_kwargs['cloud_id'] = config['cloud_id']
        elif config.get('url'):
            es_kwargs['hosts'] = [config['url']]
        else:
            raise ValueError("Either 'cloud_id' or 'url' must be provided.")

        # Add authentication details
        if config.get('api_key'):
            api_key_str = config['api_key']
            if ':' in api_key_str:
                es_kwargs['api_key'] = tuple(api_key_str.split(':', 1))
            else:
                es_kwargs['api_key'] = api_key_str
        elif config.get('user') and config.get('password'):
            es_kwargs['basic_auth'] = (config['user'], config['password'])
        else:
            raise ValueError("Authentication details (api_key or user/password) are required.")

        # Create Elasticsearch client
        es = Elasticsearch(**es_kwargs)

        if not es.ping():
            raise ConnectionError("Failed to connect to Elasticsearch. Please check credentials and network.")

        return es

    except Exception as e:
        # Re-raise exceptions to be handled by the caller
        raise e