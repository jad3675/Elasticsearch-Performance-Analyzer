# Elasticsearch Cluster Resource Analyzer

A comprehensive Python application for analyzing Elasticsearch cluster performance, resource utilization, and operational health. This tool provides detailed insights into cluster operations through both a user-friendly GUI and command-line interface.

## Features

### Comprehensive Analysis Modules

- **Cluster Overview**: Health status, version info, node distribution, and shard allocation
- **Pipeline Performance**: Ingest pipeline metrics, processing rates, and failure analysis
- **Node Resources**: CPU, memory, and resource utilization across all nodes
- **Thread Pool Analysis**: Detailed thread pool utilization, queue depths, and rejection rates
- **Memory & Garbage Collection**: JVM heap usage, GC performance, and memory pressure indicators
- **Circuit Breaker Monitoring**: Breaker status and trip detection for memory protection
- **Search Performance**: Query latency, cache hit rates, and search optimization insights
- **I/O & Disk Performance**: Disk usage, read/write operations, and storage analysis
- **Network Traffic**: Transport layer metrics and connection monitoring
- **Index Operations**: Indexing, refresh, merge, and flush performance analysis
- **Segments & Allocation**: Segment count, memory usage, and shard distribution
- **Hot Threads**: CPU bottleneck detection and performance analysis with interactive stack trace drilling
- **Real-time Activity**: Live indexing delta monitoring

### Multiple Output Formats

- **Interactive GUI**: Real-time analysis with scrollable results
- **HTML Reports**: Professional, tabbed reports with interactive features:
  - Collapsible hot threads analysis with stack trace drilling
  - Responsive design for mobile/desktop viewing
  - JavaScript-enhanced user interactions
- **Structured JSON Export**: Machine-readable data with organized sections for:
  - Programmatic analysis and integration
  - Custom reporting and visualization
  - Data pipeline integration

### Flexible Connectivity

- **Elasticsearch Cloud**: Native Cloud ID support
- **Self-hosted Clusters**: Direct URL connections
- **Authentication**: API key and basic authentication support
- **SSL Control**: Optional SSL certificate verification

## Installation

### Prerequisites

```bash
pip install elasticsearch
```

### Download

Save the application as `es_cluster_perf_analyzer.py` or clone from your repository.

## Usage

### GUI Mode (Default)

```bash
python es_cluster_perf_analyzer.py
```

This launches the graphical interface where you can:
1. Configure connection settings (Cloud ID or URL)
2. Set authentication credentials (API key or username/password)
3. Run comprehensive cluster analysis
4. View results in multiple formats

### Command Line Mode

For automated analysis and reporting:

```bash
# Using Cloud ID and API Key
python es_cluster_perf_analyzer.py \
  --cloud-id "your-cloud-id" \
  --api-key "your-api-key" \
  --run

# Using direct URL and basic auth
python es_cluster_perf_analyzer.py \
  --url "https://your-cluster:9200" \
  --user "elastic" \
  --password "your-password" \
  --run

# Export directly to JSON file
python es_cluster_perf_analyzer.py \
  --cloud-id "your-cloud-id" \
  --api-key "your-api-key" \
  --export-json "/path/to/analysis-report.json"

# Disable SSL verification if needed
python es_cluster_perf_analyzer.py \
  --url "https://localhost:9200" \
  --user "elastic" \
  --password "changeme" \
  --no-ssl-verify \
  --run
```

### Command Line Arguments

| Argument | Description |
|----------|-------------|
| `--cloud-id` | Elasticsearch Cloud ID |
| `--url` | Elasticsearch cluster URL (e.g., https://localhost:9200) |
| `--api-key` | API Key (format: 'id:key' or base64 encoded) |
| `--user` | Username for basic authentication |
| `--password` | Password for basic authentication |
| `--no-ssl-verify` | Disable SSL certificate verification |
| `--run` | Auto-run analysis and open browser report |
| `--export-json FILEPATH` | Export analysis results to specified JSON file and exit |

## Configuration Examples

### Elasticsearch Cloud

```bash
python es_cluster_perf_analyzer.py \
  --cloud-id "deployment-name:dXMtY2VudHJhbDEuZ2NwLmNsb3VkLmVzLmlvJGNlNTg2..." \
  --api-key "VnVhQ2ZHY0JDZGJrU..." \
  --run
```

### Self-hosted Cluster

```bash
python es_cluster_perf_analyzer.py \
  --url "https://es-node1.company.com:9200" \
  --user "monitoring_user" \
  --password "secure_password" \
  --run
```

### Local Development

```bash
python es_cluster_perf_analyzer.py \
  --url "http://localhost:9200" \
  --user "elastic" \
  --password "changeme" \
  --run
```

### Automated JSON Export

```bash
# Export analysis directly to JSON for automation/CI pipelines
python es_cluster_perf_analyzer.py \
  --cloud-id "deployment-name:dXMtY2VudHJhbDEuZ2NwLmNsb3VkLmVzLmlvJGNlNTg2..." \
  --api-key "VnVhQ2ZHY0JDZGJrU..." \
  --export-json "./reports/cluster-analysis-$(date +%Y%m%d).json"
```

## Analysis Output

### Key Metrics Tracked

**Performance Indicators**:
- Query latency and throughput
- Indexing rates and processing times
- Cache hit rates (query cache, request cache, field data)
- Thread pool utilization and queue depths
- GC pause times and memory pressure

**Resource Utilization**:
- CPU usage across nodes
- JVM heap utilization
- Disk space and I/O performance
- Network traffic patterns
- Segment count and memory usage

**Health Indicators**:
- Circuit breaker status
- Unassigned shards
- Hot thread detection with detailed stack traces
- Pipeline failure rates
- Node connectivity

### Report Features

**HTML Reports**:
- Tabbed interface for easy navigation between analysis sections
- Responsive design for mobile/desktop viewing
- Color-coded metrics (green/yellow/red status indicators)
- Interactive elements:
  - Collapsible hot threads analysis with stack trace drilling
  - JavaScript-enhanced navigation and content toggling
- Professional styling suitable for stakeholder presentations

**Structured JSON Export**:
- Organized data sections matching HTML report structure
- Summary metrics and detailed breakdowns for each analysis area
- Machine-readable format for:
  - Integration with monitoring systems
  - Custom dashboard creation
  - Automated analysis workflows
  - Data pipeline consumption

**Real-time Monitoring**:
- 10-second delta checks for live indexing activity
- Current thread pool status monitoring
- Active operations tracking
- Console output for CLI operations

## Troubleshooting

### Common Issues

**Connection Errors**:
```
Failed to connect to Elasticsearch. Please check credentials and network.
```
- Verify cluster URL/Cloud ID is correct
- Check authentication credentials
- Ensure network connectivity
- Try `--no-ssl-verify` for development environments

**Missing Dependencies**:
```
Please install the elasticsearch library: pip install elasticsearch
```
- Install required Python packages: `pip install elasticsearch`

**Permission Errors**:
- Ensure user has cluster monitoring privileges
- Required cluster privileges: `monitor`, `monitor_stats`

### SSL/TLS Issues

For development or self-signed certificates:
```bash
python es_cluster_perf_analyzer.py --no-ssl-verify --url "https://localhost:9200" --user "elastic" --password "changeme" --run
```

## Performance Considerations

- Analysis typically takes 30-60 seconds depending on cluster size
- Uses multiple API calls to gather comprehensive metrics
- Implements connection pooling and timeout handling
- Thread-safe GUI updates prevent interface freezing
- Structured data storage enables efficient JSON export

## Security Notes

- Credentials are not stored persistently
- SSL verification enabled by default
- Supports read-only monitoring users
- No data modification operations performed

## Requirements

- Python 3.6+
- `elasticsearch` Python library
- `tkinter` (usually included with Python)
- Network access to Elasticsearch cluster

## License

This tool is provided as-is for Elasticsearch cluster monitoring and analysis purposes.

---

**Note**: This analyzer performs read-only operations and does not modify cluster data or settings. It's designed to be safe for use in production environments with appropriate monitoring credentials.
