import argparse
import json
from .connection import get_es_client
from .analysis import cluster_overview, pipeline_performance, node_resources, thread_pools, memory_gc, circuit_breakers, search_performance, io_performance, network_traffic, index_operations, segments_allocation, hot_threads, shard_distribution, indexing_delta
from .reporting import html_report, json_report
from .utils.formatters import format_table

def setup_parser():
    """Sets up the argument parser for the CLI."""
    parser = argparse.ArgumentParser(description="Elasticsearch Cluster Analyzer. Run with no arguments for GUI mode.")
    conn_group = parser.add_mutually_exclusive_group()
    conn_group.add_argument("--cloud-id", help="Elasticsearch Cloud ID")
    conn_group.add_argument("--url", help="Elasticsearch cluster URL (e.g., https://localhost:9200)")
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument("--api-key", help="API Key for authentication (format: 'id:key' or base64 encoded string)")
    auth_group.add_argument("--user", help="Username for basic authentication")
    parser.add_argument("--password", help="Password for basic authentication (required with --user)")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--run", action="store_true", help="Automatically run analysis, open report in browser, and exit.")
    parser.add_argument("--export-json", metavar="FILEPATH", help="Export analysis results to the specified JSON file and exit.")
    return parser

def handle_cli(args):
    """Handles the command-line interface execution."""
    try:
        config = {
            'cloud_id': args.cloud_id, 'url': args.url, 'api_key': args.api_key,
            'user': args.user, 'password': args.password, 'verify_ssl': not args.no_ssl_verify
        }
        es = get_es_client(config)
        print("Successfully connected to Elasticsearch cluster.")

        analysis_data = {}
        analysis_functions = {
            'cluster_overview': cluster_overview.analyze_cluster_overview,
            'pipeline_performance': pipeline_performance.analyze_pipeline_performance,
            'node_resources': node_resources.analyze_node_resources,
            'thread_pools': thread_pools.analyze_thread_pools,
            'memory_and_gc': memory_gc.analyze_memory_and_gc,
            'circuit_breakers': circuit_breakers.analyze_circuit_breakers,
            'search_performance': search_performance.analyze_search_performance,
            'io_performance': io_performance.analyze_io_performance,
            'network_traffic': network_traffic.analyze_network_traffic,
            'index_operations': index_operations.analyze_index_operations,
            'segments_and_allocation': segments_allocation.analyze_segments_and_allocation,
            'hot_threads': hot_threads.analyze_hot_threads,
            'shard_distribution': shard_distribution.analyze_shard_distribution,
            'indexing_delta': indexing_delta.analyze_indexing_delta,
        }

        for name, func in analysis_functions.items():
            print(f"Running {name} analysis...")
            analysis_data[name] = func(es)

        print("\nAnalysis complete.")

        if args.export_json:
            success, message = json_report.save_json_report(analysis_data, args.export_json)
            print(message)
        
        if args.run:
            print("Generating HTML report...")
            text_report = generate_text_report(analysis_data)
            html_content = html_report.generate_html_report(analysis_data, text_report)
            html_report.open_in_browser(html_content, None)
            print("HTML report has been opened in your browser.")

    except Exception as e:
        print(f"Error: {str(e)}")

def generate_text_report(analysis_data):
    """Generates a formatted text report from analysis data."""
    report_parts = []
    
    render_map = {
        'cluster_overview': _render_cluster_overview_report,
        'pipeline_performance': _render_pipeline_performance_report,
        'node_resources': _render_node_resources_report,
        'thread_pools': _render_thread_pools_report,
        'memory_and_gc': _render_memory_and_gc_report,
        'circuit_breakers': _render_circuit_breakers_report,
        'search_performance': _render_search_performance_report,
        'io_performance': _render_io_performance_report,
        'network_traffic': _render_network_traffic_report,
        'index_operations': _render_index_operations_report,
        'segments_and_allocation': _render_segments_and_allocation_report,
        'hot_threads': _render_hot_threads_report,
        'shard_distribution': _render_shard_distribution_report,
        'indexing_delta': _render_indexing_delta_report,
    }
    
    for section_name, data in analysis_data.items():
        if section_name in render_map:
            report_parts.append(render_map[section_name](data))
            
    return "".join(report_parts)

# --- Text Rendering Functions ---

def _render_cluster_overview_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for cluster_overview.\n\n"
    parts = ["📋 CLUSTER OVERVIEW:\n\n"]
    status = data['info']['status']
    status_icon = '🟢' if status == 'green' else '🟡' if status == 'yellow' else '🔴'
    rows = [['Cluster Name', data['info']['cluster_name']], ['Status', f"{status_icon} {status.upper()}"], ['Elasticsearch Version', data['info']['es_version']], ['Total Nodes', str(data['info']['total_nodes'])], ['Data Nodes', str(data['info']['data_nodes'])]]
    parts.append(format_table(headers=['Property', 'Value'], rows=rows, title="Cluster Information"))
    shard_rows = [['Active Primary', str(data['shard_health']['active_primary'])], ['Total Active', str(data['shard_health']['active_total'])], ['Relocating', str(data['shard_health']['relocating'])], ['Initializing', str(data['shard_health']['initializing'])], ['Unassigned', f"{'⚠️ ' if data['shard_health']['unassigned'] > 0 else ''}{data['shard_health']['unassigned']}"]]
    parts.append(format_table(headers=['Shard Type', 'Count'], rows=shard_rows, title="Shard Health"))
    if data['node_roles']:
        parts.append(format_table(headers=['Node Role', 'Count'], rows=sorted(data['node_roles'].items()), title="Node Roles"))
    for warning in data['warnings']: parts.append(f"   ⚠️  {warning}\n")
    parts.append("\n")
    return "".join(parts)

def _render_pipeline_performance_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for pipeline_performance.\n\n"
    parts = ["⚡ PIPELINE PERFORMANCE ANALYSIS:\n\n", "   Pipeline Summary:\n"]
    parts.append(f"   📈 Total Documents Processed: {data['summary']['total_docs_processed']:,}\n")
    parts.append(f"   📈 Average Processing Time: {data['summary']['avg_processing_time_ms']:.2f}ms\n")
    if data['summary']['total_failures'] > 0: parts.append(f"   ⚠️  Total Failed Operations: {data['summary']['total_failures']:,}\n")
    parts.append("\n")
    active_pipelines = sorted([p for p in data['pipelines'].items() if p[1]['count'] > 0], key=lambda x: x[1]['count'], reverse=True)
    if active_pipelines:
        healthy_rows, failed_rows = [], []
        for pid, metrics in active_pipelines:
            avg_time = metrics['time_ms'] / metrics['count']
            row = [pid, f"{metrics['count']:,}", f"{avg_time:.2f}ms"]
            if metrics['failed'] > 0:
                row.extend([f"{metrics['failed']:,}", f"{(metrics['failed'] / metrics['count'] * 100):.1f}%"])
                failed_rows.append(row)
            else:
                healthy_rows.append(row)
        if failed_rows: parts.append(format_table(headers=['Pipeline', 'Docs', 'Avg Time', 'Failed', 'Failure %'], rows=failed_rows, title="⚠️ Pipelines with Failures"))
        if healthy_rows: parts.append(format_table(headers=['Pipeline', 'Documents', 'Avg Time'], rows=healthy_rows, title="✅ Healthy Pipelines"))
    else: parts.append("   No active pipelines found.\n\n")
    return "".join(parts)

def _render_node_resources_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for node_resources.\n\n"
    parts = ["📊 NODE RESOURCES:\n\n", "   Resource Summary:\n"]
    parts.append(f"   📈 Total Cluster vCPUs: {data['summary']['total_cluster_vcpus']}\n")
    parts.append(f"   📈 Total Nodes: {data['summary']['total_nodes']}\n")
    parts.append(f"   📈 Average CPU Usage: {data['summary']['avg_cpu_usage_percent']:.1f}%\n")
    parts.append(f"   📈 Average Load: {data['summary']['avg_load_1m']:.2f}\n\n")
    rows = [[d['node'], d['roles'], d['cpus'], d['heap_size'], d['ram'], d['cpu_usage_percent'], d['load_1m']] for d in data['details_by_node']]
    parts.append(format_table(headers=['Node Name', 'Roles', 'CPUs', 'Heap Size', 'RAM', 'CPU Usage', 'Load'], rows=rows, title="Node Resources"))
    return "".join(parts)

def _render_thread_pools_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for thread_pools.\n\n"
    parts = ["🧵 COMPREHENSIVE THREAD POOL ANALYSIS:\n\n"]
    overall_totals = data['summary']
    parts.append("   Thread Pool Health Summary:\n")
    parts.append(f"   📊 Total Active Threads: {overall_totals['active']}\n")
    parts.append(f"   📊 Total Queued Operations: {overall_totals['queue']}\n")
    parts.append(f"   📊 Total Available Threads: {overall_totals['available']}\n")
    if overall_totals['rejected'] > 0:
        parts.append(f"   ⚠️  Total Rejections: {overall_totals['rejected']}\n")
    health_status = "🟢 Good" if overall_totals['utilization_percent'] < 50 else "🟡 Moderate" if overall_totals['utilization_percent'] < 80 else "🔴 High"
    parts.append(f"   {health_status} Overall Thread Pool Utilization: {overall_totals['utilization_percent']:.1f}%\n\n")
    pool_types_of_interest = ['search', 'get', 'bulk', 'write', 'management', 'flush', 'refresh', 'merge']
    for pool_type in pool_types_of_interest:
        if pool_type in data['pools'] and (data['pools'][pool_type]['summary']['active'] > 0 or data['pools'][pool_type]['summary']['queue'] > 0 or data['pools'][pool_type]['summary']['rejected'] > 0):
            pool_data = data['pools'][pool_type]
            rows = [[d['node'], str(d['active']), str(d['queue']), str(d['size']), str(d['rejected'])] for d in pool_data['details']]
            parts.append(format_table(headers=['Node', 'Active', 'Queue', 'Size', 'Rejected'], rows=sorted(rows, key=lambda x: x[0]), title=f"{pool_type.title()} Thread Pool"))
            for warning in data['warnings']:
                if pool_type in warning.lower(): parts.append(f"   ⚠️  {warning}\n")
            parts.append("\n")
    return "".join(parts)

def _render_memory_and_gc_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for memory_and_gc.\n\n"
    parts = ["🧠 MEMORY & GARBAGE COLLECTION ANALYSIS:\n\n"]
    summary = data['summary']
    parts.append("   GC Performance Summary:\n")
    parts.append(f"   📊 Total GC Collections: {summary['total_gc_collections']:,}\n")
    parts.append(f"   📊 Average GC Time: {summary['avg_gc_time_ms']:.2f}ms\n")
    parts.append(f"   📊 Total GC Time: {summary['total_gc_time_s']:.1f}s\n")
    if summary['avg_gc_time_ms'] > 100: parts.append("   ⚠️  High average GC pause times detected\n")
    if data['gc_by_node'] and sum(d['old_gc_count'] for d in data['gc_by_node']) > sum(d['young_gc_count'] for d in data['gc_by_node']) * 0.1: parts.append("   ⚠️  Frequent old generation GCs detected\n")
    parts.append("\n")
    if data['warnings']:
        for warning in data['warnings']: parts.append(f"   ⚠️  {warning}\n")
        parts.append("\n")
    mem_rows = [[d['node'], f"{d['heap_used_bytes'] / 1024**2:.0f}MB", f"{d['heap_max_bytes'] / 1024**2:.0f}MB", f"{d['heap_used_percent']:.1f}%", f"{d['old_gen_used_bytes'] / 1024**2:.0f}MB", f"{d['old_gen_used_percent']:.1f}%"] for d in data['memory_by_node']]
    gc_rows = [[d['node'], str(d['young_gc_count']), f"{d['avg_young_gc_ms']:.1f}ms", str(d['old_gc_count']), f"{d['avg_old_gc_ms']:.1f}ms" if d['old_gc_count'] > 0 else "0ms"] for d in data['gc_by_node']]
    parts.append(format_table(headers=['Node', 'Heap Used', 'Heap Max', 'Heap %', 'Old Gen Used', 'Old Gen %'], rows=mem_rows, title="Memory Utilization"))
    parts.append(format_table(headers=['Node', 'Young GCs', 'Avg Young', 'Old GCs', 'Avg Old'], rows=gc_rows, title="Garbage Collection Performance"))
    return "".join(parts)

def _render_circuit_breakers_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for circuit_breakers.\n\n"
    parts = ["🛡️ CIRCUIT BREAKER ANALYSIS:\n\n"]
    total_tripped = data['summary']['total_tripped']
    parts.append("   Circuit Breaker Summary:\n")
    if total_tripped > 0:
        parts.append(f"   ⚠️🔥 Total Breaker Trips Detected: {total_tripped}\n")
        parts.append("      Investigate immediately! Tripped breakers indicate memory pressure and can cause request failures.\n")
    else:
        parts.append("   ✅ No circuit breaker trips detected. Memory management is stable.\n")
    parts.append("\n")
    rows = [[d['node'], d['breaker'], f"{d['limit_bytes'] / 1024**2:.1f}MB", f"{d['estimated_bytes'] / 1024**2:.1f}MB", f"{d['usage_percent']:.1f}%", str(d['tripped_count'])] for d in data['details']]
    if rows:
        parts.append(format_table(headers=['Node', 'Breaker', 'Limit', 'Estimated', 'Usage %', 'Tripped'], rows=rows, title="Circuit Breaker Status by Node"))
    return "".join(parts)

def _render_search_performance_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for search_performance.\n\n"
    parts = ["🔍 SEARCH PERFORMANCE & CACHE ANALYSIS:\n\n"]
    summary = data['summary']
    parts.append("   Search & Cache Summary:\n")
    parts.append(f"   📊 Average Query Latency: {summary['avg_query_latency_ms']:.2f}ms\n")
    parts.append(f"   📊 Total Queries: {summary['total_queries']:,}\n")
    parts.append(f"   📊 Query Cache Hit Rate: {summary['query_cache_hit_rate']:.1f}%\n")
    parts.append(f"   📊 Request Cache Hit Rate: {summary['request_cache_hit_rate']:.1f}%\n")
    parts.append(f"   📊 Field Data Memory: {summary['fielddata_memory_bytes'] / 1024**2:.1f}MB\n")
    if data['warnings']:
        for warning in data['warnings']: parts.append(f"   ⚠️  {warning}\n")
    parts.append("\n")
    cache_rows = [[idx['index'][:30], f"{idx['query_cache_hit_rate']:.1f}%", f"{idx['request_cache_hit_rate']:.1f}%", f"{idx['query_cache_memory_bytes'] / 1024**2:.1f}MB", f"{idx['fielddata_memory_bytes'] / 1024**2:.1f}MB"] for idx in data['cache_by_index']]
    search_rows = [[node['node'], f"{node['query_total']:,}", f"{node['avg_query_ms']:.2f}ms", f"{node['fetch_total']:,}", f"{node['avg_fetch_ms']:.2f}ms", str(node['query_current'])] for node in data['performance_by_node']]
    if cache_rows: parts.append(format_table(headers=['Index', 'Query Cache Hit %', 'Request Cache Hit %', 'Query Cache Mem', 'Field Data Mem'], rows=cache_rows, title="Cache Performance by Index"))
    parts.append(format_table(headers=['Node', 'Total Queries', 'Avg Query Time', 'Total Fetches', 'Avg Fetch Time', 'Current'], rows=search_rows, title="Search Performance by Node"))
    return "".join(parts)

def _render_io_performance_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for io_performance.\n\n"
    parts = ["💾 I/O & DISK PERFORMANCE ANALYSIS:\n\n"]
    summary = data['summary']
    parts.append("   I/O & Storage Summary:\n")
    parts.append(f"   📊 Total Cluster Storage: {summary['total_cluster_storage_gb']:.1f}GB\n")
    parts.append(f"   📊 Available Storage: {summary['available_storage_gb']:.1f}GB\n")
    parts.append(f"   📊 Cluster Storage Usage: {summary['cluster_storage_usage_percent']:.1f}%\n")
    parts.append(f"   📊 Total Disk Reads: {summary['total_disk_reads']:,}\n")
    parts.append(f"   📊 Total Disk Writes: {summary['total_disk_writes']:,}\n")
    if data['warnings']:
        for warning in data['warnings']: parts.append(f"   ⚠️  {warning}\n")
    parts.append("\n")
    rows = [[d['node'], f"{d['total_space_gb']:.1f}GB", f"{d['used_space_gb']:.1f}GB", f"{d['disk_used_percent']:.1f}%", f"{d['read_ops']:,}", f"{d['write_ops']:,}", f"{d['read_mb']:.1f}MB", f"{d['write_mb']:.1f}MB"] for d in data['details_by_node']]
    parts.append(format_table(headers=['Node', 'Total Space', 'Used Space', 'Usage %', 'Read Ops', 'Write Ops', 'Read Data', 'Write Data'], rows=rows, title="Disk Usage and I/O Performance"))
    return "".join(parts)

def _render_network_traffic_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for network_traffic.\n\n"
    parts = ["🌐 NETWORK TRAFFIC ANALYSIS:\n\n"]
    summary = data['summary']
    parts.append("   Network Summary:\n")
    parts.append(f"   📊 Total Data Received (RX): {summary['total_rx_mb']:.1f}MB\n")
    parts.append(f"   📊 Total Data Sent (TX): {summary['total_tx_mb']:.1f}MB\n\n")
    rows = [[d['node'], f"{d['rx_count']:,}", f"{d['tx_count']:,}", f"{d['rx_mb']:.1f}MB", f"{d['tx_mb']:.1f}MB", str(d['server_connections_open'])] for d in data['details_by_node']]
    parts.append(format_table(headers=['Node', 'RX Count', 'TX Count', 'RX Data', 'TX Data', 'Connections'], rows=rows, title="Network Transport Performance"))
    return "".join(parts)

def _render_index_operations_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for index_operations.\n\n"
    parts = ["📝 INDEX OPERATIONS ANALYSIS:\n\n"]
    summary = data['summary']
    parts.append("   Index Operations Summary:\n")
    parts.append(f"   📊 Total Index Operations: {summary['index_total']:,}\n")
    parts.append(f"   📊 Average Index Latency: {summary['avg_index_latency_ms']:.2f}ms\n")
    parts.append(f"   📊 Total Refresh Operations: {summary['refresh_total']:,}\n")
    parts.append(f"   📊 Average Refresh Latency: {summary['avg_refresh_latency_ms']:.2f}ms\n")
    parts.append(f"   📊 Total Merge Operations: {summary['merge_total']:,}\n")
    if summary['merge_total'] > 0: parts.append(f"   📊 Average Merge Latency: {summary['avg_merge_latency_ms']:.2f}ms\n")
    if data['warnings']:
        for warning in data['warnings']: parts.append(f"   ⚠️  {warning}\n")
    parts.append("\n")
    indexing_rows, ops_rows = [], []
    for name, d in data['details_by_index'].items():
        if d['index_total'] > 1000 or d['delete_total'] > 100 or d['index_current'] > 0:
            indexing_rows.append([name[:25], f"{d['index_total']:,}", f"{d['avg_index_ms']:.2f}ms", f"{d['delete_total']:,}", f"{d['avg_delete_ms']:.2f}ms", str(d['index_current'])])
        if d['refresh_total'] > 0 or d['merge_total'] > 0:
            ops_rows.append([name[:25], f"{d['refresh_total']:,}", f"{d['avg_refresh_ms']:.2f}ms", f"{d['merge_total']:,}", f"{d['avg_merge_ms']:.2f}ms", str(d['merge_current'])])
    if indexing_rows: parts.append(format_table(headers=['Index', 'Index Ops', 'Avg Index Time', 'Delete Ops', 'Avg Delete Time', 'Current'], rows=indexing_rows, title="Indexing Performance by Index"))
    if ops_rows: parts.append(format_table(headers=['Index', 'Refresh Ops', 'Avg Refresh', 'Merge Ops', 'Avg Merge', 'Current Merges'], rows=ops_rows, title="Index Operations Performance"))
    return "".join(parts)

def _render_segments_and_allocation_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for segments_and_allocation.\n\n"
    parts = ["🔧 SEGMENTS & ALLOCATION ANALYSIS:\n\n"]
    summary = data['summary']
    parts.append("   Segments & Allocation Summary:\n")
    parts.append(f"   📊 Total Segments: {summary['total_segments']:,}\n")
    parts.append(f"   📊 Total Segment Memory: {summary['total_segment_memory_bytes'] / 1024**2:.1f}MB\n")
    parts.append(f"   📊 Total Shards (on data nodes): {summary['total_shards_on_data_nodes']}\n")
    parts.append(f"   📊 Average Segments per Index: {summary['avg_segments_per_index']:.1f}\n")
    if data['warnings']:
        for warning in data['warnings']: parts.append(f"   ⚠️  {warning}\n")
    parts.append("\n")
    seg_rows = [[d['index'][:25], str(d['segment_count']), f"{d['memory_bytes'] / 1024**2:.1f}MB", f"{d['max_segment_size_bytes'] / 1024**2:.1f}MB"] for d in data['segments_by_index']]
    if seg_rows: parts.append(format_table(headers=['Index', 'Segments', 'Memory Usage', 'Largest Segment'], rows=sorted(seg_rows, key=lambda x: int(x[1]), reverse=True)[:20], title="Segment Analysis (Top 20 by Count)"))
    alloc_rows = [[d['node'], str(d['shards']), d['disk_used'], d['disk_available'], f"{d['disk_usage_percent']}%"] for d in data['allocation_by_node']]
    parts.append(format_table(headers=['Node', 'Shards', 'Disk Used', 'Disk Available', 'Usage %'], rows=alloc_rows, title="Shard Allocation by Node"))
    return "".join(parts)

def _render_hot_threads_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for hot_threads.\n\n"
    parts = ["🔥 HOT THREADS ANALYSIS:\n\n"]
    total = data['summary']['total_hot_threads']
    parts.append("   Hot Threads Summary:\n")
    parts.append(f"   📊 Total Hot Threads Detected: {total}\n")
    if not data['parsed_nodes']:
        parts.append("   ✅ No significant hot threads detected.\n\n")
    else:
        parts.append(f"   ⚠️  {data['warnings'][0]}\n\n")
        parts.append("---HOT-THREADS-INTERACTIVE-START---\n")
        parts.append(json.dumps(data['parsed_nodes']))
        parts.append("\n---HOT-THREADS-INTERACTIVE-END---\n")
    return "".join(parts)
    
def _render_shard_distribution_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for shard_distribution.\n\n"
    parts = ["🔍 SHARD DISTRIBUTION ANALYSIS:\n\n"]
    summary = data['summary']
    parts.append("   Cluster Shard Summary:\n")
    parts.append(f"   📈 Total Indices: {summary['total_indices']}\n")
    parts.append(f"   📈 Total Primary Shards: {summary['total_primary_shards']}\n")
    parts.append(f"   📈 Total Replica Shards: {summary['total_replica_shards']}\n")
    parts.append(f"   📈 Total Documents: {summary['total_documents']:,}\n")
    if summary['unassigned_shards'] > 0:
        parts.append(f"   ⚠️  Warning: {data['warnings'][0]}\n")
    parts.append("\n")
    return "".join(parts)

def _render_indexing_delta_report(data):
    if not data or data.get('error'): return "   ⚠️  Could not retrieve data for indexing_delta.\n\n"
    parts = ["📝 CURRENT INDEXING ACTIVITY (DELTA CHECK):\n"]
    if not data['active_indices']:
        parts.append(f"   ⚠️  {data['warnings'][0]}\n")
    else:
        parts.append(f"   📈 ACTIVE INDICES (DELTA CHECK): {data['summary']['active_index_count']}\n")
        for item in data['active_indices']:
            parts.append(f"   ✅ Indexing detected in {item['index']} (+{item['new_operations']:,} ops)\n")
    parts.append("\n")
    return "".join(parts)