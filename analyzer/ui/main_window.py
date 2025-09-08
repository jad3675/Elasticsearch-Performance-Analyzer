import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import json
from ..connection import get_es_client
from ..analysis import cluster_overview, pipeline_performance, node_resources, thread_pools, memory_gc, circuit_breakers, search_performance, io_performance, network_traffic, index_operations, segments_allocation, hot_threads, shard_distribution, indexing_delta
from ..reporting import html_report, json_report
from ..utils.formatters import format_table

class ElasticsearchAnalyzer:
    def __init__(self, root, cli_args=None):
        self.root = root
        self.root.title("Elasticsearch Cluster Resource Analyzer")
        self.root.geometry("800x700")
        self.cli_args = cli_args
        
        # Variables
        self.connection_type = tk.StringVar(value="cloud_id")
        self.auth_type = tk.StringVar(value="api_key")
        self.cloud_id_var = tk.StringVar()
        self.url_var = tk.StringVar()
        self.api_key_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.verify_ssl_var = tk.BooleanVar(value=True)
        self.es = None
        self.analysis_data = {}
        
        self.setup_ui()

    def toggle_connection_fields(self):
        """Toggle visibility of connection fields based on connection type."""
        if self.connection_type.get() == "cloud_id":
            self.cloud_frame.grid()
            self.url_frame.grid_remove()
        else:
            self.cloud_frame.grid_remove()
            self.url_frame.grid()

    def toggle_auth_fields(self):
        """Toggle visibility of authentication fields based on auth type."""
        if self.auth_type.get() == "api_key":
            self.api_key_frame.grid()
            self.basic_auth_frame.grid_remove()
        else:
            self.api_key_frame.grid_remove()
            self.basic_auth_frame.grid()
    
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Connection section
        conn_frame = ttk.LabelFrame(main_frame, text="Elasticsearch Connection", padding="10")
        conn_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Connection Type Selection
        ttk.Label(conn_frame, text="Connection Type:").grid(row=0, column=0, sticky=tk.W)
        
        ttk.Radiobutton(
            conn_frame, text="Cloud ID", variable=self.connection_type,
            value="cloud_id", command=self.toggle_connection_fields
        ).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Radiobutton(
            conn_frame, text="URL", variable=self.connection_type,
            value="url", command=self.toggle_connection_fields
        ).grid(row=0, column=2, sticky=tk.W)
        
        # Cloud ID Frame
        self.cloud_frame = ttk.Frame(conn_frame)
        self.cloud_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E))
        self.cloud_frame.columnconfigure(1, weight=1)
        ttk.Label(self.cloud_frame, text="Cloud ID:").grid(row=0, column=0, sticky=tk.W)
        self.cloud_id_entry = ttk.Entry(self.cloud_frame, textvariable=self.cloud_id_var, width=60)
        self.cloud_id_entry.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5)
        
        # URL Frame
        self.url_frame = ttk.Frame(conn_frame)
        self.url_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E))
        self.url_frame.columnconfigure(1, weight=1)
        ttk.Label(self.url_frame, text="URL:").grid(row=0, column=0, sticky=tk.W)
        self.url_entry = ttk.Entry(self.url_frame, textvariable=self.url_var, width=60)
        self.url_entry.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), padx=5)
        
        # Authentication Frame
        auth_frame = ttk.LabelFrame(conn_frame, text="Authentication", padding="5")
        auth_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        ttk.Label(auth_frame, text="Auth Type:").grid(row=0, column=0, sticky=tk.W)
        
        ttk.Radiobutton(
            auth_frame, text="API Key", variable=self.auth_type,
            value="api_key", command=self.toggle_auth_fields
        ).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Radiobutton(
            auth_frame, text="Basic Auth", variable=self.auth_type,
            value="basic", command=self.toggle_auth_fields
        ).grid(row=0, column=2, sticky=tk.W)
        
        # API Key Frame
        self.api_key_frame = ttk.Frame(auth_frame)
        self.api_key_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E))
        self.api_key_frame.columnconfigure(1, weight=1)
        ttk.Label(self.api_key_frame, text="API Key:").grid(row=0, column=0, sticky=tk.W)
        self.api_key_entry = ttk.Entry(self.api_key_frame, textvariable=self.api_key_var, width=60, show="*")
        self.api_key_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        help_label = ttk.Label(self.api_key_frame, text="Format: encoded_key OR key_id:key_secret",
                                 font=("TkDefaultFont", 8), foreground="gray")
        help_label.grid(row=1, column=1, sticky=tk.W, padx=5)
        
        # Basic Auth Frame
        self.basic_auth_frame = ttk.Frame(auth_frame)
        self.basic_auth_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E))
        self.basic_auth_frame.columnconfigure(1, weight=1)
        ttk.Label(self.basic_auth_frame, text="Username:").grid(row=0, column=0, sticky=tk.W)
        self.username_entry = ttk.Entry(self.basic_auth_frame, textvariable=self.username_var, width=60)
        self.username_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        ttk.Label(self.basic_auth_frame, text="Password:").grid(row=1, column=0, sticky=tk.W)
        self.password_entry = ttk.Entry(self.basic_auth_frame, textvariable=self.password_var, width=60, show="*")
        self.password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5)

        # SSL Verification
        ttk.Checkbutton(
            conn_frame, text="Verify SSL Certificate", variable=self.verify_ssl_var
        ).grid(row=4, column=0, columnspan=3, sticky=tk.W, pady=(5, 0))
        
        # Buttons frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        connect_btn = ttk.Button(btn_frame, text="Connect & Analyze", command=self.analyze_cluster)
        connect_btn.pack(side=tk.LEFT, padx=5)
        
        # Initial visibility setup
        self.toggle_connection_fields()
        self.toggle_auth_fields()
        ttk.Button(btn_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        self.browser_btn = ttk.Button(btn_frame, text="Open in Browser", command=self.open_in_browser, state=tk.DISABLED)
        self.browser_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(btn_frame, text="Export to JSON", command=self.export_results_to_json, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results", padding="10")
        results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        
        # Text widget for results
        self.results_text = scrolledtext.ScrolledText(results_frame, width=80, height=30, wrap=tk.WORD)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
    
    def analyze_cluster(self):
        """Main analysis function"""
        # Run analysis in separate thread to prevent UI blocking
        threading.Thread(target=self._run_analysis, daemon=True).start()
    
    def _run_analysis(self):
        """Run the actual analysis (called in separate thread)"""
        try:
            self.analysis_data = {}
            
            config = {
                'cloud_id': self.cloud_id_var.get().strip(),
                'url': self.url_var.get().strip(),
                'api_key': self.api_key_var.get().strip(),
                'user': self.username_var.get().strip(),
                'password': self.password_var.get().strip(),
                'verify_ssl': self.verify_ssl_var.get()
            }
            self.es = get_es_client(config)
            
            self.update_results("Connecting to Elasticsearch cluster...\n")

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
                self.update_results(f"Running {name} analysis...\n")
                self.analysis_data[name] = func(self.es)
                self._render_text_report(name)

            self.update_results("\n✅ Analysis Complete\n")
            
        except Exception as e:
            error_msg = str(e)
            self.update_results(f"❌ Error during analysis: {error_msg}\n")
            messagebox.showerror("Analysis Error", error_msg)
    
    def _render_text_report(self, section_name):
        data = self.analysis_data.get(section_name)
        if not data or data.get('error'):
            self.update_results(f"   ⚠️  Could not retrieve data for {section_name}.\n\n")
            return

        # Dynamically call the render function for the specific section
        render_function_name = f"_render_{section_name}_report"
        render_function = getattr(self, render_function_name, self._render_default_report)
        render_function(data)

    def _render_default_report(self, data):
        self.update_results(json.dumps(data, indent=2) + "\n\n")

    def _render_cluster_overview_report(self, data):
        self.update_results("📋 CLUSTER OVERVIEW:\n\n")
        status = data['info']['status']
        status_icon = '🟢' if status == 'green' else '🟡' if status == 'yellow' else '🔴'
        overview_table_rows = [
            ['Cluster Name', data['info']['cluster_name']],
            ['Status', f"{status_icon} {status.upper()}"],
            ['Elasticsearch Version', data['info']['es_version']],
            ['Total Nodes', str(data['info']['total_nodes'])],
            ['Data Nodes', str(data['info']['data_nodes'])]
        ]
        self.update_results(format_table(headers=['Property', 'Value'], rows=overview_table_rows, title="Cluster Information"))
        
        shard_health_rows = [
            ['Active Primary', str(data['shard_health']['active_primary'])],
            ['Total Active', str(data['shard_health']['active_total'])],
            ['Relocating', str(data['shard_health']['relocating'])],
            ['Initializing', str(data['shard_health']['initializing'])],
            ['Unassigned', f"{'⚠️ ' if data['shard_health']['unassigned'] > 0 else ''}{data['shard_health']['unassigned']}"]
        ]
        self.update_results(format_table(headers=['Shard Type', 'Count'], rows=shard_health_rows, title="Shard Health"))

        if data['node_roles']:
            self.update_results(format_table(headers=['Node Role', 'Count'], rows=sorted(data['node_roles'].items()), title="Node Roles"))
        
        for warning in data['warnings']: self.update_results(f"   ⚠️  {warning}\n")
        self.update_results("\n")

    def _render_pipeline_performance_report(self, data):
        self.update_results("⚡ PIPELINE PERFORMANCE ANALYSIS:\n\n")
        self.update_results("   Pipeline Summary:\n")
        self.update_results(f"   📈 Total Documents Processed: {data['summary']['total_docs_processed']:,}\n")
        self.update_results(f"   📈 Average Processing Time: {data['summary']['avg_processing_time_ms']:.2f}ms\n")
        if data['summary']['total_failures'] > 0: self.update_results(f"   ⚠️  Total Failed Operations: {data['summary']['total_failures']:,}\n")
        self.update_results("\n")

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
            if failed_rows: self.update_results(format_table(headers=['Pipeline', 'Docs', 'Avg Time', 'Failed', 'Failure %'], rows=failed_rows, title="⚠️ Pipelines with Failures"))
            if healthy_rows: self.update_results(format_table(headers=['Pipeline', 'Documents', 'Avg Time'], rows=healthy_rows, title="✅ Healthy Pipelines"))
        else: self.update_results("   No active pipelines found.\n\n")

    def _render_node_resources_report(self, data):
        self.update_results("📊 NODE RESOURCES:\n\n")
        self.update_results("   Resource Summary:\n")
        self.update_results(f"   📈 Total Cluster vCPUs: {data['summary']['total_cluster_vcpus']}\n")
        self.update_results(f"   📈 Total Nodes: {data['summary']['total_nodes']}\n")
        self.update_results(f"   📈 Average CPU Usage: {data['summary']['avg_cpu_usage_percent']:.1f}%\n")
        self.update_results(f"   📈 Average Load: {data['summary']['avg_load_1m']:.2f}\n\n")
        
        table_rows = [[
            d['node'], d['roles'], d['cpus'], d['heap_size'],
            d['ram'], d['cpu_usage_percent'], d['load_1m']
        ] for d in data['details_by_node']]
        self.update_results(format_table(headers=['Node Name', 'Roles', 'CPUs', 'Heap Size', 'RAM', 'CPU Usage', 'Load'], rows=table_rows, title="Node Resources"))

    def _render_thread_pools_report(self, data):
        self.update_results("🧵 COMPREHENSIVE THREAD POOL ANALYSIS:\n\n")
        overall_totals = data['summary']
        self.update_results("   Thread Pool Health Summary:\n")
        self.update_results(f"   📊 Total Active Threads: {overall_totals['active']}\n")
        self.update_results(f"   📊 Total Queued Operations: {overall_totals['queue']}\n")
        self.update_results(f"   📊 Total Available Threads: {overall_totals['available']}\n")
        if overall_totals['rejected'] > 0:
            self.update_results(f"   ⚠️  Total Rejections: {overall_totals['rejected']}\n")
        
        health_status = "🟢 Good" if overall_totals['utilization_percent'] < 50 else "🟡 Moderate" if overall_totals['utilization_percent'] < 80 else "🔴 High"
        self.update_results(f"   {health_status} Overall Thread Pool Utilization: {overall_totals['utilization_percent']:.1f}%\n\n")

        pool_types_of_interest = ['search', 'get', 'bulk', 'write', 'management', 'flush', 'refresh', 'merge']
        for pool_type in pool_types_of_interest:
            if pool_type in data['pools']:
                pool_data = data['pools'][pool_type]
                
                if pool_data['summary']['active'] > 0 or pool_data['summary']['queue'] > 0 or pool_data['summary']['rejected'] > 0:
                    table_rows = [[
                        d['node'], str(d['active']), str(d['queue']), str(d['size']), str(d['rejected'])
                    ] for d in pool_data['details']]
                    
                    self.update_results(format_table(
                        headers=['Node', 'Active', 'Queue', 'Size', 'Rejected'],
                        rows=sorted(table_rows, key=lambda x: x[0]),
                        title=f"{pool_type.title()} Thread Pool"
                    ))
                    
                    for warning in data['warnings']:
                        if pool_type in warning.lower(): self.update_results(f"   ⚠️  {warning}\n")
                    self.update_results("\n")

    def _render_memory_and_gc_report(self, data):
        self.update_results("🧠 MEMORY & GARBAGE COLLECTION ANALYSIS:\n\n")
        summary = data['summary']
        self.update_results("   GC Performance Summary:\n")
        self.update_results(f"   📊 Total GC Collections: {summary['total_gc_collections']:,}\n")
        self.update_results(f"   📊 Average GC Time: {summary['avg_gc_time_ms']:.2f}ms\n")
        self.update_results(f"   📊 Total GC Time: {summary['total_gc_time_s']:.1f}s\n")
        
        if summary['avg_gc_time_ms'] > 100: self.update_results("   ⚠️  High average GC pause times detected\n")
        if data['gc_by_node'] and sum(d['old_gc_count'] for d in data['gc_by_node']) > sum(d['young_gc_count'] for d in data['gc_by_node']) * 0.1:
            self.update_results("   ⚠️  Frequent old generation GCs detected\n")
        self.update_results("\n")

        if data['warnings']:
            for warning in data['warnings']: self.update_results(f"   ⚠️  {warning}\n")
            self.update_results("\n")
        
        memory_rows = [[
            d['node'], f"{d['heap_used_bytes'] / 1024**2:.0f}MB", f"{d['heap_max_bytes'] / 1024**2:.0f}MB",
            f"{d['heap_used_percent']:.1f}%", f"{d['old_gen_used_bytes'] / 1024**2:.0f}MB", f"{d['old_gen_used_percent']:.1f}%"
        ] for d in data['memory_by_node']]
        
        gc_rows = [[
            d['node'], str(d['young_gc_count']), f"{d['avg_young_gc_ms']:.1f}ms",
            str(d['old_gc_count']), f"{d['avg_old_gc_ms']:.1f}ms" if d['old_gc_count'] > 0 else "0ms"
        ] for d in data['gc_by_node']]

        self.update_results(format_table(headers=['Node', 'Heap Used', 'Heap Max', 'Heap %', 'Old Gen Used', 'Old Gen %'], rows=memory_rows, title="Memory Utilization"))
        self.update_results(format_table(headers=['Node', 'Young GCs', 'Avg Young', 'Old GCs', 'Avg Old'], rows=gc_rows, title="Garbage Collection Performance"))

    def _render_circuit_breakers_report(self, data):
        self.update_results("🛡️ CIRCUIT BREAKER ANALYSIS:\n\n")
        total_tripped = data['summary']['total_tripped']
        self.update_results("   Circuit Breaker Summary:\n")
        if total_tripped > 0:
            self.update_results(f"   ⚠️🔥 Total Breaker Trips Detected: {total_tripped}\n")
            self.update_results("      Investigate immediately! Tripped breakers indicate memory pressure and can cause request failures.\n")
        else:
            self.update_results("   ✅ No circuit breaker trips detected. Memory management is stable.\n")
        self.update_results("\n")
        
        table_rows = [[
            d['node'], d['breaker'], f"{d['limit_bytes'] / 1024**2:.1f}MB",
            f"{d['estimated_bytes'] / 1024**2:.1f}MB", f"{d['usage_percent']:.1f}%", str(d['tripped_count'])
        ] for d in data['details']]
        
        if table_rows:
            headers = ['Node', 'Breaker', 'Limit', 'Estimated', 'Usage %', 'Tripped']
            self.update_results(format_table(headers=headers, rows=table_rows, title="Circuit Breaker Status by Node"))

    def _render_search_performance_report(self, data):
        self.update_results("🔍 SEARCH PERFORMANCE & CACHE ANALYSIS:\n\n")
        summary = data['summary']
        self.update_results("   Search & Cache Summary:\n")
        self.update_results(f"   📊 Average Query Latency: {summary['avg_query_latency_ms']:.2f}ms\n")
        self.update_results(f"   📊 Total Queries: {summary['total_queries']:,}\n")
        self.update_results(f"   📊 Query Cache Hit Rate: {summary['query_cache_hit_rate']:.1f}%\n")
        self.update_results(f"   📊 Request Cache Hit Rate: {summary['request_cache_hit_rate']:.1f}%\n")
        self.update_results(f"   📊 Field Data Memory: {summary['fielddata_memory_bytes'] / 1024**2:.1f}MB\n")

        if data['warnings']:
            for warning in data['warnings']: self.update_results(f"   ⚠️  {warning}\n")
        self.update_results("\n")

        cache_table_rows = [[
            idx['index'][:30], f"{idx['query_cache_hit_rate']:.1f}%", f"{idx['request_cache_hit_rate']:.1f}%",
            f"{idx['query_cache_memory_bytes'] / 1024**2:.1f}MB", f"{idx['fielddata_memory_bytes'] / 1024**2:.1f}MB"
        ] for idx in data['cache_by_index']]
        
        search_table_rows = [[
            node['node'], f"{node['query_total']:,}", f"{node['avg_query_ms']:.2f}ms",
            f"{node['fetch_total']:,}", f"{node['avg_fetch_ms']:.2f}ms", str(node['query_current'])
        ] for node in data['performance_by_node']]
        
        if cache_table_rows: self.update_results(format_table(headers=['Index', 'Query Cache Hit %', 'Request Cache Hit %', 'Query Cache Mem', 'Field Data Mem'], rows=cache_table_rows, title="Cache Performance by Index"))
        self.update_results(format_table(headers=['Node', 'Total Queries', 'Avg Query Time', 'Total Fetches', 'Avg Fetch Time', 'Current'], rows=search_table_rows, title="Search Performance by Node"))

    def _render_io_performance_report(self, data):
        self.update_results("💾 I/O & DISK PERFORMANCE ANALYSIS:\n\n")
        summary = data['summary']
        self.update_results("   I/O & Storage Summary:\n")
        self.update_results(f"   📊 Total Cluster Storage: {summary['total_cluster_storage_gb']:.1f}GB\n")
        self.update_results(f"   📊 Available Storage: {summary['available_storage_gb']:.1f}GB\n")
        self.update_results(f"   📊 Cluster Storage Usage: {summary['cluster_storage_usage_percent']:.1f}%\n")
        self.update_results(f"   📊 Total Disk Reads: {summary['total_disk_reads']:,}\n")
        self.update_results(f"   📊 Total Disk Writes: {summary['total_disk_writes']:,}\n")

        if data['warnings']:
            for warning in data['warnings']: self.update_results(f"   ⚠️  {warning}\n")
        self.update_results("\n")

        disk_table_rows = [[
            d['node'], f"{d['total_space_gb']:.1f}GB", f"{d['used_space_gb']:.1f}GB", f"{d['disk_used_percent']:.1f}%",
            f"{d['read_ops']:,}", f"{d['write_ops']:,}", f"{d['read_mb']:.1f}MB", f"{d['write_mb']:.1f}MB"
        ] for d in data['details_by_node']]
        
        disk_headers = ['Node', 'Total Space', 'Used Space', 'Usage %', 'Read Ops', 'Write Ops', 'Read Data', 'Write Data']
        self.update_results(format_table(headers=disk_headers, rows=disk_table_rows, title="Disk Usage and I/O Performance"))

    def _render_network_traffic_report(self, data):
        self.update_results("🌐 NETWORK TRAFFIC ANALYSIS:\n\n")
        summary = data['summary']
        self.update_results("   Network Summary:\n")
        self.update_results(f"   📊 Total Data Received (RX): {summary['total_rx_mb']:.1f}MB\n")
        self.update_results(f"   📊 Total Data Sent (TX): {summary['total_tx_mb']:.1f}MB\n\n")

        network_table_rows = [[
            d['node'], f"{d['rx_count']:,}", f"{d['tx_count']:,}",
            f"{d['rx_mb']:.1f}MB", f"{d['tx_mb']:.1f}MB", str(d['server_connections_open'])
        ] for d in data['details_by_node']]
        
        network_headers = ['Node', 'RX Count', 'TX Count', 'RX Data', 'TX Data', 'Connections']
        self.update_results(format_table(headers=network_headers, rows=network_table_rows, title="Network Transport Performance"))

    def _render_index_operations_report(self, data):
        self.update_results("📝 INDEX OPERATIONS ANALYSIS:\n\n")
        summary = data['summary']
        self.update_results("   Index Operations Summary:\n")
        self.update_results(f"   📊 Total Index Operations: {summary['index_total']:,}\n")
        self.update_results(f"   📊 Average Index Latency: {summary['avg_index_latency_ms']:.2f}ms\n")
        self.update_results(f"   📊 Total Refresh Operations: {summary['refresh_total']:,}\n")
        self.update_results(f"   📊 Average Refresh Latency: {summary['avg_refresh_latency_ms']:.2f}ms\n")
        self.update_results(f"   📊 Total Merge Operations: {summary['merge_total']:,}\n")
        if summary['merge_total'] > 0: self.update_results(f"   📊 Average Merge Latency: {summary['avg_merge_latency_ms']:.2f}ms\n")

        if data['warnings']:
            for warning in data['warnings']: self.update_results(f"   ⚠️  {warning}\n")
        self.update_results("\n")
        
        indexing_table_rows, operations_table_rows = [], []
        for name, d in data['details_by_index'].items():
            if d['index_total'] > 1000 or d['delete_total'] > 100 or d['index_current'] > 0:
                indexing_table_rows.append([name[:25], f"{d['index_total']:,}", f"{d['avg_index_ms']:.2f}ms", f"{d['delete_total']:,}", f"{d['avg_delete_ms']:.2f}ms", str(d['index_current'])])
            if d['refresh_total'] > 0 or d['merge_total'] > 0:
                operations_table_rows.append([name[:25], f"{d['refresh_total']:,}", f"{d['avg_refresh_ms']:.2f}ms", f"{d['merge_total']:,}", f"{d['avg_merge_ms']:.2f}ms", str(d['merge_current'])])

        if indexing_table_rows: self.update_results(format_table(headers=['Index', 'Index Ops', 'Avg Index Time', 'Delete Ops', 'Avg Delete Time', 'Current'], rows=indexing_table_rows, title="Indexing Performance by Index"))
        if operations_table_rows: self.update_results(format_table(headers=['Index', 'Refresh Ops', 'Avg Refresh', 'Merge Ops', 'Avg Merge', 'Current Merges'], rows=operations_table_rows, title="Index Operations Performance"))

    def _render_segments_and_allocation_report(self, data):
        self.update_results("🔧 SEGMENTS & ALLOCATION ANALYSIS:\n\n")
        summary = data['summary']
        self.update_results("   Segments & Allocation Summary:\n")
        self.update_results(f"   📊 Total Segments: {summary['total_segments']:,}\n")
        self.update_results(f"   📊 Total Segment Memory: {summary['total_segment_memory_bytes'] / 1024**2:.1f}MB\n")
        self.update_results(f"   📊 Total Shards (on data nodes): {summary['total_shards_on_data_nodes']}\n")
        self.update_results(f"   📊 Average Segments per Index: {summary['avg_segments_per_index']:.1f}\n")

        if data['warnings']:
            for warning in data['warnings']: self.update_results(f"   ⚠️  {warning}\n")
        self.update_results("\n")

        segment_table_rows = [[
            d['index'][:25], str(d['segment_count']), f"{d['memory_bytes'] / 1024**2:.1f}MB", f"{d['max_segment_size_bytes'] / 1024**2:.1f}MB"
        ] for d in data['segments_by_index']]
        
        if segment_table_rows: self.update_results(format_table(headers=['Index', 'Segments', 'Memory Usage', 'Largest Segment'], rows=sorted(segment_table_rows, key=lambda x: int(x[1]), reverse=True)[:20], title="Segment Analysis (Top 20 by Count)"))
        
        allocation_rows = [[
            d['node'], str(d['shards']), d['disk_used'], d['disk_available'], f"{d['disk_usage_percent']}%"
        ] for d in data['allocation_by_node']]
        
        self.update_results(format_table(headers=['Node', 'Shards', 'Disk Used', 'Disk Available', 'Usage %'], rows=allocation_rows, title="Shard Allocation by Node"))

    def _render_hot_threads_report(self, data):
        self.update_results("🔥 HOT THREADS ANALYSIS:\n\n")
        total_hot_threads = data['summary']['total_hot_threads']
        self.update_results("   Hot Threads Summary:\n")
        self.update_results(f"   📊 Total Hot Threads Detected: {total_hot_threads}\n")
        if not data['parsed_nodes']:
            self.update_results("   ✅ No significant hot threads detected.\n\n")
        else:
            self.update_results(f"   ⚠️  {data['warnings'][0]}\n\n")
            self.update_results("---HOT-THREADS-INTERACTIVE-START---\n")
            self.update_results(json.dumps(data['parsed_nodes']))
            self.update_results("\n---HOT-THREADS-INTERACTIVE-END---\n")

    def _render_shard_distribution_report(self, data):
        self.update_results("🔍 SHARD DISTRIBUTION ANALYSIS:\n\n")
        summary = data['summary']
        self.update_results("   Cluster Shard Summary:\n")
        self.update_results(f"   📈 Total Indices: {summary['total_indices']}\n")
        self.update_results(f"   📈 Total Primary Shards: {summary['total_primary_shards']}\n")
        self.update_results(f"   📈 Total Replica Shards: {summary['total_replica_shards']}\n")
        self.update_results(f"   📈 Total Documents: {summary['total_documents']:,}\n")
        
        if summary['unassigned_shards'] > 0:
            self.update_results(f"   ⚠️  Warning: {data['warnings'][0]}\n")
        self.update_results("\n")
            
    def _render_indexing_delta_report(self, data):
        self.update_results("📝 CURRENT INDEXING ACTIVITY (DELTA CHECK):\n")
        summary = data['summary']
        
        if not data['active_indices']:
            self.update_results(f"   ⚠️  {data['warnings'][0]}\n")
        else:
            self.update_results(f"   📈 ACTIVE INDICES (DELTA CHECK): {summary['active_index_count']}\n")
            for item in data['active_indices']:
                self.update_results(f"   ✅ Indexing detected in {item['index']} (+{item['new_operations']:,} ops)\n")
        self.update_results("\n")

    def open_in_browser(self):
        """Open analysis results in default web browser"""
        if not self.results_text.get(1.0, tk.END).strip():
            messagebox.showwarning("No Data", "No analysis results to display")
            return
        
        text_report = self.results_text.get(1.0, tk.END)
        html_content = html_report.generate_html_report(self.analysis_data, text_report)
        html_report.open_in_browser(html_content, self.root.after)

    def export_results_to_json(self):
        """Export analysis results to a structured JSON file."""
        if not self.analysis_data:
            messagebox.showwarning("No Data", "No analysis data to export.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Analysis Report as JSON"
        )
        
        if not filepath:
            return

        success, message = json_report.save_json_report(self.analysis_data, filepath)
        if success:
            messagebox.showinfo("Export Successful", message)
        else:
            messagebox.showerror("Export Error", message)
            
    def update_results(self, text):
        """Update results text widget (thread-safe)"""
        def update():
            self.results_text.insert(tk.END, text)
            self.results_text.see(tk.END)
            if self.results_text.get(1.0, tk.END).strip():
                self.browser_btn.config(state=tk.NORMAL)
                self.export_btn.config(state=tk.NORMAL)
        
        if self.root.winfo_exists():
            self.root.after(0, update)
    
    def clear_results(self):
        """Clear the results text widget"""
        self.results_text.delete(1.0, tk.END)
        self.browser_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.DISABLED)