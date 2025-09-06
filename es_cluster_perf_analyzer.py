import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import base64
import tempfile
import webbrowser
import os
import datetime
import time
import json
import argparse
import html
import re

try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False

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
        
        # Populate vars from CLI args if provided
        if self.cli_args:
            if self.cli_args.cloud_id:
                self.connection_type.set("cloud_id")
                self.cloud_id_var.set(self.cli_args.cloud_id)
            elif self.cli_args.url:
                self.connection_type.set("url")
                self.url_var.set(self.cli_args.url)

            if self.cli_args.api_key:
                self.auth_type.set("api_key")
                self.api_key_var.set(self.cli_args.api_key)
            elif self.cli_args.user and self.cli_args.password:
                self.auth_type.set("basic")
                self.username_var.set(self.cli_args.user)
                self.password_var.set(self.cli_args.password)

            if self.cli_args.no_ssl_verify:
                self.verify_ssl_var.set(False)
        
        # Check if elasticsearch library is available
        if not ES_AVAILABLE:
            messagebox.showerror("Missing Dependency",
                               "Please install the elasticsearch library:\npip install elasticsearch")
            self.root.destroy()
            return
            
        self.setup_ui()

        # Auto-run analysis if specified by CLI arg
        if self.cli_args and (self.cli_args.run or self.cli_args.export_json):
            # Hide the main window for a cleaner CLI experience
            self.root.withdraw()
            self.root.after(100, self.analyze_cluster)

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
    
    def _format_table(self, headers, rows, title=None):
        """Create a formatted ASCII table with headers and rows"""
        # Calculate column widths
        col_widths = {header: len(header) for header in headers}
        for row in rows:
            for header, value in zip(headers, row):
                col_widths[header] = max(col_widths[header], len(str(value)))
        
        # Build the table
        output = []
        if title:
            output.append(f"   {title}\n")
        
        # Header row
        header_line = "   "
        separator_line = "   "
        for header in headers:
            width = col_widths[header]
            header_line += f"{header:<{width}} | "
            separator_line += "-" * width + "-+-"
        output.append(header_line.rstrip())
        output.append(separator_line.rstrip())
        
        # Data rows
        for row in rows:
            data_line = "   "
            for header, value in zip(headers, row):
                width = col_widths[header]
                data_line += f"{str(value):<{width}} | "
            output.append(data_line.rstrip())
        
        return "\n".join(output) + "\n\n"

    def _parse_size_to_gb(self, size_str):
        """Parse size string (like '8gb', '2048mb') to GB"""
        try:
            size_str = size_str.lower().strip()
            if 'gb' in size_str:
                return float(size_str.replace('gb', ''))
            elif 'mb' in size_str:
                return float(size_str.replace('mb', '')) / 1024
            elif 'kb' in size_str:
                return float(size_str.replace('kb', '')) / (1024 * 1024)
            elif 'tb' in size_str:
                return float(size_str.replace('tb', '')) * 1024
            else:
                # Try to parse as number (assume MB)
                return float(size_str) / 1024
        except:
            return 0
    
    def setup_connection(self):
        """Setup Elasticsearch connection using official client"""
        try:
            es_kwargs = {
                'verify_certs': self.verify_ssl_var.get(),
                'request_timeout': 30,
                'retry_on_timeout': True,
                'max_retries': 3
            }

            # Add connection details
            if self.connection_type.get() == "cloud_id":
                cloud_id = self.cloud_id_var.get().strip()
                if not cloud_id: raise ValueError("Cloud ID is required")
                es_kwargs['cloud_id'] = cloud_id
            else:
                url = self.url_var.get().strip()
                if not url: raise ValueError("URL is required")
                es_kwargs['hosts'] = [url]

            # Add authentication details
            if self.auth_type.get() == "api_key":
                api_key_str = self.api_key_var.get().strip()
                if not api_key_str: raise ValueError("API Key is required")
                if ':' in api_key_str:
                    es_kwargs['api_key'] = tuple(api_key_str.split(':', 1))
                else:
                    es_kwargs['api_key'] = api_key_str # Assumes base64 encoded
            else:
                username = self.username_var.get().strip()
                password = self.password_var.get().strip()
                if not username: raise ValueError("Username is required")
                es_kwargs['basic_auth'] = (username, password)
            
            # Create Elasticsearch client
            self.es = Elasticsearch(**es_kwargs)
            
            if not self.es.ping():
                raise ConnectionError("Failed to connect to Elasticsearch. Please check credentials and network.")

            return True
            
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            return False
    
    def analyze_cluster(self):
        """Main analysis function"""
        # Run analysis in separate thread to prevent UI blocking
        threading.Thread(target=self._run_analysis, daemon=True).start()
    
    def _run_analysis(self):
        """Run the actual analysis (called in separate thread)"""
        try:
            # Initialize structured data store for this run
            self.analysis_data = {}
            # Setup connection
            if not self.setup_connection():
                return
            
            self.update_results("Connecting to Elasticsearch cluster...\n")
            
            # --- Section: Cluster Overview ---
            self.update_results("📋 CLUSTER OVERVIEW:\n\n")
            overview_data = {'info': {}, 'shard_health': {}, 'node_roles': {}, 'node_versions': {}, 'warnings': []}
            try:
                cluster_health = self.es.cluster.health()
                cluster_info = self.es.info()
                nodes_info = self.es.nodes.info()
                
                es_version = cluster_info.get('version', {})
                overview_data['info'] = {
                    'cluster_name': cluster_health.get('cluster_name', 'Unknown'),
                    'status': cluster_health.get('status', 'Unknown'),
                    'es_version': es_version.get('number', 'Unknown'),
                    'lucene_version': es_version.get('lucene_version', 'Unknown'),
                    'build_date': es_version.get('build_date', 'Unknown'),
                    'total_nodes': cluster_health.get('number_of_nodes', 0),
                    'data_nodes': cluster_health.get('number_of_data_nodes', 0),
                }
                
                overview_data['shard_health'] = {
                    'active_primary': cluster_health.get('active_primary_shards', 0),
                    'active_total': cluster_health.get('active_shards', 0),
                    'relocating': cluster_health.get('relocating_shards', 0),
                    'initializing': cluster_health.get('initializing_shards', 0),
                    'unassigned': cluster_health.get('unassigned_shards', 0),
                }
                if overview_data['shard_health']['unassigned'] > 0: overview_data['warnings'].append("Unassigned shards detected.")

                for node_id, node_data in nodes_info.get('nodes', {}).items():
                    for role in node_data.get('roles', []):
                        overview_data['node_roles'][role] = overview_data['node_roles'].get(role, 0) + 1
                    version = node_data.get('version', 'Unknown')
                    overview_data['node_versions'][version] = overview_data['node_versions'].get(version, 0) + 1
                if len(overview_data['node_versions']) > 1: overview_data['warnings'].append("Mixed cluster versions detected.")
                
                # Render text report from structured data
                status = overview_data['info']['status']
                status_icon = '🟢' if status == 'green' else '🟡' if status == 'yellow' else '🔴'
                overview_table_rows = [
                    ['Cluster Name', overview_data['info']['cluster_name']],
                    ['Status', f"{status_icon} {status.upper()}"],
                    ['Elasticsearch Version', overview_data['info']['es_version']],
                    ['Total Nodes', str(overview_data['info']['total_nodes'])],
                    ['Data Nodes', str(overview_data['info']['data_nodes'])]
                ]
                self.update_results(self._format_table(headers=['Property', 'Value'], rows=overview_table_rows, title="Cluster Information"))
                
                shard_health_rows = [
                    ['Active Primary', str(overview_data['shard_health']['active_primary'])],
                    ['Total Active', str(overview_data['shard_health']['active_total'])],
                    ['Relocating', str(overview_data['shard_health']['relocating'])],
                    ['Initializing', str(overview_data['shard_health']['initializing'])],
                    ['Unassigned', f"{'⚠️ ' if overview_data['shard_health']['unassigned'] > 0 else ''}{overview_data['shard_health']['unassigned']}"]
                ]
                self.update_results(self._format_table(headers=['Shard Type', 'Count'], rows=shard_health_rows, title="Shard Health"))

                if overview_data['node_roles']:
                    self.update_results(self._format_table(headers=['Node Role', 'Count'], rows=sorted(overview_data['node_roles'].items()), title="Node Roles"))
                
                for warning in overview_data['warnings']: self.update_results(f"   ⚠️  {warning}\n")
                self.update_results("\n")
                
            except Exception as e:
                overview_data['error'] = f"Could not retrieve cluster overview: {str(e)}"
                self.update_results(f"   ⚠️  {overview_data['error']}\n\n")
            self.analysis_data['cluster_overview'] = overview_data
            
            # --- Section: Pipeline Performance ---
            self.update_results("⚡ PIPELINE PERFORMANCE ANALYSIS:\n\n")
            pipeline_data = {'summary': {}, 'pipelines': {}, 'warnings': []}
            try:
                pipeline_stats = self.es.nodes.stats(metric=['ingest'])
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
                if total_ingest_failures > 0: pipeline_data['warnings'].append(f"{total_ingest_failures:,} failed ingest operations detected")

                # Render text report
                self.update_results("   Pipeline Summary:\n")
                self.update_results(f"   📈 Total Documents Processed: {pipeline_data['summary']['total_docs_processed']:,}\n")
                self.update_results(f"   📈 Average Processing Time: {pipeline_data['summary']['avg_processing_time_ms']:.2f}ms\n")
                if pipeline_data['summary']['total_failures'] > 0: self.update_results(f"   ⚠️  Total Failed Operations: {pipeline_data['summary']['total_failures']:,}\n")
                self.update_results("\n")

                active_pipelines = sorted([p for p in pipeline_data['pipelines'].items() if p[1]['count'] > 0], key=lambda x: x[1]['count'], reverse=True)
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
                    if failed_rows: self.update_results(self._format_table(headers=['Pipeline', 'Docs', 'Avg Time', 'Failed', 'Failure %'], rows=failed_rows, title="⚠️ Pipelines with Failures"))
                    if healthy_rows: self.update_results(self._format_table(headers=['Pipeline', 'Documents', 'Avg Time'], rows=healthy_rows, title="✅ Healthy Pipelines"))
                else: self.update_results("   No active pipelines found.\n\n")

            except Exception as e:
                pipeline_data['error'] = f"Could not retrieve pipeline stats: {str(e)}"
                self.update_results(f"   ⚠️  {pipeline_data['error']}\n\n")
            self.analysis_data['pipeline_performance'] = pipeline_data

            # --- Section: Node Resources ---
            self.update_results("📊 NODE RESOURCES:\n\n")
            node_resources_data = {'summary': {}, 'details_by_node': []}
            role_map = {
                'c': 'cold', 'd': 'data', 'f': 'frozen', 'h': 'hot',
                'i': 'ingest', 'l': 'ml', 'm': 'master', 'r': 'remote_cluster_client',
                's': 'content', 't': 'transform', 'v': 'voting_only', 'w': 'warm'
            }
            try:
                nodes_info = self.es.nodes.info(metric=['os', 'jvm'])
                nodes_stats = self.es.nodes.stats(metric=['os', 'process'])
                cat_nodes = self.es.cat.nodes(h='name,node.role,load_1m,heap.percent,heap.max,ram.max', format='json')

                cat_nodes_map = {n['name']: n for n in cat_nodes}
                total_vcpus = sum(d.get('os', {}).get('available_processors', 0) for d in nodes_info.get('nodes', {}).values())
                
                for node_id, node_data in nodes_info.get('nodes', {}).items():
                    node_name = node_data.get('name', 'Unknown')
                    cat_node_info = cat_nodes_map.get(node_name, {})
                    stats_node_info = nodes_stats.get('nodes', {}).get(node_id, {})
                    
                    cpu_usage = stats_node_info.get('process', {}).get('cpu', {}).get('percent', 0)
                    load = float(cat_node_info.get('load_1m', '0') or '0')
                    
                    roles_str = cat_node_info.get('node.role', 'N/A')
                    if roles_str and roles_str != 'N/A':
                        # The cat API returns a condensed string, e.g., "himr". Iterate through it.
                        full_roles = [role_map.get(role, role) for role in roles_str]
                        formatted_roles = ', '.join(sorted(full_roles))
                    else:
                        formatted_roles = 'N/A'

                    node_resources_data['details_by_node'].append({
                        'node': node_name,
                        'roles': formatted_roles,
                        'cpus': f"{node_data.get('os', {}).get('available_processors', 'N/A')} vCPUs",
                        'heap_size': cat_node_info.get('heap.max', 'N/A'),
                        'ram': cat_node_info.get('ram.max', 'N/A'),
                        'cpu_usage_percent': f"{cpu_usage}%",
                        'load_1m': f"{load:.2f}"
                    })

                node_resources_data['summary'] = {
                    'total_cluster_vcpus': total_vcpus,
                    'total_nodes': len(node_resources_data['details_by_node']),
                    'avg_cpu_usage_percent': sum(float(n['cpu_usage_percent'][:-1]) for n in node_resources_data['details_by_node']) / len(node_resources_data['details_by_node']) if node_resources_data['details_by_node'] else 0,
                    'avg_load_1m': sum(float(n['load_1m']) for n in node_resources_data['details_by_node']) / len(node_resources_data['details_by_node']) if node_resources_data['details_by_node'] else 0,
                }
                
                # Render text report
                self.update_results("   Resource Summary:\n")
                self.update_results(f"   📈 Total Cluster vCPUs: {node_resources_data['summary']['total_cluster_vcpus']}\n")
                self.update_results(f"   📈 Total Nodes: {node_resources_data['summary']['total_nodes']}\n")
                self.update_results(f"   📈 Average CPU Usage: {node_resources_data['summary']['avg_cpu_usage_percent']:.1f}%\n")
                self.update_results(f"   📈 Average Load: {node_resources_data['summary']['avg_load_1m']:.2f}\n\n")
                
                table_rows = [[
                    d['node'], d['roles'], d['cpus'], d['heap_size'],
                    d['ram'], d['cpu_usage_percent'], d['load_1m']
                ] for d in node_resources_data['details_by_node']]
                self.update_results(self._format_table(headers=['Node Name', 'Roles', 'CPUs', 'Heap Size', 'RAM', 'CPU Usage', 'Load'], rows=table_rows, title="Node Resources"))

            except Exception as e:
                node_resources_data['error'] = f"Could not retrieve node resources: {str(e)}"
                self.update_results(f"   ⚠️  {node_resources_data['error']}\n\n")
            self.analysis_data['node_resources'] = node_resources_data
            
            # 3. Comprehensive Thread Pool Analysis
            self._analyze_all_thread_pools()
            
            # 4. Memory and GC Analysis
            self._analyze_memory_and_gc()
            
            # 5. Circuit Breaker Analysis
            self._analyze_circuit_breakers()
            
            # 6. Search Performance Analysis
            self._analyze_search_performance()
            
            # 7. I/O Performance Analysis
            self._analyze_io_performance()
            
            # 8. Network Traffic Analysis
            self._analyze_network_traffic()
            
            # 9. Index Operations Analysis
            self._analyze_index_operations()
            
            # 8. Segments and Allocation Analysis
            self._analyze_segments_and_allocation()
            
            # 9. Hot Threads Analysis
            self._analyze_hot_threads()
            
            # 10. Shard Distribution Analysis
            self._analyze_shard_distribution()
            
            # 11. Indexing Delta Check
            self._analyze_indexing_delta()
            
            # Add completion message to overview section
            self.update_results("\n✅ Connected to cluster: Cluster Analysis Summary\n")
            self.update_results(f"   Total Analyzed Sections: 5\n")
            self.update_results("   Analysis Status: Complete\n\n")
            
            # If running from CLI, open browser and exit
            if self.cli_args and self.cli_args.run:
                self.update_results("   Analysis complete. Opening report in browser...\n")
                self.open_in_browser()
                # Schedule closing the app after a delay to ensure browser opens
                self.root.after(3000, self.root.destroy)
            elif self.cli_args and self.cli_args.export_json:
                self.update_results("   Analysis complete. Exporting to JSON...\n")
                self.export_results_to_json(filepath=self.cli_args.export_json)
                self.root.after(100, self.root.destroy)

        except Exception as e:
            error_msg = str(e)
            self.update_results(f"❌ Error during analysis: {error_msg}\n")
            messagebox.showerror("Analysis Error", error_msg)
            
        

    def _analyze_all_thread_pools(self):
        """Comprehensive thread pool analysis, storing structured data."""
        self.update_results("🧵 COMPREHENSIVE THREAD POOL ANALYSIS:\n\n")
        
        section_data = {
            'summary': {},
            'pools': {},
            'warnings': []
        }

        try:
            thread_pool_cat = self.es.cat.thread_pool(h='node_name,name,active,queue,rejected,size,max', format='json')
            
            # Process data into structured format first
            for pool_entry in thread_pool_cat:
                pool_name = pool_entry.get('name')
                if pool_name not in section_data['pools']:
                    section_data['pools'][pool_name] = {
                        'summary': {'active': 0, 'queue': 0, 'rejected': 0, 'available': 0},
                        'details': []
                    }
                
                try:
                    active = int(pool_entry.get('active', 0))
                    queue = int(pool_entry.get('queue', 0))
                    rejected = int(pool_entry.get('rejected', 0))
                    
                    # Handle 'size' which might not be a simple integer
                    size_str = pool_entry.get('size', '0')
                    size_for_calc = int(size_str) if str(size_str).isdigit() else 0
                    
                except (ValueError, TypeError):
                    continue # Skip entries with non-numeric data

                section_data['pools'][pool_name]['summary']['active'] += active
                section_data['pools'][pool_name]['summary']['queue'] += queue
                section_data['pools'][pool_name]['summary']['rejected'] += rejected
                section_data['pools'][pool_name]['summary']['available'] += size_for_calc
                section_data['pools'][pool_name]['details'].append({
                    'node': pool_entry.get('node_name', 'Unknown'),
                    'active': active,
                    'queue': queue,
                    'rejected': rejected,
                    'size': pool_entry.get('size', 'N/A')
                })

            # Calculate overall summary from processed data
            overall_totals = {'active': 0, 'queue': 0, 'rejected': 0, 'available': 0}
            for pool_name, data in section_data['pools'].items():
                for key in overall_totals:
                    overall_totals[key] += data['summary'][key]
            
            overall_utilization = (overall_totals['active'] / overall_totals['available'] * 100) if overall_totals['available'] > 0 else 0
            section_data['summary'] = {**overall_totals, 'utilization_percent': overall_utilization}

            # Generate and display text report from structured data
            self.update_results("   Thread Pool Health Summary:\n")
            self.update_results(f"   📊 Total Active Threads: {overall_totals['active']}\n")
            self.update_results(f"   📊 Total Queued Operations: {overall_totals['queue']}\n")
            self.update_results(f"   📊 Total Available Threads: {overall_totals['available']}\n")
            if overall_totals['rejected'] > 0:
                self.update_results(f"   ⚠️  Total Rejections: {overall_totals['rejected']}\n")
            
            health_status = "🟢 Good" if overall_utilization < 50 else "🟡 Moderate" if overall_utilization < 80 else "🔴 High"
            self.update_results(f"   {health_status} Overall Thread Pool Utilization: {overall_utilization:.1f}%\n\n")

            # Display per-pool details
            pool_types_of_interest = ['search', 'get', 'bulk', 'write', 'management', 'flush', 'refresh', 'merge']
            for pool_type in pool_types_of_interest:
                if pool_type in section_data['pools']:
                    pool_data = section_data['pools'][pool_type]
                    pool_totals = pool_data['summary']
                    
                    if pool_totals['active'] > 0 or pool_totals['queue'] > 0 or pool_totals['rejected'] > 0:
                        table_rows = [[
                            d['node'], str(d['active']), str(d['queue']), str(d['size']), str(d['rejected'])
                        ] for d in pool_data['details']]
                        
                        self.update_results(self._format_table(
                            headers=['Node', 'Active', 'Queue', 'Size', 'Rejected'],
                            rows=sorted(table_rows, key=lambda x: x[0]),
                            title=f"{pool_type.title()} Thread Pool"
                        ))
                        
                        if pool_totals['available'] > 0:
                            utilization = (pool_totals['active'] / pool_totals['available']) * 100
                            if utilization > 80:
                                section_data['warnings'].append(f"High {pool_type} thread utilization: {utilization:.1f}%")
                        if pool_totals['queue'] > 50:
                            section_data['warnings'].append(f"High {pool_type} queue length: {pool_totals['queue']}")
                        if pool_totals['rejected'] > 0:
                            section_data['warnings'].append(f"{pool_type.title()} rejections: {pool_totals['rejected']}")
                        
                        # Display warnings immediately under the table
                        for warning in section_data['warnings']:
                            if pool_type in warning.lower(): self.update_results(f"   ⚠️  {warning}\n")
                        self.update_results("\n")
            
        except Exception as e:
            error_msg = f"Could not retrieve thread pool info: {str(e)}"
            self.update_results(f"   ⚠️  {error_msg}\n\n")
            section_data['error'] = error_msg
        
        self.analysis_data['thread_pools'] = section_data
    
    def _analyze_memory_and_gc(self):
        """Memory and garbage collection analysis, storing structured data."""
        self.update_results("🧠 MEMORY & GARBAGE COLLECTION ANALYSIS:\n\n")
        
        section_data = {
            'summary': {},
            'memory_by_node': [],
            'gc_by_node': [],
            'warnings': []
        }

        try:
            jvm_stats = self.es.nodes.stats(metric=['jvm'])
            
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
                
                if heap_used_percent > 85: section_data['warnings'].append(f"High heap usage on {node_name}: {heap_used_percent:.1f}%")
                if old_gen_percent > 80: section_data['warnings'].append(f"High old generation usage on {node_name}: {old_gen_percent:.1f}%")

            # Calculate and store summary
            total_gc_time = gc_totals['young_time_ms'] + gc_totals['old_time_ms']
            total_collections = gc_totals['young_collections'] + gc_totals['old_collections']
            avg_gc_time = total_gc_time / total_collections if total_collections > 0 else 0
            
            section_data['summary'] = {
                'total_gc_collections': total_collections,
                'avg_gc_time_ms': avg_gc_time,
                'total_gc_time_s': total_gc_time / 1000
            }
            if avg_gc_time > 100: section_data['warnings'].append("High average GC pause times detected")
            if gc_totals['old_collections'] > gc_totals['young_collections'] * 0.1: section_data['warnings'].append("Frequent old generation GCs detected")
            
            # Generate and display text report from structured data
            self.update_results("   GC Performance Summary:\n")
            self.update_results(f"   📊 Total GC Collections: {total_collections:,}\n")
            self.update_results(f"   📊 Average GC Time: {avg_gc_time:.2f}ms\n")
            self.update_results(f"   📊 Total GC Time: {total_gc_time/1000:.1f}s\n")
            
            # Display summary-level warnings
            if avg_gc_time > 100: self.update_results("   ⚠️  High average GC pause times detected\n")
            if gc_totals['old_collections'] > gc_totals['young_collections'] * 0.1: self.update_results("   ⚠️  Frequent old generation GCs detected\n")
            self.update_results("\n")

            if section_data['warnings']:
                for warning in section_data['warnings']: self.update_results(f"   ⚠️  {warning}\n")
                self.update_results("\n")
            
            # Generate table rows from structured data
            memory_rows = [[
                d['node'], f"{d['heap_used_bytes'] / 1024**2:.0f}MB", f"{d['heap_max_bytes'] / 1024**2:.0f}MB",
                f"{d['heap_used_percent']:.1f}%", f"{d['old_gen_used_bytes'] / 1024**2:.0f}MB", f"{d['old_gen_used_percent']:.1f}%"
            ] for d in section_data['memory_by_node']]
            
            gc_rows = [[
                d['node'], str(d['young_gc_count']), f"{d['avg_young_gc_ms']:.1f}ms",
                str(d['old_gc_count']), f"{d['avg_old_gc_ms']:.1f}ms" if d['old_gc_count'] > 0 else "0ms"
            ] for d in section_data['gc_by_node']]

            self.update_results(self._format_table(headers=['Node', 'Heap Used', 'Heap Max', 'Heap %', 'Old Gen Used', 'Old Gen %'], rows=memory_rows, title="Memory Utilization"))
            self.update_results(self._format_table(headers=['Node', 'Young GCs', 'Avg Young', 'Old GCs', 'Avg Old'], rows=gc_rows, title="Garbage Collection Performance"))
            
        except Exception as e:
            error_msg = f"Could not retrieve memory/GC info: {str(e)}"
            self.update_results(f"   ⚠️  {error_msg}\n\n")
            section_data['error'] = error_msg
        
        self.analysis_data['memory_and_gc'] = section_data
    
    def _analyze_search_performance(self):
        """Search performance and cache analysis, storing structured data."""
        self.update_results("🔍 SEARCH PERFORMANCE & CACHE ANALYSIS:\n\n")
        
        section_data = {
            'summary': {},
            'cache_by_index': [],
            'performance_by_node': [],
            'warnings': []
        }

        try:
            indices_stats = self.es.indices.stats(metric=['search', 'query_cache', 'fielddata', 'request_cache'])
            nodes_stats = self.es.nodes.stats(metric=['indices'])
            
            total_cache_stats = {'query_cache_hits': 0, 'query_cache_misses': 0, 'fielddata_memory_bytes': 0, 'request_cache_hits': 0, 'request_cache_misses': 0}
            total_search_stats = {'query_total': 0, 'query_time_ms': 0, 'fetch_total': 0, 'fetch_time_ms': 0}
            
            # Process cache stats per index
            for index_name, index_data in indices_stats.get('indices', {}).items():
                total = index_data.get('total', {})
                qc = total.get('query_cache', {}); rc = total.get('request_cache', {})
                qc_hits, qc_misses = qc.get('hit_count', 0), qc.get('miss_count', 0)
                rc_hits, rc_misses = rc.get('hit_count', 0), rc.get('miss_count', 0)
                fd_mem_bytes = total.get('fielddata', {}).get('memory_size_in_bytes', 0)
                
                total_cache_stats['query_cache_hits'] += qc_hits
                total_cache_stats['query_cache_misses'] += qc_misses
                total_cache_stats['request_cache_hits'] += rc_hits
                total_cache_stats['request_cache_misses'] += rc_misses
                total_cache_stats['fielddata_memory_bytes'] += fd_mem_bytes

                qc_total, rc_total = qc_hits + qc_misses, rc_hits + rc_misses
                if qc_total > 1000 or rc_total > 1000 or fd_mem_bytes > 10 * 1024 * 1024:
                    section_data['cache_by_index'].append({
                        'index': index_name,
                        'query_cache_hit_rate': (qc_hits / qc_total * 100) if qc_total > 0 else 0,
                        'request_cache_hit_rate': (rc_hits / rc_total * 100) if rc_total > 0 else 0,
                        'query_cache_memory_bytes': qc.get('memory_size_in_bytes', 0),
                        'fielddata_memory_bytes': fd_mem_bytes
                    })

            # Process search performance per node
            for node_id, node_data in nodes_stats.get('nodes', {}).items():
                search = node_data.get('indices', {}).get('search', {})
                query_total, query_time = search.get('query_total', 0), search.get('query_time_in_millis', 0)
                fetch_total, fetch_time = search.get('fetch_total', 0), search.get('fetch_time_in_millis', 0)
                
                total_search_stats['query_total'] += query_total
                total_search_stats['query_time_ms'] += query_time
                total_search_stats['fetch_total'] += fetch_total
                total_search_stats['fetch_time_ms'] += fetch_time

                avg_query_ms = query_time / query_total if query_total > 0 else 0
                avg_fetch_ms = fetch_time / fetch_total if fetch_total > 0 else 0
                
                section_data['performance_by_node'].append({
                    'node': node_data.get('name', 'Unknown'),
                    'query_total': query_total,
                    'avg_query_ms': avg_query_ms,
                    'fetch_total': fetch_total,
                    'avg_fetch_ms': avg_fetch_ms,
                    'query_current': search.get('query_current', 0)
                })
                
                if avg_query_ms > 100: section_data['warnings'].append(f"High query latency on {node_data.get('name', 'Unknown')}: {avg_query_ms:.2f}ms")
                if search.get('query_current', 0) > 10: section_data['warnings'].append(f"High concurrent queries on {node_data.get('name', 'Unknown')}: {search.get('query_current', 0)}")

            # Calculate and store summary
            total_qc = total_cache_stats['query_cache_hits'] + total_cache_stats['query_cache_misses']
            total_rc = total_cache_stats['request_cache_hits'] + total_cache_stats['request_cache_misses']
            qc_hit_rate = (total_cache_stats['query_cache_hits'] / total_qc * 100) if total_qc > 0 else 0
            rc_hit_rate = (total_cache_stats['request_cache_hits'] / total_rc * 100) if total_rc > 0 else 0
            avg_cluster_query = total_search_stats['query_time_ms'] / total_search_stats['query_total'] if total_search_stats['query_total'] > 0 else 0
            
            section_data['summary'] = {
                'avg_query_latency_ms': avg_cluster_query,
                'total_queries': total_search_stats['query_total'],
                'query_cache_hit_rate': qc_hit_rate,
                'request_cache_hit_rate': rc_hit_rate,
                'fielddata_memory_bytes': total_cache_stats['fielddata_memory_bytes']
            }

            # Generate and display text report from structured data
            self.update_results("   Search & Cache Summary:\n")
            self.update_results(f"   📊 Average Query Latency: {section_data['summary']['avg_query_latency_ms']:.2f}ms\n")
            self.update_results(f"   📊 Total Queries: {section_data['summary']['total_queries']:,}\n")
            self.update_results(f"   📊 Query Cache Hit Rate: {section_data['summary']['query_cache_hit_rate']:.1f}%\n")
            self.update_results(f"   📊 Request Cache Hit Rate: {section_data['summary']['request_cache_hit_rate']:.1f}%\n")
            self.update_results(f"   📊 Field Data Memory: {section_data['summary']['fielddata_memory_bytes'] / 1024**2:.1f}MB\n")

            if qc_hit_rate < 50 and total_qc > 1000: section_data['warnings'].append("Low query cache hit rate - consider query optimization")
            if rc_hit_rate < 80 and total_rc > 1000: section_data['warnings'].append("Low request cache hit rate - check request patterns")
            if avg_cluster_query > 50: section_data['warnings'].append("High average query latency detected")
            
            if section_data['warnings']:
                for warning in section_data['warnings']: self.update_results(f"   ⚠️  {warning}\n")
            self.update_results("\n")

            cache_table_rows = [[
                idx['index'][:30], f"{idx['query_cache_hit_rate']:.1f}%", f"{idx['request_cache_hit_rate']:.1f}%",
                f"{idx['query_cache_memory_bytes'] / 1024**2:.1f}MB", f"{idx['fielddata_memory_bytes'] / 1024**2:.1f}MB"
            ] for idx in section_data['cache_by_index']]
            
            search_table_rows = [[
                node['node'], f"{node['query_total']:,}", f"{node['avg_query_ms']:.2f}ms",
                f"{node['fetch_total']:,}", f"{node['avg_fetch_ms']:.2f}ms", str(node['query_current'])
            ] for node in section_data['performance_by_node']]
            
            if cache_table_rows: self.update_results(self._format_table(headers=['Index', 'Query Cache Hit %', 'Request Cache Hit %', 'Query Cache Mem', 'Field Data Mem'], rows=cache_table_rows, title="Cache Performance by Index"))
            self.update_results(self._format_table(headers=['Node', 'Total Queries', 'Avg Query Time', 'Total Fetches', 'Avg Fetch Time', 'Current'], rows=search_table_rows, title="Search Performance by Node"))

        except Exception as e:
            error_msg = f"Could not retrieve search performance info: {str(e)}"
            self.update_results(f"   ⚠️  {error_msg}\n\n")
            section_data['error'] = error_msg

        self.analysis_data['search_performance'] = section_data
    
    def _analyze_io_performance(self):
        """I/O and disk performance analysis, storing structured data."""
        self.update_results("💾 I/O & DISK PERFORMANCE ANALYSIS:\n\n")
        
        section_data = {'summary': {}, 'details_by_node': [], 'warnings': []}

        try:
            fs_stats = self.es.nodes.stats(metric=['fs'])
            
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
                
                if disk_used_percent > 85: section_data['warnings'].append(f"High disk usage on {node_name}: {disk_used_percent:.1f}%")
                if available_space_gb < 10: section_data['warnings'].append(f"Low disk space on {node_name}: {available_space_gb:.1f}GB remaining")

            # Calculate and store summary
            cluster_used_percent = ((total_disk_stats['total_space_gb'] - total_disk_stats['available_space_gb']) / total_disk_stats['total_space_gb'] * 100) if total_disk_stats['total_space_gb'] > 0 else 0
            section_data['summary'] = {
                'total_cluster_storage_gb': total_disk_stats['total_space_gb'],
                'available_storage_gb': total_disk_stats['available_space_gb'],
                'cluster_storage_usage_percent': cluster_used_percent,
                'total_disk_reads': total_disk_stats['total_reads'],
                'total_disk_writes': total_disk_stats['total_writes']
            }
            if cluster_used_percent > 80: section_data['warnings'].append("High cluster storage utilization")
            if total_disk_stats['available_space_gb'] < 50: section_data['warnings'].append("Low available storage space")

            # Generate and display text report from structured data
            self.update_results("   I/O & Storage Summary:\n")
            self.update_results(f"   📊 Total Cluster Storage: {section_data['summary']['total_cluster_storage_gb']:.1f}GB\n")
            self.update_results(f"   📊 Available Storage: {section_data['summary']['available_storage_gb']:.1f}GB\n")
            self.update_results(f"   📊 Cluster Storage Usage: {section_data['summary']['cluster_storage_usage_percent']:.1f}%\n")
            self.update_results(f"   📊 Total Disk Reads: {section_data['summary']['total_disk_reads']:,}\n")
            self.update_results(f"   📊 Total Disk Writes: {section_data['summary']['total_disk_writes']:,}\n")
            if section_data['summary']['cluster_storage_usage_percent'] > 80: self.update_results("   ⚠️  High cluster storage utilization\n")
            if section_data['summary']['available_storage_gb'] < 50: self.update_results("   ⚠️  Low available storage space\n")
            self.update_results("\n")

            if section_data['warnings']:
                for warning in section_data['warnings']: self.update_results(f"   ⚠️  {warning}\n")
                self.update_results("\n")

            disk_table_rows = [[
                d['node'], f"{d['total_space_gb']:.1f}GB", f"{d['used_space_gb']:.1f}GB", f"{d['disk_used_percent']:.1f}%",
                f"{d['read_ops']:,}", f"{d['write_ops']:,}", f"{d['read_mb']:.1f}MB", f"{d['write_mb']:.1f}MB"
            ] for d in section_data['details_by_node']]
            
            disk_headers = ['Node', 'Total Space', 'Used Space', 'Usage %', 'Read Ops', 'Write Ops', 'Read Data', 'Write Data']
            self.update_results(self._format_table(headers=disk_headers, rows=disk_table_rows, title="Disk Usage and I/O Performance"))
            
        except Exception as e:
            error_msg = f"Could not retrieve I/O performance info: {str(e)}"
            self.update_results(f"   ⚠️  {error_msg}\n\n")
            section_data['error'] = error_msg
        
        self.analysis_data['io_performance'] = section_data

    def _analyze_index_operations(self):
        """Index operation performance analysis, storing structured data."""
        self.update_results("📝 INDEX OPERATIONS ANALYSIS:\n\n")
        
        section_data = {'summary': {}, 'details_by_index': {}, 'warnings': []}

        try:
            indices_stats = self.es.indices.stats(metric=['indexing', 'refresh', 'merge', 'flush'])
            
            totals = {'index_total': 0, 'index_time_ms': 0, 'delete_total': 0, 'delete_time_ms': 0, 'refresh_total': 0, 'refresh_time_ms': 0, 'merge_total': 0, 'merge_time_ms': 0}

            for index_name, index_data in indices_stats.get('indices', {}).items():
                total = index_data.get('total', {})
                indexing = total.get('indexing', {}); refresh = total.get('refresh', {}); merge = total.get('merge', {})
                
                index_total, index_time = indexing.get('index_total', 0), indexing.get('index_time_in_millis', 0)
                delete_total, delete_time = indexing.get('delete_total', 0), indexing.get('delete_time_in_millis', 0)
                refresh_total, refresh_time = refresh.get('total', 0), refresh.get('total_time_in_millis', 0)
                merge_total, merge_time = merge.get('total', 0), merge.get('total_time_in_millis', 0)

                for key, val in [('index_total', index_total), ('index_time_ms', index_time), ('delete_total', delete_total), ('delete_time_ms', delete_time), ('refresh_total', refresh_total), ('refresh_time_ms', refresh_time), ('merge_total', merge_total), ('merge_time_ms', merge_time)]:
                    totals[key] += val

                avg_index = index_time / index_total if index_total > 0 else 0
                avg_delete = delete_time / delete_total if delete_total > 0 else 0
                avg_refresh = refresh_time / refresh_total if refresh_total > 0 else 0
                avg_merge = merge_time / merge_total if merge_total > 0 else 0
                
                section_data['details_by_index'][index_name] = {
                    'index_total': index_total, 'avg_index_ms': avg_index, 'index_current': indexing.get('index_current', 0),
                    'delete_total': delete_total, 'avg_delete_ms': avg_delete,
                    'refresh_total': refresh_total, 'avg_refresh_ms': avg_refresh,
                    'merge_total': merge_total, 'avg_merge_ms': avg_merge, 'merge_current': merge.get('current', 0)
                }
                
                if avg_index > 50: section_data['warnings'].append(f"High indexing latency in {index_name[:20]}: {avg_index:.2f}ms")
                if merge.get('current', 0) > 2: section_data['warnings'].append(f"High concurrent merges in {index_name[:20]}: {merge.get('current', 0)}")
                if avg_merge > 1000: section_data['warnings'].append(f"Slow merge operations in {index_name[:20]}: {avg_merge:.2f}ms")

            # Calculate and store summary
            avg_index_latency = totals['index_time_ms'] / totals['index_total'] if totals['index_total'] > 0 else 0
            avg_refresh_latency = totals['refresh_time_ms'] / totals['refresh_total'] if totals['refresh_total'] > 0 else 0
            avg_merge_latency = totals['merge_time_ms'] / totals['merge_total'] if totals['merge_total'] > 0 else 0
            
            section_data['summary'] = {**totals, 'avg_index_latency_ms': avg_index_latency, 'avg_refresh_latency_ms': avg_refresh_latency, 'avg_merge_latency_ms': avg_merge_latency}
            if avg_index_latency > 20: section_data['warnings'].append("High average indexing latency - consider optimizing mapping or bulk sizes")
            if avg_refresh_latency > 100: section_data['warnings'].append("Slow refresh operations - consider adjusting refresh intervals")
            if avg_merge_latency > 500: section_data['warnings'].append("Slow merge operations - check segment optimization settings")

            # Generate and display text report from structured data
            self.update_results("   Index Operations Summary:\n")
            self.update_results(f"   📊 Total Index Operations: {section_data['summary']['index_total']:,}\n")
            self.update_results(f"   📊 Average Index Latency: {section_data['summary']['avg_index_latency_ms']:.2f}ms\n")
            self.update_results(f"   📊 Total Refresh Operations: {section_data['summary']['refresh_total']:,}\n")
            self.update_results(f"   📊 Average Refresh Latency: {section_data['summary']['avg_refresh_latency_ms']:.2f}ms\n")
            self.update_results(f"   📊 Total Merge Operations: {section_data['summary']['merge_total']:,}\n")
            if section_data['summary']['merge_total'] > 0: self.update_results(f"   📊 Average Merge Latency: {section_data['summary']['avg_merge_latency_ms']:.2f}ms\n")
            
            # Display summary-level warnings
            if section_data['summary']['avg_index_latency_ms'] > 20: self.update_results("   ⚠️  High average indexing latency - consider optimizing mapping or bulk sizes\n")
            if section_data['summary']['avg_refresh_latency_ms'] > 100: self.update_results("   ⚠️  Slow refresh operations - consider adjusting refresh intervals\n")
            if section_data['summary']['avg_merge_latency_ms'] > 500: self.update_results("   ⚠️  Slow merge operations - check segment optimization settings\n")
            self.update_results("\n")

            if section_data['warnings']:
                for warning in section_data['warnings']: self.update_results(f"   ⚠️  {warning}\n")
                self.update_results("\n")
            
            # Generate table rows from structured data
            indexing_table_rows, operations_table_rows = [], []
            for name, d in section_data['details_by_index'].items():
                if d['index_total'] > 1000 or d['delete_total'] > 100 or d['index_current'] > 0:
                    indexing_table_rows.append([name[:25], f"{d['index_total']:,}", f"{d['avg_index_ms']:.2f}ms", f"{d['delete_total']:,}", f"{d['avg_delete_ms']:.2f}ms", str(d['index_current'])])
                if d['refresh_total'] > 0 or d['merge_total'] > 0:
                    operations_table_rows.append([name[:25], f"{d['refresh_total']:,}", f"{d['avg_refresh_ms']:.2f}ms", f"{d['merge_total']:,}", f"{d['avg_merge_ms']:.2f}ms", str(d['merge_current'])])

            if indexing_table_rows: self.update_results(self._format_table(headers=['Index', 'Index Ops', 'Avg Index Time', 'Delete Ops', 'Avg Delete Time', 'Current'], rows=indexing_table_rows, title="Indexing Performance by Index"))
            if operations_table_rows: self.update_results(self._format_table(headers=['Index', 'Refresh Ops', 'Avg Refresh', 'Merge Ops', 'Avg Merge', 'Current Merges'], rows=operations_table_rows, title="Index Operations Performance"))

        except Exception as e:
            error_msg = f"Could not retrieve index operations info: {str(e)}"
            self.update_results(f"   ⚠️  {error_msg}\n\n")
            section_data['error'] = error_msg
            
        self.analysis_data['index_operations'] = section_data

    def _analyze_segments_and_allocation(self):
        """Segment and allocation analysis, storing structured data."""
        self.update_results("🔧 SEGMENTS & ALLOCATION ANALYSIS:\n\n")
        
        section_data = {'summary': {}, 'segments_by_index': [], 'allocation_by_node': [], 'warnings': []}

        try:
            segments_stats = self.es.indices.segments()
            allocation_data = self.es.cat.allocation(format='json', h='node,shards,disk.used,disk.avail,disk.percent')

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
                    if index_segments > 100: section_data['warnings'].append(f"High segment count in {index_name[:20]}: {index_segments}")
                    if max_segment_size > 5 * 1024**3: section_data['warnings'].append(f"Large segment (>5GB) in {index_name[:20]}")

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
                    
                    if shards_count > 1000: section_data['warnings'].append(f"High shard count on {node_data.get('node', 'Unknown')}: {shards_count}")
                    if disk_percent > 85: section_data['warnings'].append(f"High disk usage on {node_data.get('node', 'Unknown')}")
                except (ValueError, TypeError):
                    pass

            # Calculate and store summary
            num_indices = len(section_data['segments_by_index'])
            avg_segments = total_segments / num_indices if num_indices > 0 else 0
            section_data['summary'] = {
                'total_segments': total_segments, 'total_segment_memory_bytes': total_segment_memory,
                'total_shards_on_data_nodes': total_shards, 'avg_segments_per_index': avg_segments
            }
            if avg_segments > 50: section_data['warnings'].append("High average segments per index - consider force merge operations")
            if total_segment_memory > 1024**3: section_data['warnings'].append("High segment memory usage (>1GB) - monitor heap pressure")

            # Generate and display text report from structured data
            self.update_results("   Segments & Allocation Summary:\n")
            self.update_results(f"   📊 Total Segments: {section_data['summary']['total_segments']:,}\n")
            self.update_results(f"   📊 Total Segment Memory: {section_data['summary']['total_segment_memory_bytes'] / 1024**2:.1f}MB\n")
            self.update_results(f"   📊 Total Shards (on data nodes): {section_data['summary']['total_shards_on_data_nodes']}\n")
            self.update_results(f"   📊 Average Segments per Index: {section_data['summary']['avg_segments_per_index']:.1f}\n")
            if section_data['summary']['avg_segments_per_index'] > 50: self.update_results("   ⚠️  High average segments per index - consider force merge operations\n")
            if section_data['summary']['total_segment_memory_bytes'] > 1024**3: self.update_results("   ⚠️  High segment memory usage (>1GB) - monitor heap pressure\n")
            self.update_results("\n")

            if section_data['warnings']:
                for warning in section_data['warnings']: self.update_results(f"   ⚠️  {warning}\n")
                self.update_results("\n")

            segment_table_rows = [[
                d['index'][:25], str(d['segment_count']), f"{d['memory_bytes'] / 1024**2:.1f}MB", f"{d['max_segment_size_bytes'] / 1024**2:.1f}MB"
            ] for d in section_data['segments_by_index']]
            
            if segment_table_rows: self.update_results(self._format_table(headers=['Index', 'Segments', 'Memory Usage', 'Largest Segment'], rows=sorted(segment_table_rows, key=lambda x: int(x[1]), reverse=True)[:20], title="Segment Analysis (Top 20 by Count)"))
            
            allocation_rows = [[
                d['node'], str(d['shards']), d['disk_used'], d['disk_available'], f"{d['disk_usage_percent']}%"
            ] for d in section_data['allocation_by_node']]
            
            self.update_results(self._format_table(headers=['Node', 'Shards', 'Disk Used', 'Disk Available', 'Usage %'], rows=allocation_rows, title="Shard Allocation by Node"))

        except Exception as e:
            error_msg = f"Could not retrieve segments/allocation info: {str(e)}"
            self.update_results(f"   ⚠️  {error_msg}\n\n")
            section_data['error'] = error_msg
            
        self.analysis_data['segments_and_allocation'] = section_data

    def _analyze_hot_threads(self):
        """Hot threads analysis with structured parsing for rich HTML display."""
        self.update_results("🔥 HOT THREADS ANALYSIS:\n\n")
        section_data = {'summary': {}, 'raw_output': '', 'warnings': [], 'parsed_nodes': []}

        try:
            hot_threads_response = self.es.nodes.hot_threads(threads=10, interval='500ms', snapshots=3, ignore_idle_threads=True)
            hot_threads_text = str(hot_threads_response)
            section_data['raw_output'] = hot_threads_text
            
            # Parsing logic
            parsed_nodes = []
            # Normalize the text to ensure it's splittable
            text_to_parse = hot_threads_text.strip()
            if not text_to_parse.startswith(':::'):
                text_to_parse = ':::' + text_to_parse

            node_reports = text_to_parse.split('\n:::')
            for report in node_reports:
                if not report.strip(): continue
                
                lines = report.strip().split('\n')
                node_header = lines[0]
                node_name_match = re.search(r'\{([^}]+)\}', node_header)
                node_name = node_name_match.group(1) if node_name_match else 'Unknown Node'
                
                node_data = {'name': node_name, 'threads': []}
                current_thread = None
                
                # Start parsing from the line after "Hot threads at..."
                start_line = 0
                for i, line in enumerate(lines):
                    if "Hot threads at" in line:
                        start_line = i + 1
                        break
                
                for line in lines[start_line:]:
                    if re.match(r'\s*\d+\.\d+%', line): # Start of a new thread
                        if current_thread: node_data['threads'].append(current_thread)
                        current_thread = {'summary': [line.strip()], 'stack': []}
                    elif current_thread:
                        if 'snapshots sharing' in line:
                            current_thread['summary'].append(line.strip())
                        else:
                            current_thread['stack'].append(line)
                if current_thread: node_data['threads'].append(current_thread)
                
                if node_data['threads']: parsed_nodes.append(node_data)
            
            section_data['parsed_nodes'] = parsed_nodes
            total_hot_threads = sum(len(n['threads']) for n in parsed_nodes)
            section_data['summary']['total_hot_threads'] = total_hot_threads
            if total_hot_threads > 0: section_data['warnings'].append(f"{total_hot_threads} hot threads detected.")

            # Generate UI output
            self.update_results("   Hot Threads Summary:\n")
            self.update_results(f"   📊 Total Hot Threads Detected: {total_hot_threads}\n")
            if not parsed_nodes:
                self.update_results("   ✅ No significant hot threads detected.\n\n")
            else:
                self.update_results(f"   ⚠️  {section_data['warnings'][0]}\n\n")
                # Pass structured data to the HTML renderer via this special block
                self.update_results("---HOT-THREADS-INTERACTIVE-START---\n")
                self.update_results(json.dumps(parsed_nodes))
                self.update_results("\n---HOT-THREADS-INTERACTIVE-END---\n")

        except Exception as e:
            error_msg = f"Could not retrieve hot threads info: {str(e)}"
            self.update_results(f"   ⚠️  {error_msg}\n\n")
            section_data['error'] = error_msg
            
        self.analysis_data['hot_threads'] = section_data

    def _analyze_shard_distribution(self):
        """Analyze shard distribution, storing structured data."""
        self.update_results("🔍 SHARD DISTRIBUTION ANALYSIS:\n\n")
        section_data = {'summary': {}, 'warnings': []}

        try:
            shards_info = self.es.cat.shards(h='index,shard,prirep,node,state,docs,store', format='json')
            
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

            self.update_results("   Cluster Shard Summary:\n")
            self.update_results(f"   📈 Total Indices: {section_data['summary']['total_indices']}\n")
            self.update_results(f"   📈 Total Primary Shards: {section_data['summary']['total_primary_shards']}\n")
            self.update_results(f"   📈 Total Replica Shards: {section_data['summary']['total_replica_shards']}\n")
            self.update_results(f"   📈 Total Documents: {section_data['summary']['total_documents']:,}\n")
            
            if section_data['summary']['unassigned_shards'] > 0:
                self.update_results(f"   ⚠️  Warning: {section_data['warnings'][0]}\n")
            self.update_results("\n")
            
        except Exception as e:
            error_msg = f"Could not analyze shard distribution: {str(e)}"
            self.update_results(f"   ⚠️  {error_msg}\n\n")
            section_data['error'] = error_msg
            
        self.analysis_data['shard_distribution'] = section_data
            
    def _analyze_indexing_delta(self):
        """Automated delta check for current indexing activity, storing structured data."""
        self.update_results("📝 CURRENT INDEXING ACTIVITY (DELTA CHECK):\n")
        section_data = {'summary': {}, 'active_indices': [], 'warnings': []}

        try:
            self.update_results("   Gathering baseline indexing stats...\n")
            baseline_stats = self.es.cat.indices(h='index,pri.indexing.index_total', format='json')
            
            self.update_results("   Waiting 10 seconds to check for new activity...\n")
            time.sleep(10)
            
            self.update_results("   Gathering final indexing stats...\n")
            final_stats = self.es.cat.indices(h='index,pri.indexing.index_total', format='json')
            
            baseline_totals = {i['index']: int(i.get('pri.indexing.index_total', '0') or '0') for i in baseline_stats}
            final_totals = {i['index']: int(i.get('pri.indexing.index_total', '0') or '0') for i in final_stats}

            total_new_ops = 0
            for index, final_total in final_totals.items():
                baseline_total = baseline_totals.get(index, 0)
                if final_total > baseline_total:
                    change = final_total - baseline_total
                    total_new_ops += change
                    section_data['active_indices'].append({'index': index, 'new_operations': change})
                    self.update_results(f"   ✅ Indexing detected in {index} (+{change:,} ops)\n")

            section_data['summary']['active_index_count'] = len(section_data['active_indices'])
            section_data['summary']['total_new_operations'] = total_new_ops
            
            if not section_data['active_indices']:
                section_data['warnings'].append("NO ACTIVE INDEXING DETECTED in the last 10 seconds.")
                self.update_results(f"   ⚠️  {section_data['warnings'][0]}\n")
            else:
                self.update_results(f"   📈 ACTIVE INDICES (DELTA CHECK): {section_data['summary']['active_index_count']}\n")
            self.update_results("\n")

        except Exception as e:
            error_msg = f"Could not retrieve indexing delta stats: {str(e)}"
            self.update_results(f"   ⚠️  {error_msg}\n\n")
            section_data['error'] = error_msg
        
        self.analysis_data['indexing_delta'] = section_data

    def _parse_to_sections(self, results):
        """Parse analysis results into structured sections"""
        sections = {
            'overview': {'title': 'Cluster Overview', 'content': []},
            'pipeline': {'title': 'Pipeline Performance', 'content': []},
            'node': {'title': 'Node Resources', 'content': []},
            'threads': {'title': 'Thread Pools', 'content': []},
            'memory': {'title': 'Memory & GC', 'content': []},
            'breakers': {'title': 'Circuit Breakers', 'content': []},
            'search': {'title': 'Search & Cache', 'content': []},
            'io': {'title': 'I/O & Disk', 'content': []},
            'network': {'title': 'Network Traffic', 'content': []},
            'indexing': {'title': 'Index Operations', 'content': []},
            'indexing_delta': {'title': 'Indexing Delta', 'content': []},
            'segments': {'title': 'Segments & Allocation', 'content': []},
            'hotthreads': {'title': 'Hot Threads', 'content': []},
            'shards': {'title': 'Shard Distribution', 'content': []}
        }
        
        section_markers = {
            'overview': '📋 CLUSTER OVERVIEW',
            'pipeline': '⚡ PIPELINE PERFORMANCE ANALYSIS',
            'node': '📊 NODE RESOURCES',
            'threads': '🧵 COMPREHENSIVE THREAD POOL ANALYSIS',
            'memory': '🧠 MEMORY & GARBAGE COLLECTION ANALYSIS',
            'breakers': '🛡️ CIRCUIT BREAKER ANALYSIS',
            'search': '🔍 SEARCH PERFORMANCE & CACHE ANALYSIS',
            'io': '💾 I/O & DISK PERFORMANCE ANALYSIS',
            'network': '🌐 NETWORK TRAFFIC ANALYSIS',
            'indexing': '📝 INDEX OPERATIONS ANALYSIS',
            'indexing_delta': '📝 CURRENT INDEXING ACTIVITY (DELTA CHECK)',
            'segments': '🔧 SEGMENTS & ALLOCATION ANALYSIS',
            'hotthreads': '🔥 HOT THREADS ANALYSIS',
            'shards': '🔍 SHARD DISTRIBUTION ANALYSIS'
        }
        
        # Find the start of each section
        current_section = None
        current_lines = []
        
        for line in results.split('\n'):
            # Check if this line starts a new section
            found_section = None
            for section, marker in section_markers.items():
                if marker in line:
                    found_section = section
                    break
            
            if found_section:
                # If we had a previous section, save its content
                if current_section and current_lines:
                    sections[current_section]['content'] = current_lines
                
                # Start new section
                current_section = found_section
                current_lines = [line]
            elif current_section and '=== CLUSTER RESOURCE ANALYSIS ===' not in line:
                # Only append line if we're in a section and it's not a separator
                current_lines.append(line)
        
        # Save the last section
        if current_section and current_lines:
            sections[current_section]['content'] = current_lines
            
        # Remove empty sections
        sections = {k: v for k, v in sections.items() if v['content']}
            
        return sections

    def _generate_tabs(self, sections):
        """Generate HTML for navigation tabs"""
        # Define tab order
        tab_order = ['overview', 'pipeline', 'node', 'threads', 'memory', 'breakers', 'search', 'io', 'network', 'indexing', 'indexing_delta', 'segments', 'hotthreads', 'shards']
        tabs = []
        
        # Generate tabs in specified order, but only for sections that have content
        for key in tab_order:
            if key in sections:
                tabs.append(f"""
                    <div class="nav-tab{' active' if key == 'overview' else ''}"
                         data-tab="{key}">
                        {sections[key]['title']}
                    </div>
                """)
        
        return '\n'.join(tabs)

    def _generate_tab_content(self, sections):
        """Generate HTML content for each tab"""
        # Define tab order
        tab_order = ['overview', 'pipeline', 'node', 'threads', 'memory', 'breakers', 'search', 'io', 'network', 'indexing', 'indexing_delta', 'segments', 'hotthreads', 'shards']
        tab_contents = []
        
        # Generate content in specified order, but only for sections that have content
        for key in tab_order:
            if key in sections:
                section_content = self._process_section_content(sections[key]['content'])
                tab_contents.append(f'''
                    <div class="tab-content{' active' if key == 'overview' else ''}"
                         id="tab-{key}">
                        <div class="tab-content-inner">{section_content}</div>
                    </div>
                ''')
        
        return '\n'.join(tab_contents)
    
    def _process_section_content(self, content_lines):
        """Process content lines and return formatted HTML by grouping content into blocks."""
        content_lines = [line.strip() for line in content_lines[1:] if line.strip()]
        
        blocks = []
        current_block_type = None
        current_block_lines = []
        in_special_block = None # Can be 'pre' or 'hot-threads-interactive'

        for line in content_lines:
            # Check for start markers
            if line.strip() == '---HOT-THREADS-INTERACTIVE-START---':
                if current_block_lines and current_block_type: blocks.append({'type': current_block_type, 'lines': current_block_lines})
                current_block_type = 'hot-threads-interactive'
                current_block_lines = []
                in_special_block = 'hot-threads-interactive'
                continue
            
            # Check for end markers
            if line.strip() == '---HOT-THREADS-INTERACTIVE-END---':
                if current_block_lines: blocks.append({'type': 'hot-threads-interactive', 'lines': current_block_lines})
                current_block_type = None
                current_block_lines = []
                in_special_block = None
                continue

            if in_special_block:
                current_block_lines.append(line)
                continue

            # This logic runs for lines outside any special block
            line_type = 'other'
            is_table_line = '|' in line or '-+-' in line
            
            if is_table_line:
                line_type = 'table'
            elif any(i in line for i in ['📊', '📈', '🔥', '💡', '⚡']):
                line_type = 'metric'
            elif '⚠️' in line:
                line_type = 'warning'
            elif '✅' in line:
                line_type = 'success'

            if line_type != current_block_type and current_block_lines:
                blocks.append({'type': current_block_type, 'lines': current_block_lines})
                current_block_lines = []
            
            current_block_type = line_type
            current_block_lines.append(line)

        # Append the last remaining block
        if current_block_lines and current_block_type:
            blocks.append({'type': current_block_type, 'lines': current_block_lines})
            
        return self._render_html_parts(blocks)

    def _render_html_parts(self, blocks):
        """Render a list of content blocks to HTML."""
        html_parts = []
        
        for block in blocks:
            block_type = block['type']
            lines = block['lines']
            
            if block_type == 'table':
                html_parts.append(self._convert_table_to_html(lines))
            
            elif block_type == 'metric':
                html_parts.append('<div class="metric-grid">')
                for line in lines:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        icon = next((i for i in ['📊', '📈', '🔥', '💡', '⚡'] if i in parts[0]), '')
                        label = parts[0].replace(icon, '').strip()
                        value = parts[1].strip()
                        html_parts.append(f'''
                            <div class="metric-card">
                                <div class="metric-icon">{icon}</div>
                                <div class="metric-value">{value}</div>
                                <div class="metric-label">{label}</div>
                            </div>
                        ''')
                html_parts.append('</div>')

            elif block_type == 'warning':
                html_parts.append('<div class="alerts-section">')
                for line in lines:
                    html_parts.append(f'<div class="warning">{line}</div>')
                html_parts.append('</div>')
            
            elif block_type == 'success':
                html_parts.append('<div class="alerts-section">')
                for line in lines:
                    html_parts.append(f'<div class="success">{line}</div>')
                html_parts.append('</div>')

            elif block_type == 'hot-threads-interactive':
                html_parts.append(self._render_hot_threads_interactive(lines))
            
            elif block_type == 'other':
                html_parts.append('<div class="content-section">')
                for line in lines:
                    # Heuristic to detect sub-headings vs plain text
                    if line.endswith(':') and len(line) < 60 and not any(c.isdigit() for c in line):
                         html_parts.append(f'<h4 class="content-subheading">{line}</h4>')
                    else:
                         html_parts.append(f'<div class="content-line">{line}</div>')
                html_parts.append('</div>')

        return '\n'.join(html_parts)

    def _render_hot_threads_interactive(self, json_lines):
        """Render parsed hot threads data into a collapsible HTML structure."""
        try:
            nodes_data = json.loads("".join(json_lines))
            if not nodes_data: return '<div class="content-section"><p>No hot threads data to display.</p></div>'
            
            html_parts = ['<div class="hot-threads-container">']
            for node in nodes_data:
                html_parts.append(f'<div class="hot-threads-node">')
                html_parts.append(f'<h4>Node: {html.escape(node["name"])}</h4>')
                for i, thread in enumerate(node["threads"]):
                    summary_html = '<br>'.join(html.escape(s) for s in thread['summary'])
                    stack_html = '<br>'.join(html.escape(s) for s in thread['stack'])
                    
                    html_parts.append(f'''
                        <div class="hot-thread">
                            <div class="hot-thread-summary" onclick="toggleStackTrace(this)">
                                {summary_html}
                                <span class="toggler">+</span>
                            </div>
                            <div class="hot-thread-stack">
                                <pre>{stack_html}</pre>
                            </div>
                        </div>
                    ''')
                html_parts.append('</div>')
            html_parts.append('</div>')
            return ''.join(html_parts)
        except json.JSONDecodeError as e:
            return f'<div class="warning">Error parsing hot threads data: {html.escape(str(e))}</div>'
        except Exception as e:
            return f'<div class="warning">An unexpected error occurred while rendering hot threads: {html.escape(str(e))}</div>'

    def _convert_table_to_html(self, table_lines):
        """Convert ASCII table to HTML table, handling optional title."""
        html_lines = ['<div class="table-container">']
        
        # Check for a title line (does not contain '|' or '-+-')
        first_line = table_lines[0].strip()
        if '|' not in first_line and '-+-' not in first_line:
            html_lines.append(f'<h3 class="table-title">{first_line}</h3>')
            table_lines = table_lines[1:]

        html_lines.append('<table>')
        header_done = False
        
        for line in table_lines:
            if '-+-' in line:
                continue
            
            # Split by '|' but keep empty strings for empty cells
            cells = [cell.strip() for cell in line.split('|')]
            
            if not header_done:
                html_lines.append('<thead><tr>')
                for cell in cells:
                    html_lines.append(f'<th>{cell}</th>')
                html_lines.append('</tr></thead><tbody>')
                header_done = True
            else:
                html_lines.append('<tr>')
                for cell in cells:
                    html_lines.append(f'<td>{cell}</td>')
                html_lines.append('</tr>')
        
        html_lines.append('</tbody></table></div>')
        return '\n'.join(html_lines)
                            

    def generate_html(self):
        """Generate HTML report from analysis results"""
        results = self.results_text.get(1.0, tk.END)
        
        parsed_sections = self._parse_to_sections(results)
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Elasticsearch Cluster Analysis Report</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
            <style>
                :root {{
                    --primary-color: #0077CC;
                    --secondary-color: #005599;
                    --bg-color: #f4f7f9;
                    --text-color: #334155;
                    --warning-color: #e74c3c;
                    --success-color: #2ecc71;
                    --border-color: #e2e8f0;
                    --header-height: 70px;
                }}

                body {{
                    font-family: 'Inter', sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 0;
                    background-color: var(--bg-color);
                    color: var(--text-color);
                }}
                
                .header {{
                    background: white;
                    padding: 0 30px;
                    height: var(--header-height);
                    display: flex;
                    align-items: center;
                    position: sticky;
                    top: 0;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
                    z-index: 100;
                }}

                .header h1 {{
                    font-size: 22px;
                    font-weight: 600;
                    margin: 0;
                }}
                .header .timestamp {{
                    font-size: 13px;
                    color: #64748b;
                    margin-left: auto;
                }}

                .main-layout {{
                    display: flex;
                    max-width: 1600px;
                    margin: 20px auto;
                    padding: 0 20px;
                    gap: 20px;
                }}

                .side-nav {{
                    flex: 0 0 240px;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
                    padding: 10px;
                    height: calc(100vh - var(--header-height) - 40px);
                    position: sticky;
                    top: calc(var(--header-height) + 20px);
                    overflow-y: auto;
                }}

                .main-content {{
                    flex: 1;
                    min-width: 0;
                }}

                .nav-tab {{
                    display: block;
                    padding: 10px 15px;
                    cursor: pointer;
                    border-radius: 6px;
                    font-weight: 500;
                    color: #475569;
                    transition: all 0.2s ease;
                    margin-bottom: 5px;
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }}
                .nav-tab:hover {{
                    background: #f1f5f9;
                    color: var(--primary-color);
                }}
                .nav-tab.active {{
                    background: var(--primary-color);
                    color: white;
                    font-weight: 600;
                }}
                
                .tab-content {{
                    display: none;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                }}
                .tab-content.active {{
                    display: block;
                }}
                
                .tab-content-inner {{
                    padding: 24px;
                }}
                
                .table-title {{
                    font-size: 18px;
                    font-weight: 600;
                    margin-bottom: 12px;
                    padding: 0 10px;
                }}
                .content-subheading {{
                    font-weight: 600;
                    font-size: 14px;
                    margin-top: 16px;
                    margin-bottom: 8px;
                    color: #475569;
                }}

                .table-container {{
                    margin: 20px 0;
                    overflow-x: auto;
                    border: 1px solid var(--border-color);
                    border-radius: 8px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                th, td {{
                    padding: 12px 16px;
                    text-align: left;
                    border-bottom: 1px solid var(--border-color);
                }}
                th {{
                    background: #f8fafc;
                    font-weight: 600;
                    color: var(--text-color);
                }}
                tr:last-child td {{ border-bottom: none; }}
                tbody tr:hover {{ background: #f8fafc; }}

                .metric-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                    gap: 20px;
                    margin: 20px 0;
                }}
                
                .metric-card {{
                    background: #ffffff;
                    padding: 20px;
                    border-radius: 12px;
                    border: 1px solid var(--border-color);
                    transition: transform 0.2s ease, box-shadow 0.2s ease;
                    position: relative;
                }}
                .metric-card:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                }}
                .metric-icon {{
                    position: absolute; top: 16px; right: 16px; font-size: 24px; opacity: 0.2;
                }}
                .metric-value {{
                    font-size: 28px; font-weight: 700; color: var(--primary-color); margin-bottom: 4px;
                }}
                .metric-label {{
                    font-size: 14px; color: #64748b; font-weight: 500;
                }}

                .alerts-section, .content-section {{
                    margin: 20px 0;
                }}
                .content-section {{
                    background: #f8fafc; padding: 20px; border-radius: 8px;
                }}
                .content-line {{ padding: 4px 0; font-family: monospace; font-size: 13px; }}
                pre {{
                    white-space: pre-wrap;
                    word-wrap: break-word;
                    font-family: monospace;
                    font-size: 12px;
                    padding: 15px;
                    background: #f1f5f9;
                    border-radius: 6px;
                    border: 1px solid var(--border-color);
                }}
                
                .warning, .success {{
                    padding: 15px 20px; border-radius: 8px; margin: 10px 0; font-size: 14px; font-weight: 500;
                }}
                .warning {{
                    background: #fff1f2; border-left: 4px solid #ef4444; color: #9f1239;
                }}
                .success {{
                    background: #f0fdf4; border-left: 4px solid #22c55e; color: #15803d;
                }}
                
                .hot-threads-container {{ margin: 20px 0; }}
                .hot-threads-node {{ border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 20px; padding: 16px; }}
                .hot-threads-node h4 {{ margin-top: 0; }}
                .hot-thread {{ border-bottom: 1px solid #f1f5f9; padding-bottom: 10px; margin-bottom: 10px; }}
                .hot-thread:last-child {{ border-bottom: none; margin-bottom: 0; }}
                .hot-thread-summary {{ cursor: pointer; font-weight: 500; position: relative; padding-right: 20px; }}
                .hot-thread-summary .toggler {{ position: absolute; right: 0; top: 0; font-weight: bold; }}
                .hot-thread-stack {{ display: none; margin-top: 10px; }}

            </style>
            <script>
                function toggleStackTrace(element) {{
                    var stack = element.nextElementSibling;
                    var toggler = element.querySelector('.toggler');
                    if (stack.style.display === "block") {{
                        stack.style.display = "none";
                        toggler.textContent = '+';
                    }} else {{
                        stack.style.display = "block";
                        toggler.textContent = '-';
                    }}
                }}
                $(document).ready(function() {{
                    $('.nav-tab').click(function() {{
                        $('.nav-tab').removeClass('active');
                        $('.tab-content').removeClass('active');
                        $(this).addClass('active');
                        $('#tab-' + $(this).data('tab')).addClass('active');
                    }});
                    $('.nav-tab').first().click();
                }});
            </script>
        </head>
        <body>
            <div class="header">
                <h1>Elasticsearch Cluster Analysis Report</h1>
                <div class="timestamp">Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            </div>
            <div class="main-layout">
                <div class="side-nav">
                    {self._generate_tabs(parsed_sections)}
                </div>
                <div class="main-content">
                    {self._generate_tab_content(parsed_sections)}
                </div>
            </div>
        </body>
        </html>
        """
        
        # Convert ANSI-style emojis to HTML entities
        emoji_map = {
            "✅": "&#9989;",
            "⚠️": "&#9888;",
            "❌": "&#10060;",
            "📊": "&#128202;",
            "🔥": "&#128293;",
            "📈": "&#128200;",
            "⚡": "&#9889;",
            "💡": "&#128161;",
            "🔄": "&#128260;",
            "🧵": "&#129525;",
            "🔍": "&#128269;",
            "📝": "&#128221;",
            "🎯": "&#127919;",
            "🛡️": "&#128737;",
            "🌐": "&#127760;"
        }
        
        for emoji, html_code in emoji_map.items():
            html = html.replace(emoji, html_code)
            
        return html
    
    def open_in_browser(self):
        """Open analysis results in default web browser"""
        if not self.results_text.get(1.0, tk.END).strip():
            messagebox.showwarning("No Data", "No analysis results to display")
            return
            
        try:
            # Create temporary HTML file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.html', mode='w', encoding='utf-8') as f:
                html_content = self.generate_html()
                f.write(html_content)
                temp_path = f.name
            
            # Open in default browser
            webbrowser.open('file://' + os.path.realpath(temp_path))
            
            # Schedule file deletion after a delay
            self.root.after(5000, lambda: os.unlink(temp_path) if os.path.exists(temp_path) else None)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open in browser: {str(e)}")
            
    def export_results_to_json(self, filepath=None):
        """Export analysis results to a structured JSON file. Handles both GUI and CLI."""
        if not self.analysis_data:
            msg = "No analysis data to export."
            if self.cli_args and self.cli_args.export_json:
                print(msg)
            else:
                messagebox.showwarning("No Data", msg)
            return

        try:
            # If no filepath is provided (GUI mode), open a file dialog
            if not filepath:
                filepath = filedialog.asksaveasfilename(
                    defaultextension=".json",
                    filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                    title="Save Analysis Report as JSON"
                )
            
            if not filepath:
                return  # User cancelled or no path provided

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.analysis_data, f, indent=4)
                
            success_message = f"Analysis report successfully saved to: {filepath}"
            if self.cli_args and self.cli_args.export_json:
                print(success_message)
            else:
                messagebox.showinfo("Export Successful", success_message)

        except Exception as e:
            error_message = f"Failed to export results to JSON: {str(e)}"
            if self.cli_args and self.cli_args.export_json:
                print(f"Error: {error_message}")
            else:
                messagebox.showerror("Export Error", error_message)
    
    def update_results(self, text):
        """Update results text widget (thread-safe) and print to console in CLI mode."""
        if self.cli_args and (self.cli_args.run or self.cli_args.export_json):
            # For CLI mode, print simplified output to the console
            # This is a simple way to provide progress feedback without complex parsing
            if '<pre>' not in text and '</pre>' not in text:
                 print(text, end='')

        def update():
            # This part still runs to populate the text widget, which might be
            # needed for the HTML report generation in --run mode.
            self.results_text.insert(tk.END, text)
            self.results_text.see(tk.END)
            if self.results_text.get(1.0, tk.END).strip():
                self.browser_btn.config(state=tk.NORMAL)
                self.export_btn.config(state=tk.NORMAL)
        
        # Check if root window exists before scheduling the update
        if self.root.winfo_exists():
            self.root.after(0, update)
    
    def clear_results(self):
        """Clear the results text widget"""
        self.results_text.delete(1.0, tk.END)
        self.browser_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.DISABLED)

    def _analyze_circuit_breakers(self):
        """Analyze circuit breaker statistics and store structured data."""
        self.update_results("🛡️ CIRCUIT BREAKER ANALYSIS:\n\n")
        
        # Initialize structured data for this section
        section_data = {
            'summary': {},
            'details': []
        }

        try:
            breaker_stats = self.es.nodes.stats(metric=['breaker'])
            
            table_rows = []
            total_tripped = 0
            
            sorted_node_ids = sorted(breaker_stats.get('nodes', {}).keys(), key=lambda x: breaker_stats['nodes'][x].get('name', ''))

            for node_id in sorted_node_ids:
                node_data = breaker_stats['nodes'][node_id]
                breakers = node_data.get('breakers', {})
                for breaker_name, stats in breakers.items():
                    tripped_count = stats.get('tripped', 0)
                    total_tripped += tripped_count
                    limit_bytes = stats.get('limit_size_in_bytes', 0)
                    
                    # Only include relevant breakers in the report
                    if limit_bytes > 0 or stats.get('estimated_size_in_bytes', 0) > 0 or tripped_count > 0:
                        estimated_bytes = stats.get('estimated_size_in_bytes', 0)
                        usage_percent = (estimated_bytes / limit_bytes * 100) if limit_bytes > 0 else 0
                        
                        # Store structured data
                        section_data['details'].append({
                            'node': node_data.get('name', 'Unknown'),
                            'breaker': breaker_name,
                            'limit_bytes': limit_bytes,
                            'estimated_bytes': estimated_bytes,
                            'usage_percent': usage_percent,
                            'tripped_count': tripped_count
                        })
                        
                        # Prepare rows for text table
                        table_rows.append([
                            node_data.get('name', 'Unknown'),
                            breaker_name,
                            f"{limit_bytes / 1024**2:.1f}MB",
                            f"{estimated_bytes / 1024**2:.1f}MB",
                            f"{usage_percent:.1f}%",
                            str(tripped_count)
                        ])

            # Store and display summary
            section_data['summary']['total_tripped'] = total_tripped
            self.update_results("   Circuit Breaker Summary:\n")
            if total_tripped > 0:
                self.update_results(f"   ⚠️🔥 Total Breaker Trips Detected: {total_tripped}\n")
                self.update_results("      Investigate immediately! Tripped breakers indicate memory pressure and can cause request failures.\n")
            else:
                self.update_results("   ✅ No circuit breaker trips detected. Memory management is stable.\n")
            self.update_results("\n")
            
            # Display text table
            if table_rows:
                headers = ['Node', 'Breaker', 'Limit', 'Estimated', 'Usage %', 'Tripped']
                self.update_results(self._format_table(headers=headers, rows=table_rows, title="Circuit Breaker Status by Node"))

        except Exception as e:
            error_msg = f"Could not retrieve circuit breaker info: {str(e)}"
            self.update_results(f"   ⚠️  {error_msg}\n\n")
            section_data['error'] = error_msg
        
        # Save structured data to the main dictionary
        self.analysis_data['circuit_breakers'] = section_data

    def _analyze_network_traffic(self):
        """Network transport analysis, storing structured data."""
        self.update_results("🌐 NETWORK TRAFFIC ANALYSIS:\n\n")
        
        section_data = {'summary': {}, 'details_by_node': []}

        try:
            transport_stats = self.es.nodes.stats(metric=['transport'])
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
            
            # Calculate and store summary
            section_data['summary'] = {'total_rx_mb': total_rx_mb, 'total_tx_mb': total_tx_mb}

            # Generate and display text report from structured data
            self.update_results("   Network Summary:\n")
            self.update_results(f"   📊 Total Data Received (RX): {section_data['summary']['total_rx_mb']:.1f}MB\n")
            self.update_results(f"   📊 Total Data Sent (TX): {section_data['summary']['total_tx_mb']:.1f}MB\n\n")

            network_table_rows = [[
                d['node'], f"{d['rx_count']:,}", f"{d['tx_count']:,}",
                f"{d['rx_mb']:.1f}MB", f"{d['tx_mb']:.1f}MB", str(d['server_connections_open'])
            ] for d in section_data['details_by_node']]
            
            network_headers = ['Node', 'RX Count', 'TX Count', 'RX Data', 'TX Data', 'Connections']
            self.update_results(self._format_table(headers=network_headers, rows=network_table_rows, title="Network Transport Performance"))

        except Exception as e:
            error_msg = f"Could not retrieve network traffic info: {str(e)}"
            self.update_results(f"   ⚠️  {error_msg}\n\n")
            section_data['error'] = error_msg
        
        self.analysis_data['network_traffic'] = section_data

def main():
    parser = argparse.ArgumentParser(description="Elasticsearch Cluster Analyzer. Run with no arguments for GUI mode.")
    # Connection args
    conn_group = parser.add_mutually_exclusive_group()
    conn_group.add_argument("--cloud-id", help="Elasticsearch Cloud ID")
    conn_group.add_argument("--url", help="Elasticsearch cluster URL (e.g., https://localhost:9200)")
    
    # Auth args
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument("--api-key", help="API Key for authentication (format: 'id:key' or base64 encoded string)")
    auth_group.add_argument("--user", help="Username for basic authentication")
    
    parser.add_argument("--password", help="Password for basic authentication (required with --user)")
    parser.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--run", action="store_true", help="Automatically run analysis, open report in browser, and exit. Requires connection and auth args.")
    parser.add_argument("--export-json", metavar="FILEPATH", help="Export analysis results to the specified JSON file and exit. Requires connection and auth args.")
    
    args = parser.parse_args()
    
    # Validate args for CLI run
    if args.run or args.export_json:
        if not (args.cloud_id or args.url):
            parser.error("Connection details (--cloud-id or --url) are required for CLI runs.")
        if not (args.api_key or (args.user and args.password)):
             parser.error("Authentication details (--api-key or --user/--password) are required for CLI runs.")
        if args.user and not args.password:
            parser.error("--password is required when --user is provided.")

    root = tk.Tk()
    app = ElasticsearchAnalyzer(root, cli_args=args)
    
    # The mainloop will run. If in CLI mode, the app will auto-run and then destroy the root window.
    root.mainloop()

if __name__ == "__main__":
    main()
