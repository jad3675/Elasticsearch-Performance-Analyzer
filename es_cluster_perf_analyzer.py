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

try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False

class ElasticsearchAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Elasticsearch Cluster Resource Analyzer")
        self.root.geometry("800x700")
        
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
        
        # Check if elasticsearch library is available
        if not ES_AVAILABLE:
            messagebox.showerror("Missing Dependency",
                               "Please install the elasticsearch library:\npip install elasticsearch")
            self.root.destroy()
            return
            
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
            # Initialize all required metrics
            total_cpus = 0
            active_primary_shards = 0
            indexing_stats = []
            primary_shards = []
            
            # Setup connection
            if not self.setup_connection():
                return
            
            self.update_results("Connecting to Elasticsearch cluster...\n")
            
            # Test connection and get comprehensive cluster info
            cluster_health = self.es.cluster.health()
            cluster_info = self.es.info()
            nodes_info = self.es.nodes.info()
            pipeline_stats = self.es.nodes.stats(metric=['ingest'])
            
            # Process pipeline stats
            total_ingest_count = 0
            total_ingest_time_ms = 0
            total_ingest_failures = 0
            pipeline_metrics = {}
            
            for node_id, node_data in pipeline_stats.get('nodes', {}).items():
                ingest_stats = node_data.get('ingest', {})
                total = ingest_stats.get('total', {})
                total_ingest_count += total.get('count', 0)
                total_ingest_time_ms += total.get('time_in_millis', 0)
                total_ingest_failures += total.get('failed', 0)
                
                # Per-pipeline stats
                for pipeline_id, stats in ingest_stats.get('pipelines', {}).items():
                    if pipeline_id not in pipeline_metrics:
                        pipeline_metrics[pipeline_id] = {
                            'count': 0,
                            'time_ms': 0,
                            'failed': 0
                        }
                    pipeline_metrics[pipeline_id]['count'] += stats.get('count', 0)
                    pipeline_metrics[pipeline_id]['time_ms'] += stats.get('time_in_millis', 0)
                    pipeline_metrics[pipeline_id]['failed'] += stats.get('failed', 0)
            
            # Calculate average processing time
            avg_process_time = (total_ingest_time_ms / total_ingest_count) if total_ingest_count > 0 else 0
            
            # Enhanced Cluster Overview Section
            self.update_results("📋 CLUSTER OVERVIEW:\n\n")
            
            # Basic cluster info
            cluster_name = cluster_health.get('cluster_name', 'Unknown')
            cluster_status = cluster_health.get('status', 'Unknown')
            num_nodes = cluster_health.get('number_of_nodes', 0)
            num_data_nodes = cluster_health.get('number_of_data_nodes', 0)
            
            # Elasticsearch version and build info
            es_version = cluster_info.get('version', {})
            version_number = es_version.get('number', 'Unknown')
            build_date = es_version.get('build_date', 'Unknown')
            lucene_version = es_version.get('lucene_version', 'Unknown')
            
            # Cluster-level metrics
            active_primary_shards = cluster_health.get('active_primary_shards', 0)
            active_shards = cluster_health.get('active_shards', 0)
            relocating_shards = cluster_health.get('relocating_shards', 0)
            initializing_shards = cluster_health.get('initializing_shards', 0)
            unassigned_shards = cluster_health.get('unassigned_shards', 0)
            
            # Display overview in organized sections
            overview_table_rows = [
                ['Cluster Name', cluster_name],
                ['Status', f"{'🟢' if cluster_status == 'green' else '🟡' if cluster_status == 'yellow' else '🔴'} {cluster_status.upper()}"],
                ['Elasticsearch Version', version_number],
                ['Lucene Version', lucene_version],
                ['Build Date', build_date[:10] if build_date != 'Unknown' else 'Unknown'],
                ['Total Nodes', str(num_nodes)],
                ['Data Nodes', str(num_data_nodes)],
                ['Master Nodes', str(num_nodes - num_data_nodes)]
            ]
            
            self.update_results(self._format_table(
                headers=['Property', 'Value'],
                rows=overview_table_rows,
                title="Cluster Information"
            ))
            
            # Shard health overview
            shard_health_rows = [
                ['Active Primary Shards', str(active_primary_shards)],
                ['Total Active Shards', str(active_shards)],
                ['Relocating Shards', str(relocating_shards)],
                ['Initializing Shards', str(initializing_shards)],
                ['Unassigned Shards', f"{'⚠️ ' if unassigned_shards > 0 else ''}{unassigned_shards}"]
            ]
            
            self.update_results(self._format_table(
                headers=['Shard Type', 'Count'],
                rows=shard_health_rows,
                title="Shard Distribution Health"
            ))
            
            # Node architecture overview
            node_roles = {}
            node_versions = {}
            
            for node_id, node_data in nodes_info.get('nodes', {}).items():
                roles = node_data.get('roles', [])
                version = node_data.get('version', 'Unknown')
                
                # Count roles
                for role in roles:
                    node_roles[role] = node_roles.get(role, 0) + 1
                
                # Track versions
                node_versions[version] = node_versions.get(version, 0) + 1
            
            if node_roles:
                role_rows = [[role, str(count)] for role, count in sorted(node_roles.items())]
                self.update_results(self._format_table(
                    headers=['Node Role', 'Count'],
                    rows=role_rows,
                    title="Node Roles Distribution"
                ))
            
            # Display any version inconsistencies
            if len(node_versions) > 1:
                version_rows = [[version, str(count)] for version, count in sorted(node_versions.items())]
                self.update_results(self._format_table(
                    headers=['Version', 'Node Count'],
                    rows=version_rows,
                    title="⚠️ Version Distribution (Mixed Versions Detected)"
                ))
            
            if total_ingest_failures > 0:
                self.update_results(f"\n   ⚠️ Pipeline Failures: {total_ingest_failures:,} failed ingest operations detected\n")
            
            self.update_results("\n")
            
            # Show per-pipeline metrics if available
            if pipeline_metrics:
                # Sort pipelines by document count
                active_pipelines = {k: v for k, v in pipeline_metrics.items() if v['count'] > 0}
                sorted_pipelines = sorted(active_pipelines.items(),
                                       key=lambda x: x[1]['count'],
                                       reverse=True)
                
                if sorted_pipelines:
                    self.update_results("⚡ PIPELINE PERFORMANCE ANALYSIS:\n\n")
                    
                    # Prepare tables for failed and healthy pipelines
                    failed_rows = []
                    healthy_rows = []
                    
                    for pipeline_id, metrics in sorted_pipelines:
                        avg_time = metrics['time_ms'] / metrics['count']
                        row = [
                            pipeline_id,
                            f"{metrics['count']:,}",
                            f"{avg_time:.2f}ms"
                        ]
                        
                        if metrics['failed'] > 0:
                            failure_rate = (metrics['failed'] / metrics['count'] * 100)
                            row.extend([
                                f"{metrics['failed']:,}",
                                f"{failure_rate:.1f}%"
                            ])
                            failed_rows.append(row)
                        else:
                            healthy_rows.append(row)
                    
                    # Show failed pipelines table
                    if failed_rows:
                        self.update_results(self._format_table(
                            headers=['Pipeline', 'Documents', 'Avg Time', 'Failed', 'Failure Rate'],
                            rows=failed_rows,
                            title="⚠️  Pipelines with Failures"
                        ))
                    
                    # Show healthy pipelines table
                    if healthy_rows:
                        self.update_results(self._format_table(
                            headers=['Pipeline', 'Documents', 'Avg Time'],
                            rows=healthy_rows,
                            title="✅ Healthy Pipelines"
                        ))
                    
                    # Add summary
                    total_docs = sum(m['count'] for _, m in sorted_pipelines)
                    total_failed = sum(m['failed'] for _, m in sorted_pipelines)
                    total_time = sum(m['time_ms'] for _, m in sorted_pipelines)
                    avg_time = total_time / total_docs if total_docs > 0 else 0
                    
                    self.update_results("   Pipeline Summary:\n")
                    self.update_results(f"   📈 Total Active Pipelines: {len(sorted_pipelines)}\n")
                    self.update_results(f"   📈 Total Documents Processed: {total_docs:,}\n")
                    self.update_results(f"   📈 Average Processing Time: {avg_time:.2f}ms\n")
                    if total_failed > 0:
                        self.update_results(f"   ⚠️  Total Failed Operations: {total_failed:,}\n")
                    self.update_results("\n")
                else:
                    self.update_results("   No active pipelines found.\n\n")
            
            # Node resource analysis section
            self.update_results("📊 NODE RESOURCES:\n\n")
            
            # Try multiple approaches to get CPU info
            # Initialize metrics
            total_cpus = 0
            active_primary_shards = 0
            table_rows = []
            
            try:
                # Get node information from all available APIs
                nodes_stats = self.es.nodes.stats()
                nodes_info_api = self.es.nodes.info()
                cat_nodes = self.es.cat.nodes(h='name,cpu,load_1m,processors,heap.max,ram.max', format='json')
                
                # Create a mapping of node names to their roles
                node_roles_map = {}
                for node_id, node_data in nodes_info_api.get('nodes', {}).items():
                    node_name = node_data.get('name')
                    roles = node_data.get('roles', [])
                    if node_name:
                        # Abbreviate roles for concise table display
                        role_abbreviations = {
                            'master': 'm', 'data': 'd', 'data_content': 'dc',
                            'data_hot': 'dh', 'data_warm': 'dw', 'data_cold': 'dco',
                            'data_frozen': 'df', 'ingest': 'i', 'ml': 'ml',
                            'remote_cluster_client': 'r', 'transform': 't'
                        }
                        abbreviated_roles = [role_abbreviations.get(r, r) for r in roles]
                        node_roles_map[node_name] = ', '.join(sorted(abbreviated_roles))

                # Process nodes and collect data
                for node in cat_nodes:
                    node_name = node.get('name', 'Unknown')
                    roles_str = node_roles_map.get(node_name, 'N/A')
                    processors = node.get('processors', 'N/A')
                    heap_max = node.get('heap.max', 'N/A')
                    ram_max = node.get('ram.max', 'N/A')
                    cpu_usage = node.get('cpu', '0')
                    load = node.get('load_1m', 'N/A')
                    
                    # Get CPU count from various sources
                    cpu_count = 0
                    if processors and processors != 'N/A':
                        try:
                            cpu_count = int(processors)
                        except:
                            pass
                    
                    # Try nodes.info if cat API doesn't have processors
                    if cpu_count == 0:
                        for node_data in nodes_info_api.get('nodes', {}).values():
                            if node_data.get('name') == node_name:
                                os_info = node_data.get('os', {})
                                cpu_count = (os_info.get('available_processors') or
                                           os_info.get('allocated_processors') or
                                           node_data.get('settings', {}).get('node', {}).get('processors', 0))
                                break
                    
                    # Fallback to heap-based estimation
                    if cpu_count == 0 and heap_max and heap_max != 'N/A':
                        try:
                            heap_gb = self._parse_size_to_gb(heap_max)
                            if heap_gb > 0:
                                cpu_count = max(1, int(heap_gb / 2))
                        except:
                            pass
                    
                    total_cpus += cpu_count
                    
                    # Add row to table data
                    table_rows.append([
                        node_name,
                        roles_str,
                        f"{cpu_count} vCPUs",
                        heap_max,
                        ram_max,
                        f"{cpu_usage}%",
                        load
                    ])
                
                # Display the node resources table
                headers = ['Node Name', 'Roles', 'CPUs', 'Heap Size', 'RAM', 'CPU Usage', 'Load']
                self.update_results(self._format_table(
                    headers=headers,
                    rows=sorted(table_rows, key=lambda x: x[0]),  # Sort by node name
                    title="Node Resources"
                ))
                
                # Add resource summary
                self.update_results("   Resource Summary:\n")
                self.update_results(f"   📈 Total Cluster vCPUs: {total_cpus}\n")
                self.update_results(f"   📈 Total Nodes: {len(cat_nodes)}\n")
                
                # Calculate and show cluster averages
                try:
                    avg_cpu = sum(float(node.get('cpu', 0)) for node in cat_nodes) / len(cat_nodes)
                    avg_load = sum(float(node.get('load_1m', 0)) for node in cat_nodes) / len(cat_nodes)
                    self.update_results(f"   📈 Average CPU Usage: {avg_cpu:.1f}%\n")
                    self.update_results(f"   📈 Average Load: {avg_load:.2f}\n")
                except:
                    pass
                
                self.update_results("\n")
                
            except Exception as e:
                self.update_results(f"   ⚠️  Could not retrieve node resource info: {str(e)}\n\n")
            
            # 3. Comprehensive Thread Pool Analysis
            self._analyze_all_thread_pools()
            
            # 4. Memory and GC Analysis
            self._analyze_memory_and_gc()
            
            # 5. Search Performance Analysis
            self._analyze_search_performance()
            
            # 6. I/O Performance Analysis
            self._analyze_io_performance()
            
            # 7. Index Operations Analysis
            self._analyze_index_operations()
            
            # 8. Segments and Allocation Analysis
            self._analyze_segments_and_allocation()
            
            # 9. Hot Threads Analysis
            self._analyze_hot_threads()
            
            # 10. Shard Distribution Analysis
            self._analyze_shard_distribution()
            
            # 11. Indexing Delta Check
            self._analyze_indexing_delta()
            
            # Final pipeline performance summary (if not already covered)
            if "PIPELINE PERFORMANCE ANALYSIS" not in self.results_text.get(1.0, tk.END):
                 self._analyze_pipeline_performance(pipeline_metrics, total_ingest_count, total_ingest_time_ms, total_ingest_failures, avg_process_time)
            
            # Add completion message to overview section
            self.update_results("\n✅ Connected to cluster: Cluster Analysis Summary\n")
            self.update_results(f"   Total Analyzed Sections: 5\n")
            self.update_results("   Analysis Status: Complete\n\n")
            
        except Exception as e:
            error_msg = str(e)
            self.update_results(f"❌ Error during analysis: {error_msg}\n")
            messagebox.showerror("Analysis Error", error_msg)
            
    def _analyze_pipeline_performance(self, pipeline_metrics, total_ingest_count, total_ingest_time_ms, total_ingest_failures, avg_process_time):
        """Analyze pipeline performance metrics"""
        self.update_results("⚡ PIPELINE PERFORMANCE ANALYSIS:\n")
        self.update_results("=" * 50 + "\n")
        
        docs_per_second = (total_ingest_count / (total_ingest_time_ms / 1000)) if total_ingest_time_ms > 0 else 0
        self.update_results(f"📊 Processing Rate: {docs_per_second:.2f} docs/second\n")
        self.update_results(f"📊 Average Processing Time: {avg_process_time:.2f}ms\n")
        self.update_results(f"📊 Total Pipeline Failures: {total_ingest_failures:,}\n\n")
        
        if pipeline_metrics:
            self.update_results("🔄 PIPELINE RECOMMENDATIONS:\n")
            self.update_results("=" * 30 + "\n")
            
            for pipeline_id, metrics in pipeline_metrics.items():
                avg_time = (metrics['time_ms'] / metrics['count']) if metrics['count'] > 0 else 0
                if avg_time > 100:
                    self.update_results(f"⚠️  High processing time for pipeline '{pipeline_id}' ({avg_time:.2f}ms)\n")
                    self.update_results("   Consider optimizing pipeline processors or splitting into multiple pipelines.\n\n")
                
                failure_rate = (metrics['failed'] / metrics['count'] * 100) if metrics['count'] > 0 else 0
                if failure_rate > 1:
                    self.update_results(f"⚠️  High failure rate for pipeline '{pipeline_id}' ({failure_rate:.1f}%)\n")
                    self.update_results("   Check pipeline processors and document structure.\n\n")
    
    def _analyze_resources(self, total_cpus, total_active, total_available, primary_shards, active_primary_shards, indexing_stats):
        """Add resource utilization analysis to current section"""
        # Calculate utilization metrics
        cpu_utilization = (total_active / total_cpus) * 100 if total_cpus > 0 else 0
        thread_utilization = (total_active / total_available) * 100 if total_available > 0 else 0
        
        self.update_results("\n   Resource Utilization:\n")
        
        self.update_results("   Resource Metrics:\n")
        self.update_results(f"   📊 Total vCPUs Available: {total_cpus}\n")
        self.update_results(f"   🔥 Active Write Threads: {total_active}\n")
        self.update_results(f"   📈 Primary Shards: {len(primary_shards)}\n")
        self.update_results(f"   ⚡ Active Indexing Shards: {active_primary_shards}\n\n")
        
        self.update_results("   Utilization:\n")
        self.update_results(f"   💡 CPU Utilization: {cpu_utilization:.1f}%\n")
        self.update_results(f"   💡 Thread Pool Utilization: {thread_utilization:.1f}%\n\n")
        
        if cpu_utilization > 80 or thread_utilization > 75:
            self.update_results("   Recommendations:\n")
            if cpu_utilization > 80:
                self.update_results("   ⚠️  HIGH CPU UTILIZATION DETECTED!\n")
                self.update_results("      Consider scaling up cluster resources or optimizing indexing load.\n")
            if thread_utilization > 75:
                self.update_results("   ⚠️  HIGH THREAD POOL UTILIZATION!\n")
                self.update_results("      Consider increasing thread pool size or reducing concurrent operations.\n")
            self.update_results("\n")
        

    def _analyze_all_thread_pools(self):
        """Comprehensive thread pool analysis for all pool types"""
        self.update_results("🧵 COMPREHENSIVE THREAD POOL ANALYSIS:\n\n")
        
        try:
            # Get thread pool data
            thread_pool_cat = self.es.cat.thread_pool(h='node_name,name,active,queue,rejected,size,max', format='json')
            
            # Thread pools to monitor
            pool_types = ['search', 'get', 'bulk', 'write', 'management', 'flush', 'refresh', 'merge']
            
            overall_totals = {
                'active': 0,
                'queue': 0,
                'rejected': 0,
                'available': 0
            }
            
            for pool_type in pool_types:
                pools = [p for p in thread_pool_cat if p.get('name') == pool_type]
                
                if pools:
                    pool_totals = {'active': 0, 'queue': 0, 'rejected': 0, 'available': 0}
                    table_rows = []
                    
                    for pool in pools:
                        node_name = pool.get('node_name', 'Unknown')
                        active = int(pool.get('active', 0))
                        queue = int(pool.get('queue', 0))
                        size = pool.get('size', 'N/A')
                        rejected = int(pool.get('rejected', 0))
                        
                        pool_totals['active'] += active
                        pool_totals['queue'] += queue
                        pool_totals['rejected'] += rejected
                        
                        try:
                            if size and size != 'N/A':
                                pool_totals['available'] += int(size)
                        except:
                            pass
                        
                        table_rows.append([node_name, str(active), str(queue), str(size), str(rejected)])
                    
                    # Only display pools with activity or issues
                    if pool_totals['active'] > 0 or pool_totals['queue'] > 0 or pool_totals['rejected'] > 0:
                        headers = ['Node', 'Active', 'Queue', 'Size', 'Rejected']
                        self.update_results(self._format_table(
                            headers=headers,
                            rows=sorted(table_rows, key=lambda x: x[0]),
                            title=f"{pool_type.title()} Thread Pool"
                        ))
                        
                        # Pool-specific analysis
                        if pool_totals['available'] > 0:
                            utilization = (pool_totals['active'] / pool_totals['available']) * 100
                            if utilization > 80:
                                self.update_results(f"   ⚠️  High {pool_type} thread utilization: {utilization:.1f}%\n")
                        
                        if pool_totals['queue'] > 50:
                            self.update_results(f"   ⚠️  High {pool_type} queue length: {pool_totals['queue']}\n")
                        
                        if pool_totals['rejected'] > 0:
                            self.update_results(f"   ⚠️  {pool_type.title()} rejections: {pool_totals['rejected']}\n")
                        
                        self.update_results("\n")
                    
                    # Add to overall totals
                    for key in overall_totals:
                        overall_totals[key] += pool_totals[key]
            
            # Overall thread pool health summary
            self.update_results("   Thread Pool Health Summary:\n")
            self.update_results(f"   📊 Total Active Threads: {overall_totals['active']}\n")
            self.update_results(f"   📊 Total Queued Operations: {overall_totals['queue']}\n")
            self.update_results(f"   📊 Total Available Threads: {overall_totals['available']}\n")
            if overall_totals['rejected'] > 0:
                self.update_results(f"   ⚠️  Total Rejections: {overall_totals['rejected']}\n")
            
            overall_utilization = (overall_totals['active'] / overall_totals['available'] * 100) if overall_totals['available'] > 0 else 0
            health_status = "🟢 Good" if overall_utilization < 50 else "🟡 Moderate" if overall_utilization < 80 else "🔴 High"
            self.update_results(f"   {health_status} Overall Thread Pool Utilization: {overall_utilization:.1f}%\n\n")
            
        except Exception as e:
            self.update_results(f"   ⚠️  Could not retrieve thread pool info: {str(e)}\n\n")
    
    def _analyze_memory_and_gc(self):
        """Memory and garbage collection analysis"""
        self.update_results("🧠 MEMORY & GARBAGE COLLECTION ANALYSIS:\n\n")
        
        try:
            # Get JVM and memory stats
            jvm_stats = self.es.nodes.stats(metric=['jvm'])
            
            gc_summary = {
                'young_collections': 0,
                'young_time_ms': 0,
                'old_collections': 0,
                'old_time_ms': 0
            }
            
            memory_table_rows = []
            gc_table_rows = []
            
            for node_id, node_data in jvm_stats.get('nodes', {}).items():
                node_name = node_data.get('name', 'Unknown')
                jvm = node_data.get('jvm', {})
                
                # Memory analysis
                mem = jvm.get('mem', {})
                heap_used_percent = mem.get('heap_used_percent', 0)
                heap_max_mb = mem.get('heap_max_in_bytes', 0) / (1024 * 1024)
                heap_used_mb = mem.get('heap_used_in_bytes', 0) / (1024 * 1024)
                
                # Memory pools
                pools = mem.get('pools', {})
                old_gen = pools.get('old', {})
                old_gen_used_mb = old_gen.get('used_in_bytes', 0) / (1024 * 1024)
                old_gen_max_mb = old_gen.get('max_in_bytes', 1) / (1024 * 1024)
                old_gen_percent = (old_gen_used_mb / old_gen_max_mb * 100) if old_gen_max_mb > 0 else 0
                
                memory_table_rows.append([
                    node_name,
                    f"{heap_used_mb:.0f}MB",
                    f"{heap_max_mb:.0f}MB",
                    f"{heap_used_percent:.1f}%",
                    f"{old_gen_used_mb:.0f}MB",
                    f"{old_gen_percent:.1f}%"
                ])
                
                # GC analysis
                gc = jvm.get('gc', {})
                collectors = gc.get('collectors', {})
                
                young = collectors.get('young', {})
                old = collectors.get('old', {})
                
                young_count = young.get('collection_count', 0)
                young_time = young.get('collection_time_in_millis', 0)
                old_count = old.get('collection_count', 0)
                old_time = old.get('collection_time_in_millis', 0)
                
                gc_summary['young_collections'] += young_count
                gc_summary['young_time_ms'] += young_time
                gc_summary['old_collections'] += old_count
                gc_summary['old_time_ms'] += old_time
                
                # Calculate average GC times
                avg_young_gc = young_time / young_count if young_count > 0 else 0
                avg_old_gc = old_time / old_count if old_count > 0 else 0
                
                gc_table_rows.append([
                    node_name,
                    str(young_count),
                    f"{avg_young_gc:.1f}ms",
                    str(old_count),
                    f"{avg_old_gc:.1f}ms" if old_count > 0 else "0ms"
                ])
                
                # Memory pressure warnings
                if heap_used_percent > 85:
                    self.update_results(f"   ⚠️  High heap usage on {node_name}: {heap_used_percent:.1f}%\n")
                if old_gen_percent > 80:
                    self.update_results(f"   ⚠️  High old generation usage on {node_name}: {old_gen_percent:.1f}%\n")
            
            # Display memory table
            memory_headers = ['Node', 'Heap Used', 'Heap Max', 'Heap %', 'Old Gen Used', 'Old Gen %']
            self.update_results(self._format_table(
                headers=memory_headers,
                rows=memory_table_rows,
                title="Memory Utilization"
            ))
            
            # Display GC table
            gc_headers = ['Node', 'Young GCs', 'Avg Young', 'Old GCs', 'Avg Old']
            self.update_results(self._format_table(
                headers=gc_headers,
                rows=gc_table_rows,
                title="Garbage Collection Performance"
            ))
            
            # GC Health Assessment
            total_gc_time = gc_summary['young_time_ms'] + gc_summary['old_time_ms']
            total_collections = gc_summary['young_collections'] + gc_summary['old_collections']
            avg_gc_time = total_gc_time / total_collections if total_collections > 0 else 0
            
            self.update_results("   GC Performance Summary:\n")
            self.update_results(f"   📊 Total GC Collections: {total_collections:,}\n")
            self.update_results(f"   📊 Average GC Time: {avg_gc_time:.2f}ms\n")
            self.update_results(f"   📊 Total GC Time: {total_gc_time/1000:.1f}s\n")
            
            if avg_gc_time > 100:
                self.update_results("   ⚠️  High average GC pause times detected\n")
            if gc_summary['old_collections'] > gc_summary['young_collections'] * 0.1:
                self.update_results("   ⚠️  Frequent old generation GCs detected\n")
                
            self.update_results("\n")
            
        except Exception as e:
            self.update_results(f"   ⚠️  Could not retrieve memory/GC info: {str(e)}\n\n")
    
    def _analyze_search_performance(self):
        """Search performance and cache analysis"""
        self.update_results("🔍 SEARCH PERFORMANCE & CACHE ANALYSIS:\n\n")
        
        try:
            # Get search and cache statistics
            indices_stats = self.es.indices.stats(metric=['search', 'query_cache', 'fielddata', 'request_cache'])
            nodes_stats = self.es.nodes.stats(metric=['indices'])
            
            # Aggregate cache statistics
            total_cache_stats = {
                'query_cache_hits': 0,
                'query_cache_misses': 0,
                'fielddata_memory_bytes': 0,
                'request_cache_hits': 0,
                'request_cache_misses': 0
            }
            
            # Per-index cache analysis
            cache_table_rows = []
            
            for index_name, index_stats in indices_stats.get('indices', {}).items():
                total_stats = index_stats.get('total', {})
                
                # Query cache
                query_cache = total_stats.get('query_cache', {})
                qc_hits = query_cache.get('hit_count', 0)
                qc_misses = query_cache.get('miss_count', 0)
                qc_memory_mb = query_cache.get('memory_size_in_bytes', 0) / (1024 * 1024)
                
                # Field data cache
                fielddata = total_stats.get('fielddata', {})
                fd_memory_mb = fielddata.get('memory_size_in_bytes', 0) / (1024 * 1024)
                
                # Request cache
                request_cache = total_stats.get('request_cache', {})
                rc_hits = request_cache.get('hit_count', 0)
                rc_misses = request_cache.get('miss_count', 0)
                
                # Calculate cache hit rates
                qc_total = qc_hits + qc_misses
                qc_hit_rate = (qc_hits / qc_total * 100) if qc_total > 0 else 0
                
                rc_total = rc_hits + rc_misses
                rc_hit_rate = (rc_hits / rc_total * 100) if rc_total > 0 else 0
                
                # Only show indices with significant cache activity
                if qc_total > 1000 or rc_total > 1000 or fd_memory_mb > 10:
                    cache_table_rows.append([
                        index_name[:30],  # Truncate long index names
                        f"{qc_hit_rate:.1f}%" if qc_total > 0 else "N/A",
                        f"{rc_hit_rate:.1f}%" if rc_total > 0 else "N/A",
                        f"{qc_memory_mb:.1f}MB",
                        f"{fd_memory_mb:.1f}MB"
                    ])
                
                # Add to totals
                total_cache_stats['query_cache_hits'] += qc_hits
                total_cache_stats['query_cache_misses'] += qc_misses
                total_cache_stats['fielddata_memory_bytes'] += fielddata.get('memory_size_in_bytes', 0)
                total_cache_stats['request_cache_hits'] += rc_hits
                total_cache_stats['request_cache_misses'] += rc_misses
            
            # Display cache performance table
            if cache_table_rows:
                cache_headers = ['Index', 'Query Cache Hit %', 'Request Cache Hit %', 'Query Cache Mem', 'Field Data Mem']
                self.update_results(self._format_table(
                    headers=cache_headers,
                    rows=cache_table_rows,
                    title="Cache Performance by Index"
                ))
            
            # Node-level search performance
            search_table_rows = []
            total_search_stats = {
                'query_total': 0,
                'query_time_ms': 0,
                'fetch_total': 0,
                'fetch_time_ms': 0
            }
            
            for node_id, node_data in nodes_stats.get('nodes', {}).items():
                node_name = node_data.get('name', 'Unknown')
                indices = node_data.get('indices', {})
                search = indices.get('search', {})
                
                query_total = search.get('query_total', 0)
                query_time_ms = search.get('query_time_in_millis', 0)
                fetch_total = search.get('fetch_total', 0)
                fetch_time_ms = search.get('fetch_time_in_millis', 0)
                query_current = search.get('query_current', 0)
                
                # Calculate averages
                avg_query_latency = query_time_ms / query_total if query_total > 0 else 0
                avg_fetch_latency = fetch_time_ms / fetch_total if fetch_total > 0 else 0
                
                search_table_rows.append([
                    node_name,
                    f"{query_total:,}",
                    f"{avg_query_latency:.2f}ms",
                    f"{fetch_total:,}",
                    f"{avg_fetch_latency:.2f}ms",
                    str(query_current)
                ])
                
                # Add to totals
                total_search_stats['query_total'] += query_total
                total_search_stats['query_time_ms'] += query_time_ms
                total_search_stats['fetch_total'] += fetch_total
                total_search_stats['fetch_time_ms'] += fetch_time_ms
                
                # Performance warnings
                if avg_query_latency > 100:
                    self.update_results(f"   ⚠️  High query latency on {node_name}: {avg_query_latency:.2f}ms\n")
                if query_current > 10:
                    self.update_results(f"   ⚠️  High concurrent queries on {node_name}: {query_current}\n")
            
            # Display search performance table
            search_headers = ['Node', 'Total Queries', 'Avg Query Time', 'Total Fetches', 'Avg Fetch Time', 'Current']
            self.update_results(self._format_table(
                headers=search_headers,
                rows=search_table_rows,
                title="Search Performance by Node"
            ))
            
            # Overall cache and search summary
            self.update_results("   Search & Cache Summary:\n")
            
            # Cache hit rates
            total_qc = total_cache_stats['query_cache_hits'] + total_cache_stats['query_cache_misses']
            total_rc = total_cache_stats['request_cache_hits'] + total_cache_stats['request_cache_misses']
            
            qc_hit_rate = (total_cache_stats['query_cache_hits'] / total_qc * 100) if total_qc > 0 else 0
            rc_hit_rate = (total_cache_stats['request_cache_hits'] / total_rc * 100) if total_rc > 0 else 0
            
            self.update_results(f"   📊 Query Cache Hit Rate: {qc_hit_rate:.1f}%\n")
            self.update_results(f"   📊 Request Cache Hit Rate: {rc_hit_rate:.1f}%\n")
            self.update_results(f"   📊 Field Data Memory: {total_cache_stats['fielddata_memory_bytes'] / (1024 * 1024):.1f}MB\n")
            
            # Search performance summary
            avg_cluster_query_latency = total_search_stats['query_time_ms'] / total_search_stats['query_total'] if total_search_stats['query_total'] > 0 else 0
            self.update_results(f"   📊 Average Query Latency: {avg_cluster_query_latency:.2f}ms\n")
            self.update_results(f"   📊 Total Queries: {total_search_stats['query_total']:,}\n")
            
            # Performance recommendations
            if qc_hit_rate < 50 and total_qc > 1000:
                self.update_results("   ⚠️  Low query cache hit rate - consider query optimization\n")
            if rc_hit_rate < 80 and total_rc > 1000:
                self.update_results("   ⚠️  Low request cache hit rate - check request patterns\n")
            if avg_cluster_query_latency > 50:
                self.update_results("   ⚠️  High average query latency detected\n")
                
            self.update_results("\n")
            
        except Exception as e:
            self.update_results(f"   ⚠️  Could not retrieve search performance info: {str(e)}\n\n")
    
    def _analyze_io_performance(self):
        """I/O and disk performance analysis"""
        self.update_results("💾 I/O & DISK PERFORMANCE ANALYSIS:\n\n")
        
        try:
            # Get file system and transport stats
            fs_stats = self.es.nodes.stats(metric=['fs', 'transport'])
            
            disk_table_rows = []
            network_table_rows = []
            
            total_disk_stats = {
                'total_reads': 0,
                'total_writes': 0,
                'read_kb': 0,
                'write_kb': 0,
                'total_space_gb': 0,
                'available_space_gb': 0
            }
            
            for node_id, node_data in fs_stats.get('nodes', {}).items():
                node_name = node_data.get('name', 'Unknown')
                
                # File system analysis
                fs = node_data.get('fs', {})
                
                # Disk space analysis
                total_space_bytes = 0
                available_space_bytes = 0
                
                for data_path in fs.get('data', []):
                    total_space_bytes += data_path.get('total_in_bytes', 0)
                    available_space_bytes += data_path.get('available_in_bytes', 0)
                
                total_space_gb = total_space_bytes / (1024**3)
                available_space_gb = available_space_bytes / (1024**3)
                used_space_gb = total_space_gb - available_space_gb
                disk_used_percent = (used_space_gb / total_space_gb * 100) if total_space_gb > 0 else 0
                
                # I/O statistics
                io_stats = fs.get('io_stats', {})
                total_io = io_stats.get('total', {})
                
                read_ops = total_io.get('read_operations', 0)
                write_ops = total_io.get('write_operations', 0)
                read_kb = total_io.get('read_kilobytes', 0)
                write_kb = total_io.get('write_kilobytes', 0)
                
                disk_table_rows.append([
                    node_name,
                    f"{total_space_gb:.1f}GB",
                    f"{used_space_gb:.1f}GB",
                    f"{disk_used_percent:.1f}%",
                    f"{read_ops:,}" if read_ops > 0 else "N/A",
                    f"{write_ops:,}" if write_ops > 0 else "N/A",
                    f"{read_kb/1024:.1f}MB" if read_kb > 0 else "N/A",
                    f"{write_kb/1024:.1f}MB" if write_kb > 0 else "N/A"
                ])
                
                # Add to totals
                total_disk_stats['total_reads'] += read_ops
                total_disk_stats['total_writes'] += write_ops
                total_disk_stats['read_kb'] += read_kb
                total_disk_stats['write_kb'] += write_kb
                total_disk_stats['total_space_gb'] += total_space_gb
                total_disk_stats['available_space_gb'] += available_space_gb
                
                # Disk warnings
                if disk_used_percent > 85:
                    self.update_results(f"   ⚠️  High disk usage on {node_name}: {disk_used_percent:.1f}%\n")
                if available_space_gb < 10:  # Less than 10GB free
                    self.update_results(f"   ⚠️  Low disk space on {node_name}: {available_space_gb:.1f}GB remaining\n")
                
                # Network transport analysis
                transport = node_data.get('transport', {})
                
                rx_count = transport.get('rx_count', 0)
                tx_count = transport.get('tx_count', 0)
                rx_size_mb = transport.get('rx_size_in_bytes', 0) / (1024 * 1024)
                tx_size_mb = transport.get('tx_size_in_bytes', 0) / (1024 * 1024)
                server_open = transport.get('server_open', 0)
                
                network_table_rows.append([
                    node_name,
                    f"{rx_count:,}",
                    f"{tx_count:,}",
                    f"{rx_size_mb:.1f}MB",
                    f"{tx_size_mb:.1f}MB",
                    str(server_open)
                ])
            
            # Display disk performance table
            disk_headers = ['Node', 'Total Space', 'Used Space', 'Usage %', 'Read Ops', 'Write Ops', 'Read Data', 'Write Data']
            self.update_results(self._format_table(
                headers=disk_headers,
                rows=disk_table_rows,
                title="Disk Usage and I/O Performance"
            ))
            
            # Display network performance table
            network_headers = ['Node', 'RX Count', 'TX Count', 'RX Data', 'TX Data', 'Connections']
            self.update_results(self._format_table(
                headers=network_headers,
                rows=network_table_rows,
                title="Network Transport Performance"
            ))
            
            # I/O and disk summary
            self.update_results("   I/O & Storage Summary:\n")
            cluster_used_percent = ((total_disk_stats['total_space_gb'] - total_disk_stats['available_space_gb']) / total_disk_stats['total_space_gb'] * 100) if total_disk_stats['total_space_gb'] > 0 else 0
            
            self.update_results(f"   📊 Total Cluster Storage: {total_disk_stats['total_space_gb']:.1f}GB\n")
            self.update_results(f"   📊 Available Storage: {total_disk_stats['available_space_gb']:.1f}GB\n")
            self.update_results(f"   📊 Cluster Storage Usage: {cluster_used_percent:.1f}%\n")
            
            if total_disk_stats['total_reads'] > 0:
                self.update_results(f"   📊 Total Disk Reads: {total_disk_stats['total_reads']:,}\n")
                self.update_results(f"   📊 Total Read Data: {total_disk_stats['read_kb']/1024:.1f}MB\n")
            
            if total_disk_stats['total_writes'] > 0:
                self.update_results(f"   📊 Total Disk Writes: {total_disk_stats['total_writes']:,}\n")
                self.update_results(f"   📊 Total Write Data: {total_disk_stats['write_kb']/1024:.1f}MB\n")
            
            # Storage health assessment
            if cluster_used_percent > 80:
                self.update_results("   ⚠️  High cluster storage utilization\n")
            if total_disk_stats['available_space_gb'] < 50:  # Less than 50GB cluster-wide
                self.update_results("   ⚠️  Low available storage space\n")
                
            self.update_results("\n")
            
        except Exception as e:
            self.update_results(f"   ⚠️  Could not retrieve I/O performance info: {str(e)}\n\n")

    def _analyze_index_operations(self):
        """Index operation performance analysis"""
        self.update_results("📝 INDEX OPERATIONS ANALYSIS:\n\n")
        
        try:
            # Get index-level statistics
            indices_stats = self.es.indices.stats(metric=['indexing', 'refresh', 'merge', 'flush'])
            
            # Aggregate statistics
            indexing_table_rows = []
            operations_table_rows = []
            
            total_indexing_stats = {
                'index_total': 0,
                'index_time_ms': 0,
                'delete_total': 0,
                'delete_time_ms': 0,
                'refresh_total': 0,
                'refresh_time_ms': 0,
                'merge_total': 0,
                'merge_time_ms': 0,
                'flush_total': 0,
                'flush_time_ms': 0
            }
            
            # Analyze per-index performance
            for index_name, index_stats in indices_stats.get('indices', {}).items():
                total_stats = index_stats.get('total', {})
                
                # Indexing stats
                indexing = total_stats.get('indexing', {})
                index_total = indexing.get('index_total', 0)
                index_time_ms = indexing.get('index_time_in_millis', 0)
                delete_total = indexing.get('delete_total', 0)
                delete_time_ms = indexing.get('delete_time_in_millis', 0)
                index_current = indexing.get('index_current', 0)
                
                # Operation stats
                refresh = total_stats.get('refresh', {})
                refresh_total = refresh.get('total', 0)
                refresh_time_ms = refresh.get('total_time_in_millis', 0)
                
                merge = total_stats.get('merge', {})
                merge_total = merge.get('total', 0)
                merge_time_ms = merge.get('total_time_in_millis', 0)
                merge_current = merge.get('current', 0)
                
                flush = total_stats.get('flush', {})
                flush_total = flush.get('total', 0)
                flush_time_ms = flush.get('total_time_in_millis', 0)
                
                # Calculate all averages unconditionally to prevent UnboundLocalError
                avg_index_time = index_time_ms / index_total if index_total > 0 else 0
                avg_delete_time = delete_time_ms / delete_total if delete_total > 0 else 0
                avg_refresh_time = refresh_time_ms / refresh_total if refresh_total > 0 else 0
                avg_merge_time = merge_time_ms / merge_total if merge_total > 0 else 0
                avg_flush_time = flush_time_ms / flush_total if flush_total > 0 else 0

                # Only show indices with significant activity in the table
                if index_total > 1000 or delete_total > 100 or index_current > 0:
                    indexing_table_rows.append([
                        index_name[:25],  # Truncate long names
                        f"{index_total:,}",
                        f"{avg_index_time:.2f}ms",
                        f"{delete_total:,}",
                        f"{avg_delete_time:.2f}ms" if delete_total > 0 else "N/A",
                        str(index_current)
                    ])
                
                # Show operation performance for active indices
                if refresh_total > 0 or merge_total > 0 or flush_total > 0:
                    operations_table_rows.append([
                        index_name[:25],
                        f"{refresh_total:,}",
                        f"{avg_refresh_time:.2f}ms" if refresh_total > 0 else "N/A",
                        f"{merge_total:,}",
                        f"{avg_merge_time:.2f}ms" if merge_total > 0 else "N/A",
                        str(merge_current)
                    ])
                
                # Add to totals
                total_indexing_stats['index_total'] += index_total
                total_indexing_stats['index_time_ms'] += index_time_ms
                total_indexing_stats['delete_total'] += delete_total
                total_indexing_stats['delete_time_ms'] += delete_time_ms
                total_indexing_stats['refresh_total'] += refresh_total
                total_indexing_stats['refresh_time_ms'] += refresh_time_ms
                total_indexing_stats['merge_total'] += merge_total
                total_indexing_stats['merge_time_ms'] += merge_time_ms
                total_indexing_stats['flush_total'] += flush_total
                total_indexing_stats['flush_time_ms'] += flush_time_ms
                
                # Performance warnings (now safe to call)
                if avg_index_time > 50:
                    self.update_results(f"   ⚠️  High indexing latency in {index_name[:20]}: {avg_index_time:.2f}ms\n")
                if merge_current > 2:
                    self.update_results(f"   ⚠️  High concurrent merges in {index_name[:20]}: {merge_current}\n")
                if avg_merge_time > 1000:  # > 1 second
                    self.update_results(f"   ⚠️  Slow merge operations in {index_name[:20]}: {avg_merge_time:.2f}ms\n")
            
            # Display indexing performance table
            if indexing_table_rows:
                indexing_headers = ['Index', 'Index Ops', 'Avg Index Time', 'Delete Ops', 'Avg Delete Time', 'Current']
                self.update_results(self._format_table(
                    headers=indexing_headers,
                    rows=indexing_table_rows,
                    title="Indexing Performance by Index"
                ))
            
            # Display operations performance table
            if operations_table_rows:
                ops_headers = ['Index', 'Refresh Ops', 'Avg Refresh', 'Merge Ops', 'Avg Merge', 'Current Merges']
                self.update_results(self._format_table(
                    headers=ops_headers,
                    rows=operations_table_rows,
                    title="Index Operations Performance"
                ))
            
            # Overall index operations summary
            self.update_results("   Index Operations Summary:\n")
            
            # Calculate averages
            avg_index_latency = total_indexing_stats['index_time_ms'] / total_indexing_stats['index_total'] if total_indexing_stats['index_total'] > 0 else 0
            avg_refresh_latency = total_indexing_stats['refresh_time_ms'] / total_indexing_stats['refresh_total'] if total_indexing_stats['refresh_total'] > 0 else 0
            avg_merge_latency = total_indexing_stats['merge_time_ms'] / total_indexing_stats['merge_total'] if total_indexing_stats['merge_total'] > 0 else 0
            
            self.update_results(f"   📊 Total Index Operations: {total_indexing_stats['index_total']:,}\n")
            self.update_results(f"   📊 Average Index Latency: {avg_index_latency:.2f}ms\n")
            self.update_results(f"   📊 Total Refresh Operations: {total_indexing_stats['refresh_total']:,}\n")
            self.update_results(f"   📊 Average Refresh Latency: {avg_refresh_latency:.2f}ms\n")
            self.update_results(f"   📊 Total Merge Operations: {total_indexing_stats['merge_total']:,}\n")
            
            if total_indexing_stats['merge_total'] > 0:
                self.update_results(f"   📊 Average Merge Latency: {avg_merge_latency:.2f}ms\n")
            
            # Performance recommendations
            if avg_index_latency > 20:
                self.update_results("   ⚠️  High average indexing latency - consider optimizing mapping or bulk sizes\n")
            if avg_refresh_latency > 100:
                self.update_results("   ⚠️  Slow refresh operations - consider adjusting refresh intervals\n")
            if avg_merge_latency > 500:
                self.update_results("   ⚠️  Slow merge operations - check segment optimization settings\n")
                
            self.update_results("\n")
            
        except Exception as e:
            self.update_results(f"   ⚠️  Could not retrieve index operations info: {str(e)}\n\n")

    def _analyze_segments_and_allocation(self):
        """Segment and allocation analysis"""
        self.update_results("🔧 SEGMENTS & ALLOCATION ANALYSIS:\n\n")
        
        try:
            # Get segment and allocation information
            segments_stats = self.es.indices.segments()
            allocation_info = self.es.cat.allocation(h='node,shards,disk.indices,disk.used,disk.avail,disk.total,disk.percent', format='json')
            
            # Analyze segments by index
            segment_table_rows = []
            total_segments = 0
            total_segment_memory = 0
            
            for index_name, index_data in segments_stats.get('indices', {}).items():
                shards = index_data.get('shards', {})
                index_segments = 0
                index_memory_bytes = 0
                max_segment_size = 0
                
                for shard_id, shard_data in shards.items():
                    for segment_data in shard_data:
                        segments = segment_data.get('segments', {})
                        for segment_name, segment_info in segments.items():
                            index_segments += 1
                            segment_size = segment_info.get('size_in_bytes', 0)
                            index_memory_bytes += segment_info.get('memory_in_bytes', 0)
                            max_segment_size = max(max_segment_size, segment_size)
                
                if index_segments > 0:
                    segment_table_rows.append([
                        index_name[:25],
                        str(index_segments),
                        f"{index_memory_bytes / (1024 * 1024):.1f}MB",
                        f"{max_segment_size / (1024 * 1024):.1f}MB"
                    ])
                    
                    total_segments += index_segments
                    total_segment_memory += index_memory_bytes
                    
                    # Segment warnings
                    if index_segments > 100:
                        self.update_results(f"   ⚠️  High segment count in {index_name[:20]}: {index_segments}\n")
                    if max_segment_size > 5 * 1024 * 1024 * 1024:  # > 5GB
                        self.update_results(f"   ⚠️  Large segment detected in {index_name[:20]}: {max_segment_size / (1024**3):.1f}GB\n")
            
            # Display segments table
            if segment_table_rows:
                segment_headers = ['Index', 'Segments', 'Memory Usage', 'Largest Segment']
                self.update_results(self._format_table(
                    headers=segment_headers,
                    rows=sorted(segment_table_rows, key=lambda x: int(x[1]), reverse=True)[:20],  # Top 20
                    title="Segment Analysis (Top 20 by Count)"
                ))
            
            # Analyze shard allocation
            allocation_table_rows = []
            total_shards = 0
            total_disk_used = 0
            total_disk_available = 0
            
            for node_data in allocation_info:
                node_name = node_data.get('node', 'Unknown')
                shards_count = int(node_data.get('shards', 0))
                disk_used = node_data.get('disk.used', '0b')
                disk_avail = node_data.get('disk.avail', '0b')
                disk_total = node_data.get('disk.total', '0b')
                disk_percent = float(node_data.get('disk.percent', 0))
                
                allocation_table_rows.append([
                    node_name,
                    str(shards_count),
                    disk_used,
                    disk_avail,
                    f"{disk_percent:.1f}%"
                ])
                
                total_shards += shards_count
                # Convert disk sizes to bytes for calculation
                try:
                    disk_used_bytes = self._parse_size_to_gb(disk_used) * 1024**3
                    disk_avail_bytes = self._parse_size_to_gb(disk_avail) * 1024**3
                    total_disk_used += disk_used_bytes
                    total_disk_available += disk_avail_bytes
                except:
                    pass
                
                # Allocation warnings
                if shards_count > 1000:
                    self.update_results(f"   ⚠️  High shard count on {node_name}: {shards_count}\n")
                if disk_percent > 85:
                    self.update_results(f"   ⚠️  High disk usage on {node_name}: {disk_percent:.1f}%\n")
            
            # Display allocation table
            allocation_headers = ['Node', 'Shards', 'Disk Used', 'Disk Available', 'Usage %']
            self.update_results(self._format_table(
                headers=allocation_headers,
                rows=allocation_table_rows,
                title="Shard Allocation by Node"
            ))
            
            # Segments and allocation summary
            self.update_results("   Segments & Allocation Summary:\n")
            self.update_results(f"   📊 Total Segments: {total_segments:,}\n")
            self.update_results(f"   📊 Total Segment Memory: {total_segment_memory / (1024 * 1024):.1f}MB\n")
            self.update_results(f"   📊 Total Shards: {total_shards}\n")
            
            # Calculate average segments per index
            num_indices = len([r for r in segment_table_rows if int(r[1]) > 0])
            avg_segments_per_index = total_segments / num_indices if num_indices > 0 else 0
            self.update_results(f"   📊 Average Segments per Index: {avg_segments_per_index:.1f}\n")
            
            # Health recommendations
            if avg_segments_per_index > 50:
                self.update_results("   ⚠️  High average segments per index - consider force merge operations\n")
            if total_segment_memory > 1024 * 1024 * 1024:  # > 1GB
                self.update_results("   ⚠️  High segment memory usage - monitor heap pressure\n")
            if total_shards > total_segments * 0.8:  # Many shards relative to segments
                self.update_results("   ⚠️  High shard-to-segment ratio - consider index optimization\n")
                
            self.update_results("\n")
            
        except Exception as e:
            self.update_results(f"   ⚠️  Could not retrieve segments/allocation info: {str(e)}\n\n")

    def _analyze_hot_threads(self):
        """Hot threads analysis for bottleneck detection"""
        self.update_results("🔥 HOT THREADS ANALYSIS:\n\n")
        
        try:
            # Get hot threads information
            hot_threads = self.es.nodes.hot_threads(threads=5, interval='500ms', snapshots=3)
            
            # Parse hot threads output
            thread_analysis = {
                'cpu_intensive': [],
                'blocked_threads': [],
                'gc_threads': [],
                'search_threads': [],
                'indexing_threads': []
            }
            
            # Analyze the hot threads text
            if isinstance(hot_threads, str):
                lines = hot_threads.split('\n')
                current_node = None
                current_thread = None
                current_cpu = 0
                
                for line in lines:
                    line = line.strip()
                    
                    # Detect node sections
                    if 'Hot threads at' in line and 'node' in line:
                        # Extract node name from line like "::: Hot threads at 2024-01-01T00:00:00.000Z, interval=500ms, busiestThreads=5, ignoreIdleThreads=true, type=cpu ::: [node-name][transport_address] hot_threads"
                        try:
                            current_node = line.split('[')[1].split(']')[0]
                        except:
                            current_node = "Unknown"
                        continue
                    
                    # Detect thread information
                    if '% of cpu usage' in line:
                        try:
                            current_cpu = float(line.split('%')[0].strip())
                            # Extract thread name/type
                            if 'elasticsearch' in line:
                                thread_parts = line.split('elasticsearch[')[1].split(']')
                                if len(thread_parts) > 1:
                                    current_thread = thread_parts[1].strip().split()[0]
                        except:
                            current_cpu = 0
                    
                    # Categorize threads based on names and stack traces
                    if current_thread and current_cpu > 0:
                        thread_info = {
                            'node': current_node,
                            'thread': current_thread,
                            'cpu': current_cpu,
                            'stack_sample': line if 'at ' in line else ''
                        }
                        
                        # Categorize by thread type and activity
                        if current_cpu > 10:
                            thread_analysis['cpu_intensive'].append(thread_info)
                        
                        if 'search' in current_thread.lower() or 'query' in line.lower():
                            thread_analysis['search_threads'].append(thread_info)
                        elif 'bulk' in current_thread.lower() or 'index' in current_thread.lower():
                            thread_analysis['indexing_threads'].append(thread_info)
                        elif 'gc' in line.lower() or 'garbage' in line.lower():
                            thread_analysis['gc_threads'].append(thread_info)
                        elif 'blocked' in line.lower() or 'waiting' in line.lower():
                            thread_analysis['blocked_threads'].append(thread_info)
            
            # Generate summary tables for each category
            categories = [
                ('🔥 CPU Intensive Threads', 'cpu_intensive'),
                ('🔍 Search-Related Threads', 'search_threads'),
                ('📝 Indexing-Related Threads', 'indexing_threads'),
                ('🗑️ Garbage Collection Threads', 'gc_threads'),
                ('⏸️ Blocked Threads', 'blocked_threads')
            ]
            
            total_hot_threads = 0
            high_cpu_nodes = set()
            
            for category_name, category_key in categories:
                threads = thread_analysis[category_key]
                if threads:
                    self.update_results(f"   {category_name}:\n")
                    
                    # Aggregate by node
                    node_summary = {}
                    for thread in threads:
                        node = thread['node']
                        if node not in node_summary:
                            node_summary[node] = {
                                'thread_count': 0,
                                'total_cpu': 0,
                                'max_cpu': 0,
                                'thread_types': set()
                            }
                        
                        node_summary[node]['thread_count'] += 1
                        node_summary[node]['total_cpu'] += thread['cpu']
                        node_summary[node]['max_cpu'] = max(node_summary[node]['max_cpu'], thread['cpu'])
                        node_summary[node]['thread_types'].add(thread['thread'])
                        
                        total_hot_threads += 1
                        if thread['cpu'] > 15:
                            high_cpu_nodes.add(node)
                    
                    # Display node summary
                    for node, summary in node_summary.items():
                        avg_cpu = summary['total_cpu'] / summary['thread_count']
                        thread_types = ', '.join(list(summary['thread_types'])[:3])  # Show up to 3 types
                        
                        self.update_results(f"      {node}: {summary['thread_count']} threads, "
                                          f"avg {avg_cpu:.1f}% CPU (max {summary['max_cpu']:.1f}%), "
                                          f"types: {thread_types}\n")
                    
                    self.update_results("\n")
            
            # Overall hot threads summary
            self.update_results("   Hot Threads Summary:\n")
            self.update_results(f"   📊 Total Hot Threads Detected: {total_hot_threads}\n")
            
            if high_cpu_nodes:
                self.update_results(f"   📊 Nodes with High CPU Threads: {len(high_cpu_nodes)}\n")
                for node in sorted(high_cpu_nodes):
                    self.update_results(f"      • {node}\n")
            
            # Performance recommendations based on hot threads
            if thread_analysis['cpu_intensive']:
                self.update_results("   ⚠️  High CPU thread activity detected - monitor cluster load\n")
            
            if thread_analysis['search_threads']:
                self.update_results("   ⚠️  Search-related hot threads - consider query optimization\n")
            
            if thread_analysis['indexing_threads']:
                self.update_results("   ⚠️  Indexing-related hot threads - monitor bulk operation sizes\n")
            
            if thread_analysis['blocked_threads']:
                self.update_results("   ⚠️  Blocked threads detected - check for resource contention\n")
            
            if thread_analysis['gc_threads']:
                self.update_results("   ⚠️  GC-related hot threads - monitor heap usage and GC patterns\n")
            
            if not total_hot_threads:
                self.update_results("   ✅ No significant hot threads detected - cluster performance is stable\n")
                
            self.update_results("\n")
            
        except Exception as e:
            self.update_results(f"   ⚠️  Could not retrieve hot threads info: {str(e)}\n\n")

    def _analyze_shard_distribution(self):
        """Analyze shard distribution and index groupings"""
        self.update_results("🔍 SHARD DISTRIBUTION ANALYSIS:\n\n")
        try:
            shards_info = self.es.cat.shards(h='index,shard,prirep,node,state,docs,store', format='json')
            
            primary_shards = [s for s in shards_info if s.get('prirep') == 'p']
            replica_shards = [s for s in shards_info if s.get('prirep') == 'r']
            
            index_stats = {}
            for shard in primary_shards:
                index = shard.get('index', 'Unknown')
                if index not in index_stats:
                    index_stats[index] = {'shards': 0, 'docs': 0, 'size': '0b', 'state': 'green'}
                index_stats[index]['shards'] += 1
                try:
                    index_stats[index]['docs'] += int(shard.get('docs', '0') or '0')
                    current_size_gb = self._parse_size_to_gb(shard.get('store', '0b'))
                    if current_size_gb > self._parse_size_to_gb(index_stats[index]['size']):
                        index_stats[index]['size'] = shard.get('store', '0b')
                    if shard.get('state', '') != 'STARTED':
                        index_stats[index]['state'] = 'red'
                except (ValueError, TypeError):
                    pass

            total_indices = len(index_stats)
            total_docs = sum(stats['docs'] for stats in index_stats.values())

            # Add overall summary
            self.update_results("   Cluster Shard Summary:\n")
            self.update_results(f"   📈 Total Indices: {total_indices}\n")
            self.update_results(f"   📈 Total Primary Shards: {len(primary_shards)}\n")
            self.update_results(f"   📈 Total Replica Shards: {len(replica_shards)}\n")
            self.update_results(f"   📈 Total Documents: {total_docs:,}\n")
            
            unassigned_shards = sum(1 for s in shards_info if s.get('state', '') != 'STARTED')
            if unassigned_shards > 0:
                self.update_results(f"   ⚠️  Warning: {unassigned_shards} unassigned shards detected\n")
            self.update_results("\n")
            
        except Exception as e:
            self.update_results(f"   ⚠️  Could not analyze shard distribution: {str(e)}\n\n")
            
    def _analyze_indexing_delta(self):
        """Automated delta check for current indexing activity"""
        self.update_results("📝 CURRENT INDEXING ACTIVITY (DELTA CHECK):\n")
        try:
            self.update_results("   Gathering baseline indexing stats...\n")
            baseline_stats = self.es.cat.indices(
                h='index,pri.indexing.index_total', format='json'
            )
            
            self.update_results("   Waiting 10 seconds to check for new activity...\n")
            time.sleep(10)
            
            self.update_results("   Gathering final indexing stats...\n")
            final_stats = self.es.cat.indices(
                h='index,pri.indexing.index_total', format='json'
            )
            
            baseline_totals = {i['index']: int(i.get('pri.indexing.index_total', '0') or '0') for i in baseline_stats}
            final_totals = {i['index']: int(i.get('pri.indexing.index_total', '0') or '0') for i in final_stats}

            active_indices = []
            for index, final_total in final_totals.items():
                baseline_total = baseline_totals.get(index, 0)
                if final_total > baseline_total:
                    change = final_total - baseline_total
                    self.update_results(f"   ✅ Indexing detected in {index} (+{change:,} ops)\n")
                    active_indices.append(index)

            if not active_indices:
                self.update_results("   ⚠️  NO ACTIVE INDEXING DETECTED in the last 10 seconds.\n")
            else:
                self.update_results(f"   📈 ACTIVE INDICES (DELTA CHECK): {len(active_indices)}\n")
            self.update_results("\n")

        except Exception as e:
            self.update_results(f"   ⚠️  Could not retrieve indexing delta stats: {str(e)}\n\n")

    def _parse_to_sections(self, results):
        """Parse analysis results into structured sections"""
        sections = {
            'overview': {'title': 'Cluster Overview', 'content': []},
            'pipeline': {'title': 'Pipeline Performance', 'content': []},
            'node': {'title': 'Node Resources', 'content': []},
            'threads': {'title': 'Thread Pools', 'content': []},
            'memory': {'title': 'Memory & GC', 'content': []},
            'search': {'title': 'Search & Cache', 'content': []},
            'io': {'title': 'I/O & Disk', 'content': []},
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
            'search': '🔍 SEARCH PERFORMANCE & CACHE ANALYSIS',
            'io': '💾 I/O & DISK PERFORMANCE ANALYSIS',
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
        tab_order = ['overview', 'pipeline', 'node', 'threads', 'memory', 'search', 'io', 'indexing', 'indexing_delta', 'segments', 'hotthreads', 'shards']
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
        tab_order = ['overview', 'pipeline', 'node', 'threads', 'memory', 'search', 'io', 'indexing', 'indexing_delta', 'segments', 'hotthreads', 'shards']
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

        # First pass: Group lines into logical blocks (table, metric, text, etc.)
        for line in content_lines:
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

            # If line type changes, save previous block and start a new one
            if line_type != current_block_type and current_block_lines:
                blocks.append({'type': current_block_type, 'lines': current_block_lines})
                current_block_lines = []
            
            current_block_type = line_type
            current_block_lines.append(line)

        # Append the last remaining block
        if current_block_lines:
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
                
                .warning, .success {{
                    padding: 15px 20px; border-radius: 8px; margin: 10px 0; font-size: 14px; font-weight: 500;
                }}
                .warning {{
                    background: #fff1f2; border-left: 4px solid #ef4444; color: #9f1239;
                }}
                .success {{
                    background: #f0fdf4; border-left: 4px solid #22c55e; color: #15803d;
                }}
            </style>
            <script>
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
            "🎯": "&#127919;"
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
            
    def export_results_to_json(self):
        """Export analysis results to a JSON file"""
        results_text = self.results_text.get(1.0, tk.END).strip()
        if not results_text:
            messagebox.showwarning("No Data", "No analysis results to export.")
            return

        try:
            # Parse the text into sections, which is already done for HTML generation
            parsed_data = self._parse_to_sections(results_text)
            
            # Create a clean dictionary for export, joining content lines
            export_data = {}
            for key, value in parsed_data.items():
                export_data[key] = {
                    'title': value['title'],
                    'content': "\n".join(value['content'])
                }

            filepath = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Save Analysis Report as JSON"
            )
            
            if not filepath:
                return  # User cancelled the save dialog
                
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=4)
                
            messagebox.showinfo("Export Successful", f"Analysis report successfully saved to:\n{filepath}")

        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results to JSON: {str(e)}")
    
    def update_results(self, text):
        """Update results text widget (thread-safe)"""
        def update():
            self.results_text.insert(tk.END, text)
            self.results_text.see(tk.END)
            # Enable browser button when there's content
            if self.results_text.get(1.0, tk.END).strip():
                self.browser_btn.config(state=tk.NORMAL)
                self.export_btn.config(state=tk.NORMAL)
        self.root.after(0, update)
    
    def clear_results(self):
        """Clear the results text widget"""
        self.results_text.delete(1.0, tk.END)
        self.browser_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.DISABLED)

def main():
    root = tk.Tk()
    app = ElasticsearchAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
