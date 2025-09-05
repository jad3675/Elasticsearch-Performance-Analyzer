# Elasticsearch Cluster Resource Analyzer

## 1. Overview

The Elasticsearch Cluster Resource Analyzer is a desktop application designed for developers, DevOps engineers, and Elasticsearch administrators. It provides a comprehensive, at-a-glance analysis of an Elasticsearch cluster's health and performance.

The tool connects securely to both **Elastic Cloud** and **self-hosted** Elasticsearch instances, performs a wide array of diagnostic checks, and presents the findings in a user-friendly GUI. For deeper analysis and sharing, it generates a sophisticated, self-contained HTML report and allows for data export to JSON.

Its primary goal is to accelerate the troubleshooting process by consolidating critical performance metrics into a single, easy-to-digest interface, helping users quickly identify bottlenecks, resource saturation, and misconfigurations.

---

## 2. Features

-   **Flexible Connection Options**:
    -   Connect to **Elastic Cloud** using a Cloud ID.
    -   Connect to **self-hosted** or local clusters using a direct URL.
    -   Supports **API Key** (both Base64 encoded and `id:secret` format) and **Basic Authentication** (username/password).
    -   Option to enable/disable SSL certificate verification.

-   **Comprehensive Analysis Modules**:
    -   **Cluster Overview**: General health, status, versioning, and shard statistics.
    -   **Node Resources**: CPU, RAM, Heap, and load metrics for each node.
    -   **Thread Pool Analysis**: In-depth review of all major thread pools (`search`, `write`, `bulk`, etc.) to detect queuing and rejections.
    -   **Memory & GC Analysis**: Heap usage, old generation pressure, and garbage collection frequency/duration.
    -   **Search Performance & Caching**: Query latency, fetch times, and cache hit/miss rates.
    -   **I/O & Disk Performance**: Disk usage, read/write operations, and network transport statistics.
    -   **Index Operations**: Performance of indexing, refresh, merge, and flush operations.
    -   **Segments & Allocation**: Segment count, memory usage, and shard distribution across nodes.
    -   **Hot Threads Analysis**: Identifies CPU-intensive threads to pinpoint performance bottlenecks.
    -   **Live Indexing Delta Check**: Performs a 10-second check to identify actively indexing shards.

-   **Rich Reporting & Exporting**:
    -   **Interactive GUI**: View results directly within the application's scrollable text area.
    -   **Modern HTML Report**: Generates a professional, single-file HTML report with a side-navigation menu for easy exploration of analysis sections. The report is fully self-contained (CSS/JS embedded) for maximum portability.
    -   **JSON Export**: Save the full analysis data in a structured JSON format for programmatic access or integration with other tools.

---

## 3. How to Use

1.  **Prerequisites**: Ensure you have the necessary Python library installed:
    ```bash
    pip install elasticsearch
    ```

2.  **Run the Application**: Execute the Python script from your terminal:
    ```bash
    python es_cluster_perf_analyzer.py
    ```

3.  **Configure Connection**:
    -   **Connection Type**: Select "Cloud ID" for Elastic Cloud or "URL" for self-hosted instances.
    -   **Authentication Type**: Select "API Key" or "Basic Auth".
    -   Fill in the required credentials based on your selections.

4.  **Analyze**:
    -   Click the **"Connect & Analyze"** button. The application will connect to the cluster and run all analysis modules. The process may take 15-30 seconds, during which the UI will remain responsive.

5.  **Review Results**:
    -   Results will stream into the "Analysis Results" text area in the GUI.
    -   Click **"Open in Browser"** to view the interactive HTML report.
    -   Click **"Export to JSON"** to save the results to a file.
    -   Click **"Clear Results"** to clear the display for a new analysis.

---


## 4. Data Collection & Analysis Methodology

The selection of metrics was guided by a "top-down" diagnostic approach, starting with a high-level cluster overview and progressively drilling down into more granular subsystems. The goal is to provide a holistic view of the cluster's state by correlating data from different components.

-   **Why these modules?** The modules were chosen to cover the entire lifecycle of a request in Elasticsearch and the core subsystems that support it:
    1.  **Cluster & Node Health (`/`, `_cluster/health`, `_nodes`)**: This is the foundation. Without a healthy cluster and stable nodes, no other metric matters. It answers the question: "Is the cluster online and are all nodes participating?"
    2.  **JVM Memory & GC (`_nodes/stats`)**: Elasticsearch is a Java application, making JVM health paramount. High heap usage and frequent or long garbage collection pauses are the most common causes of performance degradation. This module helps detect memory pressure before it leads to cascading failures.
    3.  **Thread Pools (`_cat/thread_pool`)**: Thread pools are the workers of Elasticsearch. Queued or rejected tasks in pools like `search` or `write` are direct indicators of resource saturation. Monitoring all major pools provides a clear picture of what kind of workload is overwhelming the cluster.
    4.  **Indexing & Search Performance (`_indices/stats`, `_nodes/stats`)**: These modules inspect the performance of the two primary workloads: writing and reading data. Metrics like indexing latency, query times, and cache efficiency are crucial for application-level performance tuning.
    5.  **I/O and Disk (`_nodes/stats`)**: Ultimately, data is read from and written to disk. This module checks for I/O bottlenecks and monitors disk space, a critical resource that can bring a cluster to a halt if exhausted.
    6.  **Shards, Segments & Merges (`_cat/shards`, `_indices/segments`)**: The health of the underlying Lucene segments and the distribution of shards are vital for long-term performance and stability. High segment counts can degrade search performance, while imbalanced shard allocation can lead to hot spots on specific nodes.
    7.  **Hot Threads (`_nodes/hot_threads`)**: When all else fails, the `hot_threads` API provides a direct look at what the CPU is spending its time on. It's an invaluable tool for diagnosing deep, complex issues like inefficient script execution, stuck loops, or lock contention that other metrics might not reveal.

-   **API Endpoints**: The tool relies on a combination of the more structured `_nodes/stats` and `_indices/stats` APIs for detailed metrics, and the `_cat` APIs for concise, human-readable summaries that are ideal for table views. This hybrid approach allows for both deep analysis and quick overviews.
