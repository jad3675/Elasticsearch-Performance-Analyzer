# Elasticsearch Performance Analyzer

## 1. Overview

The Elasticsearch Performance Analyzer is a desktop application designed for developers, DevOps engineers, and Elasticsearch administrators. It provides a comprehensive, at-a-glance analysis of an Elasticsearch cluster's health and performance.

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
    -   **Circuit Breakers**: Monitors for tripped breakers to prevent node instability.
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
    -   **CLI Support**: Run the analyzer from the command line and export results directly.

---

## 3. Project Structure

This repository contains two versions of the application:

-   **`analyzer/` (Recommended)**: The modern, modular version of the application. It is structured as a Python package, which makes it more maintainable, extensible, and easier to integrate into automated workflows. The main entry point is `analyzer/main.py`.
-   **`es_cluster_perf_analyzer.py` (Legacy)**: The original, monolithic script. It is a self-contained script that provides the same functionality but is no longer under active development. It is preserved for reference and backward compatibility.

---

## 4. How to Use

#### a. Recommended: Modular Application

This is the preferred way to run the application.

1.  **Prerequisites**: Ensure you have the necessary Python library installed:
    ```bash
    pip install elasticsearch
    ```

2.  **Run the Application**: Execute the `analyzer` package as a module from the root directory of the project:
    ```bash
    python -m analyzer.main
    ```
    This will launch the GUI.

3.  **Command-Line Interface (CLI)**: The modular application has full CLI support for automation and monitoring integration.
    ```bash
    # Example: Run analysis and export to JSON
    python -m analyzer.main --url https://your-es-cluster:9200 --api-key "your-api-key" --run --export-json report.json
    ```

#### b. Legacy Monolithic Script

1.  **Prerequisites**:
    ```bash
    pip install elasticsearch
    ```

2.  **Run the Application**: Execute the Python script from your terminal:
    ```bash
    python es_cluster_perf_analyzer.py
    ```

---

## 5. Monitoring and Automation Integration

The analyzer is designed for easy integration with monitoring platforms like **Grafana, Prometheus, Splunk,** or any system that can consume JSON data.

The combination of the command-line interface and the JSON export feature allows you to run the analyzer as a scheduled task (e.g., a cron job) and feed the output directly into a monitoring pipeline.

#### Example: Scheduled Execution with a Cron Job

You can set up a cron job to run the analysis every 5 minutes and save the output to a location accessible by your monitoring tools.

1.  Open your crontab for editing:
    ```bash
    crontab -e
    ```

2.  Add the following line to execute the analyzer every 5 minutes. Remember to replace the placeholders with your actual project path and connection details.

    ```bash
    */5 * * * * /usr/bin/python3 /path/to/project/analyzer/main.py --url $ES_URL --api-key $ES_API_KEY --run --export-json /var/data/es_metrics.json
    ```

This command runs the analyzer in headless mode (`--run`) and saves the comprehensive metrics to `es_metrics.json`. A tool like Grafana with the **JSON API data source** can then be configured to read this file and display the metrics on a dashboard, enabling historical trending and alerting.

---

## 6. Architectural & Design Decisions

#### a. Evolution to a Modular Architecture

The project was originally a single, monolithic script. It has been refactored into a modular package structure (`analyzer/`) for several key reasons:
-   **Maintainability**: Separating concerns (e.g., connection, analysis modules, reporting) into different files makes the code easier to read, debug, and update.
-   **Extensibility**: Adding new analysis modules or output formats is as simple as adding a new file, without modifying the core application logic.
-   **Testability**: Individual components can be unit-tested in isolation.
-   **Clear Entry Points**: The separation of `main.py` (GUI and CLI orchestration) and `cli.py` (CLI command handling) creates clear and dedicated entry points for different execution modes.

#### b. GUI Framework: Tkinter

-   **The Choice**: `tkinter` was chosen as the GUI framework.
-   **The Rationale**: As part of the Python standard library, `tkinter` requires no external dependencies. This makes the application lightweight and highly portable.

#### c. Concurrency Model: `threading`

-   **The Choice**: The core analysis logic is executed in a separate background thread.
-   **The Rationale**: Elasticsearch API calls are network-bound. Running them on the main GUI thread would cause the application to freeze. Offloading the analysis to a separate thread ensures the UI remains fluid and responsive.

#### d. Reporting: Self-Contained HTML

-   **The Choice**: The primary output is a single, self-contained HTML file with embedded CSS and JavaScript.
-   **The Rationale**: Portability was the primary driver. A single file can be easily archived, emailed, or attached to a support ticket without worrying about missing dependencies.

---

## 7. Data Collection & Analysis Methodology

The selection of metrics was guided by a "top-down" diagnostic approach, starting with a high-level cluster overview and progressively drilling down into more granular subsystems.

-   **Why these modules?** The modules were chosen to cover the entire lifecycle of a request in Elasticsearch and the core subsystems that support it:
    1.  **Cluster & Node Health (`/`, `_cluster/health`, `_nodes`)**: The foundation. Is the cluster online and are all nodes participating?
    2.  **JVM Memory & GC (`_nodes/stats`)**: High heap usage and frequent garbage collection are common causes of performance degradation.
    3.  **Thread Pools (`_cat/thread_pool`)**: Queued or rejected tasks in pools like `search` or `write` are direct indicators of resource saturation.
    4.  **Indexing & Search Performance (`_indices/stats`, `_nodes/stats`)**: Inspects the performance of the two primary workloads: writing and reading data.
    5.  **I/O and Disk (`_nodes/stats`)**: Checks for I/O bottlenecks and monitors disk space.
    6.  **Shards, Segments & Merges (`_cat/shards`, `_indices/segments`)**: High segment counts or imbalanced shards can degrade performance.
    7.  **Hot Threads (`_nodes/hot_threads`)**: A direct look at what the CPU is spending its time on for diagnosing deep, complex issues.

-   **API Endpoints**: The tool relies on a combination of structured APIs (`_nodes/stats`, `_indices/stats`) for detailed metrics and the `_cat` APIs for concise summaries.
