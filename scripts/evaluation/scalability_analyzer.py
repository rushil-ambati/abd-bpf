"""
Scalability analysis module for ABD protocol evaluation.

Measures how the system behaves as the number of server nodes increases,
analyzing coordination overhead and capacity scaling patterns.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List

import matplotlib.pyplot as plt
import numpy as np
from scipy import stats

from .config import BENCHMARK_DEFAULTS, EvaluationConfig

logger = logging.getLogger(__name__)


class ScalabilityAnalyzer:
    """Handles scalability benchmarking and analysis across different node counts."""

    def __init__(self, config: EvaluationConfig):
        """Initialize scalability analyzer with configuration."""
        self.config = config
        self.workspace_root = Path.cwd()

        # Default node counts to test
        self.default_node_counts = [3, 5, 7, 9, 11]

    def detect_existing_node_counts(self) -> List[int]:
        """
        Detect node counts from existing scalability benchmark files.

        Returns:
            List of node counts that have existing benchmark data
        """
        node_counts = set()

        # Look for scalability result files in the data directory
        data_dir = self.config.data_dir
        if not data_dir.exists():
            logger.warning(f"Data directory {data_dir} does not exist")
            return []

        # Pattern: scalability_{implementation}_{node_count}_{benchmark_type}.json

        pattern = re.compile(r"scalability_(?:ebpf|userspace)_(\d+)_(?:latency|throughput)\.json")

        for file_path in data_dir.glob("scalability_*.json"):
            match = pattern.match(file_path.name)
            if match:
                node_count = int(match.group(1))
                node_counts.add(node_count)

        detected_counts = sorted(list(node_counts))
        logger.info(f"Detected existing node counts: {detected_counts}")
        return detected_counts

    def load_existing_scalability_results(self, node_counts: List[int] = None) -> Dict[str, Any]:
        """
        Load existing scalability benchmark results from files.

        Args:
            node_counts: List of node counts to load (if None, auto-detect)

        Returns:
            Dictionary containing loaded scalability benchmark results
        """
        if node_counts is None:
            node_counts = self.detect_existing_node_counts()

        if not node_counts:
            raise ValueError("No existing scalability results found. Run benchmarks first.")

        logger.info(f"Loading existing scalability results for node counts: {node_counts}")

        results = {
            "node_counts": node_counts,
            "latency_results": {},
            "throughput_results": {},
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "loaded_from_existing": True,
            },
        }

        for node_count in node_counts:
            results["latency_results"][node_count] = {}
            results["throughput_results"][node_count] = {}

            for implementation in ["ebpf", "userspace"]:
                # Load latency results
                latency_file = self.config.data_dir / f"scalability_{implementation}_{node_count}_latency.json"
                if latency_file.exists():
                    try:
                        with open(latency_file, "r", encoding="utf-8") as f:
                            latency_data = json.load(f)
                        results["latency_results"][node_count][implementation] = latency_data
                        logger.debug(f"Loaded latency data for {implementation} with {node_count} nodes")
                    except (json.JSONDecodeError, IOError) as e:
                        logger.warning(f"Failed to load latency data from {latency_file}: {e}")
                else:
                    logger.warning(f"Latency file not found: {latency_file}")

                # Load throughput results
                throughput_file = self.config.data_dir / f"scalability_{implementation}_{node_count}_throughput.json"
                if throughput_file.exists():
                    try:
                        with open(throughput_file, "r", encoding="utf-8") as f:
                            throughput_data = json.load(f)
                        results["throughput_results"][node_count][implementation] = throughput_data
                        logger.debug(f"Loaded throughput data for {implementation} with {node_count} nodes")
                    except (json.JSONDecodeError, IOError) as e:
                        logger.warning(f"Failed to load throughput data from {throughput_file}: {e}")
                else:
                    logger.warning(f"Throughput file not found: {throughput_file}")

        # Save consolidated results
        results_file = self.config.data_dir / "scalability_results.json"
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)

        logger.info(f"Loaded scalability results saved to {results_file}")
        return results

    def run_scalability_benchmarks(
        self, node_counts: List[int] = None, skip_benchmarks: bool = False
    ) -> Dict[str, Any]:
        """
        Run scalability benchmarks across different node counts.

        Args:
            node_counts: List of node counts to test (defaults to [3, 5, 7, 9, 11])
            skip_benchmarks: If True, skip benchmarks and load existing results

        Returns:
            Dictionary containing scalability benchmark results
        """
        if node_counts is None:
            node_counts = self.default_node_counts

        logger.info(f"Starting scalability benchmarks for node counts: {node_counts}")

        # If skip_benchmarks is enabled, try to load existing results
        if skip_benchmarks:
            try:
                results = self.load_existing_scalability_results(node_counts)
                logger.info("Successfully loaded existing scalability results")
                return results
            except (ValueError, FileNotFoundError, json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load existing results: {e}. Proceeding with benchmarks.")

        results = {
            "node_counts": node_counts,
            "latency_results": {},
            "throughput_results": {},
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "benchmark_config": {
                    "timeout_seconds": BENCHMARK_DEFAULTS["latency"]["timeout_seconds"],
                    "debug": self.config.debug,
                },
            },
        }

        for node_count in node_counts:
            logger.info(f"Running benchmarks with {node_count} nodes")

            results["latency_results"][node_count] = {}
            results["throughput_results"][node_count] = {}

            for implementation in ["ebpf", "userspace"]:
                logger.info(f"Testing {implementation} implementation with {node_count} nodes")

                try:
                    # Run latency benchmark
                    latency_data = self._run_scalability_latency_benchmark(implementation, node_count)
                    results["latency_results"][node_count][implementation] = latency_data

                    # Run throughput benchmark
                    throughput_data = self._run_scalability_throughput_benchmark(implementation, node_count)
                    results["throughput_results"][node_count][implementation] = throughput_data

                    logger.info(f"Completed benchmarks for {implementation} with {node_count} nodes")

                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                    logger.error(f"Benchmark failed for {implementation} with {node_count} nodes: {e}")
                    # Continue with other configurations
                    results["latency_results"][node_count][implementation] = None
                    results["throughput_results"][node_count][implementation] = None

        # Save raw results
        results_file = self.config.data_dir / "scalability_results.json"
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)

        logger.info(f"Scalability benchmarks completed. Results saved to {results_file}")
        return results

    def analyze_scalability_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scalability benchmark results to extract insights.

        Args:
            results: Raw scalability benchmark results

        Returns:
            Dictionary containing comprehensive scalability analysis
        """
        logger.info("Analyzing scalability benchmark results")

        analysis = {
            "latency_scaling": self._analyze_latency_scaling(results),
            "throughput_scaling": self._analyze_throughput_scaling(results),
            "coordination_overhead": self._analyze_coordination_overhead(results),
            "majority_analysis": self._analyze_majority_requirements(results),
            "performance_trends": self._analyze_performance_trends(results),
            "recommendations": self._generate_scalability_recommendations(results),
        }

        return analysis

    def _run_scalability_latency_benchmark(self, implementation: str, node_count: int) -> Dict[str, Any]:
        """Run latency benchmark for specific implementation and node count."""

        # Prepare command
        cmd = ["python3", "scripts/run.py"]
        if self.config.debug:
            cmd.append("--debug")
        if implementation == "userspace":
            cmd.append("--userspace")
        cmd.extend(["bench", "latency", "--num-nodes", str(node_count)])

        # Set environment variables
        env = os.environ.copy()
        output_filename = f"scalability_{implementation}_{node_count}_latency.json"
        env["ABD_BENCH_OUTPUT"] = output_filename

        return self._execute_scalability_benchmark(
            cmd,
            env,
            output_filename,
            BENCHMARK_DEFAULTS["latency"]["timeout_seconds"],
            f"latency-{implementation}-{node_count}",
        )

    def _run_scalability_throughput_benchmark(self, implementation: str, node_count: int) -> Dict[str, Any]:
        """Run throughput benchmark for specific implementation and node count."""

        # Prepare command
        cmd = ["python3", "scripts/run.py", "--num-nodes", str(node_count)]
        if self.config.debug:
            cmd.append("--debug")
        if implementation == "userspace":
            cmd.append("--userspace")
        cmd.extend(["bench", "throughput"])

        # Set environment variables
        env = os.environ.copy()
        output_filename = f"scalability_{implementation}_{node_count}_throughput.json"
        env["ABD_BENCH_OUTPUT"] = output_filename

        return self._execute_scalability_benchmark(
            cmd,
            env,
            output_filename,
            BENCHMARK_DEFAULTS["throughput"]["timeout_seconds"],
            f"throughput-{implementation}-{node_count}",
        )

    def _execute_scalability_benchmark(
        self, cmd: list, env: dict, output_filename: str, timeout_seconds: int, benchmark_id: str
    ) -> Dict[str, Any]:
        """Execute a scalability benchmark and return results."""

        logger.info(f"Executing benchmark: {benchmark_id}")
        logger.debug(f"Command: {' '.join(cmd)}")

        try:
            # Run benchmark
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                cwd=self.workspace_root,
                check=False,
            )

            if result.returncode != 0:
                logger.error(f"Benchmark {benchmark_id} failed with return code {result.returncode}")
                logger.error(f"Stderr: {result.stderr}")
                raise subprocess.CalledProcessError(result.returncode, cmd, result.stderr)

            # Load results
            result_path = self.workspace_root / output_filename
            if not result_path.exists():
                raise FileNotFoundError(f"Benchmark output file not found: {result_path}")

            with open(result_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Archive results
            archived_path = self.config.data_dir / output_filename
            shutil.move(str(result_path), str(archived_path))

            logger.info(f"Benchmark {benchmark_id} completed successfully")
            return data

        except subprocess.TimeoutExpired:
            logger.error(f"Benchmark {benchmark_id} timed out after {timeout_seconds} seconds")
            raise
        except (subprocess.CalledProcessError, FileNotFoundError, OSError, json.JSONDecodeError) as e:
            logger.error(f"Benchmark {benchmark_id} failed: {e}")
            raise

    def _analyze_latency_scaling(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze how latency scales with node count."""

        analysis = {"ebpf": {}, "userspace": {}}
        node_counts = results["node_counts"]

        for implementation in ["ebpf", "userspace"]:
            # Extract latency metrics for each node count
            write_p50 = []
            write_p95 = []
            read_p50 = []
            read_p95 = []
            valid_node_counts = []

            for node_count in node_counts:
                data = results["latency_results"].get(node_count, {}).get(implementation)
                if data is None:
                    continue

                valid_node_counts.append(node_count)

                # Extract write latencies
                if "write_latencies" in data:
                    write_latencies = []
                    if isinstance(data["write_latencies"], dict):
                        # Data is structured as {node_id: [latencies]}
                        for _, node_latencies in data["write_latencies"].items():
                            if isinstance(node_latencies, list):
                                # Convert strings to floats if needed
                                numeric_latencies = []
                                for lat in node_latencies:
                                    try:
                                        numeric_latencies.append(float(lat))
                                    except (ValueError, TypeError):
                                        continue
                                write_latencies.extend(numeric_latencies)

                    if write_latencies:
                        write_p50.append(np.percentile(write_latencies, 50))
                        write_p95.append(np.percentile(write_latencies, 95))
                    else:
                        write_p50.append(None)
                        write_p95.append(None)

                # Extract read latencies
                if "read_latencies" in data:
                    read_latencies = []
                    if isinstance(data["read_latencies"], dict):
                        # Data is structured as {node_id: [latencies]}
                        for _, node_latencies in data["read_latencies"].items():
                            if isinstance(node_latencies, list):
                                # Convert strings to floats if needed
                                numeric_latencies = []
                                for lat in node_latencies:
                                    try:
                                        numeric_latencies.append(float(lat))
                                    except (ValueError, TypeError):
                                        continue
                                read_latencies.extend(numeric_latencies)

                    if read_latencies:
                        read_p50.append(np.percentile(read_latencies, 50))
                        read_p95.append(np.percentile(read_latencies, 95))
                    else:
                        read_p50.append(None)
                        read_p95.append(None)

            analysis[implementation] = {
                "node_counts": valid_node_counts,
                "write_p50": write_p50,
                "write_p95": write_p95,
                "read_p50": read_p50,
                "read_p95": read_p95,
                "scaling_trends": self._calculate_scaling_trends(valid_node_counts, write_p50, read_p50),
            }

        return analysis

    def _analyze_throughput_scaling(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze how throughput scales with node count."""

        analysis = {"ebpf": {}, "userspace": {}}
        node_counts = results["node_counts"]

        for implementation in ["ebpf", "userspace"]:
            rps_values = []
            avg_latencies = []
            valid_node_counts = []

            for node_count in node_counts:
                data = results["throughput_results"].get(node_count, {}).get(implementation)
                if data is None:
                    continue

                valid_node_counts.append(node_count)

                # Extract throughput metrics
                if "summary" in data:
                    rps_values.append(data["summary"]["rps"])
                    latency_summary = data["summary"].get("latency_summary", {})
                    avg_latencies.append(latency_summary.get("avg_us", 0))

            analysis[implementation] = {
                "node_counts": valid_node_counts,
                "rps_values": rps_values,
                "avg_latencies": avg_latencies,
                "scaling_efficiency": self._calculate_throughput_scaling_efficiency(valid_node_counts, rps_values),
            }

        return analysis

    def _analyze_coordination_overhead(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze coordination overhead as node count increases."""

        coordination_analysis = {}
        node_counts = results["node_counts"]

        for implementation in ["ebpf", "userspace"]:
            coordination_metrics = []

            for node_count in node_counts:
                majority_size = (node_count // 2) + 1

                # Calculate theoretical vs actual performance
                throughput_data = results["throughput_results"].get(node_count, {}).get(implementation)
                if throughput_data and "summary" in throughput_data:
                    actual_rps = throughput_data["summary"]["rps"]

                    # Estimate coordination overhead
                    # Assume baseline performance with 3 nodes
                    if node_count == 3:
                        baseline_rps = actual_rps
                    else:
                        # Calculate expected performance if overhead was linear
                        expected_rps = baseline_rps if "baseline_rps" in locals() else actual_rps
                        overhead_factor = actual_rps / expected_rps if expected_rps > 0 else 1.0

                        coordination_metrics.append(
                            {
                                "node_count": node_count,
                                "majority_size": majority_size,
                                "actual_rps": actual_rps,
                                "overhead_factor": overhead_factor,
                                "coordination_cost": 1.0 - overhead_factor,
                            }
                        )

            coordination_analysis[implementation] = coordination_metrics

        return coordination_analysis

    def _analyze_majority_requirements(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the impact of majority requirements on performance."""

        majority_analysis = {}
        node_counts = results["node_counts"]

        for node_count in node_counts:
            majority_size = (node_count // 2) + 1
            minority_size = node_count - majority_size

            majority_analysis[node_count] = {
                "total_nodes": node_count,
                "majority_size": majority_size,
                "minority_size": minority_size,
                "fault_tolerance": minority_size,
                "coordination_ratio": majority_size / node_count,
            }

        return majority_analysis

    def _analyze_performance_trends(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze overall performance trends across node counts."""

        trends = {"ebpf": {}, "userspace": {}}
        node_counts = results["node_counts"]

        for implementation in ["ebpf", "userspace"]:
            # Collect performance metrics
            performance_data = []

            for node_count in node_counts:
                latency_data = results["latency_results"].get(node_count, {}).get(implementation)
                throughput_data = results["throughput_results"].get(node_count, {}).get(implementation)

                if latency_data and throughput_data:
                    # Calculate average latencies
                    write_latencies = []
                    read_latencies = []

                    if "write_latencies" in latency_data:
                        for node_data in latency_data["write_latencies"]:
                            # Convert all values to float
                            write_latencies.extend([float(x) for x in node_data])

                    if "read_latencies" in latency_data:
                        for node_data in latency_data["read_latencies"]:
                            read_latencies.extend([float(x) for x in node_data])

                    avg_write_latency = np.mean(write_latencies) if write_latencies else 0
                    avg_read_latency = np.mean(read_latencies) if read_latencies else 0

                    # Get throughput
                    rps = throughput_data["summary"]["rps"] if "summary" in throughput_data else 0

                    performance_data.append(
                        {
                            "node_count": node_count,
                            "avg_write_latency": avg_write_latency,
                            "avg_read_latency": avg_read_latency,
                            "throughput_rps": rps,
                            "throughput_per_node": rps / node_count if node_count > 0 else 0,
                        }
                    )

            trends[implementation] = {
                "performance_data": performance_data,
                "optimal_node_count": self._find_optimal_node_count(performance_data),
            }

        return trends

    def _calculate_scaling_trends(
        self, node_counts: List[int], write_latencies: List[float], read_latencies: List[float]
    ) -> Dict[str, Any]:
        """Calculate scaling trend coefficients."""

        trends = {}

        if len(node_counts) >= 2:
            # Calculate correlation between node count and latency
            if write_latencies and len([x for x in write_latencies if x is not None]) >= 2:
                valid_write = [(nc, lat) for nc, lat in zip(node_counts, write_latencies) if lat is not None]
                if len(valid_write) >= 2:
                    nc_vals, lat_vals = zip(*valid_write)
                    write_correlation, _ = stats.pearsonr(nc_vals, lat_vals)
                    trends["write_correlation"] = write_correlation

            if read_latencies and len([x for x in read_latencies if x is not None]) >= 2:
                valid_read = [(nc, lat) for nc, lat in zip(node_counts, read_latencies) if lat is not None]
                if len(valid_read) >= 2:
                    nc_vals, lat_vals = zip(*valid_read)
                    read_correlation, _ = stats.pearsonr(nc_vals, lat_vals)
                    trends["read_correlation"] = read_correlation

        return trends

    def _calculate_throughput_scaling_efficiency(
        self, node_counts: List[int], rps_values: List[float]
    ) -> Dict[str, Any]:
        """Calculate throughput scaling efficiency."""

        if len(node_counts) < 2 or len(rps_values) < 2:
            return {"efficiency": "insufficient_data"}

        # Calculate efficiency as throughput increase per additional node
        efficiency_values = []

        for i in range(1, len(node_counts)):
            node_increase = node_counts[i] - node_counts[i - 1]
            rps_increase = rps_values[i] - rps_values[i - 1]
            efficiency = rps_increase / node_increase if node_increase > 0 else 0
            efficiency_values.append(efficiency)

        return {
            "efficiency_per_node": efficiency_values,
            "average_efficiency": np.mean(efficiency_values) if efficiency_values else 0,
            "diminishing_returns": len([e for e in efficiency_values if e < 0]) > 0,
        }

    def _find_optimal_node_count(self, performance_data: List[Dict]) -> Dict[str, Any]:
        """Find optimal node count based on performance metrics."""

        if len(performance_data) < 2:
            return {"optimal_count": "insufficient_data"}

        # Calculate performance score (higher throughput, lower latency)
        best_score = float("-inf")
        optimal_count = 3

        for data in performance_data:
            # Normalize metrics (higher is better for throughput, lower is better for latency)
            throughput_score = data["throughput_rps"]
            latency_penalty = (data["avg_write_latency"] + data["avg_read_latency"]) / 2

            # Simple scoring: prioritize throughput with latency penalty
            score = throughput_score - (latency_penalty * 0.1)  # Adjust weight as needed

            if score > best_score:
                best_score = score
                optimal_count = data["node_count"]

        return {
            "optimal_count": optimal_count,
            "best_score": best_score,
            "reasoning": f"Optimal balance of throughput and latency at {optimal_count} nodes",
        }

    def _generate_scalability_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on scalability analysis."""

        recommendations = []
        node_counts = results["node_counts"]

        # Analyze trends for both implementations
        for implementation in ["ebpf", "userspace"]:
            throughput_data = []

            for node_count in node_counts:
                t_data = results["throughput_results"].get(node_count, {}).get(implementation)

                if t_data and "summary" in t_data:
                    throughput_data.append((node_count, t_data["summary"]["rps"]))

            # Analyze throughput trends
            if len(throughput_data) >= 2:
                _, rps_list = zip(*throughput_data)

                # Check if throughput increases with nodes
                if rps_list[-1] > rps_list[0]:
                    recommendations.append(
                        f"{implementation.title()} shows positive throughput scaling "
                        f"({rps_list[0]:.0f} → {rps_list[-1]:.0f} RPS)"
                    )
                else:
                    recommendations.append(
                        f"{implementation.title()} shows limited throughput scaling "
                        f"(consider overhead optimization)"
                    )

        # General recommendations
        recommendations.extend(
            [
                "• Consider optimal node count based on workload requirements",
                "• Monitor coordination overhead in high-node-count deployments",
                "• Balance fault tolerance needs with performance costs",
                "• Test with realistic network latencies for production planning",
            ]
        )

        return recommendations

    def create_scalability_visualizations(self, analysis: Dict[str, Any]):
        """Create comprehensive scalability visualizations."""

        logger.info("Generating scalability visualizations")

        # 1. Latency vs Node Count Bar Chart
        self._create_latency_scaling_chart(analysis["latency_scaling"])

        # 2. Throughput vs Node Count Line Chart
        self._create_throughput_scaling_chart(analysis["throughput_scaling"])

        # 3. Coordination Overhead Analysis
        self._create_coordination_overhead_chart(analysis["coordination_overhead"])

        # 4. Performance Efficiency Chart
        self._create_performance_efficiency_chart(analysis["performance_trends"])

        # 5. Combined Overview Dashboard
        self._create_scalability_dashboard(analysis)

        logger.info("Scalability visualizations completed")

    def _create_latency_scaling_chart(self, latency_analysis: Dict[str, Any]):
        """Create bar chart showing latency scaling with node count."""

        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle("Latency Scaling Analysis", fontsize=16, fontweight="bold")

        # Write P50 Latency
        for impl in ["ebpf", "userspace"]:
            data = latency_analysis[impl]
            if data["node_counts"] and data["write_p50"]:
                ax1.bar(
                    [x + (0.2 if impl == "userspace" else -0.2) for x in data["node_counts"]],
                    data["write_p50"],
                    width=0.4,
                    label=impl.title(),
                    color=self.config.colors[impl],
                    alpha=0.8,
                )

        ax1.set_xlabel("Number of Nodes")
        ax1.set_ylabel("Write P50 Latency (μs)")
        ax1.set_title("Write P50 Latency vs Node Count")
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        # Write P95 Latency
        for impl in ["ebpf", "userspace"]:
            data = latency_analysis[impl]
            if data["node_counts"] and data["write_p95"]:
                ax2.bar(
                    [x + (0.2 if impl == "userspace" else -0.2) for x in data["node_counts"]],
                    data["write_p95"],
                    width=0.4,
                    label=impl.title(),
                    color=self.config.colors[impl],
                    alpha=0.8,
                )

        ax2.set_xlabel("Number of Nodes")
        ax2.set_ylabel("Write P95 Latency (μs)")
        ax2.set_title("Write P95 Latency vs Node Count")
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # Read P50 Latency
        for impl in ["ebpf", "userspace"]:
            data = latency_analysis[impl]
            if data["node_counts"] and data["read_p50"]:
                ax3.bar(
                    [x + (0.2 if impl == "userspace" else -0.2) for x in data["node_counts"]],
                    data["read_p50"],
                    width=0.4,
                    label=impl.title(),
                    color=self.config.colors[impl],
                    alpha=0.8,
                )

        ax3.set_xlabel("Number of Nodes")
        ax3.set_ylabel("Read P50 Latency (μs)")
        ax3.set_title("Read P50 Latency vs Node Count")
        ax3.legend()
        ax3.grid(True, alpha=0.3)

        # Read P95 Latency
        for impl in ["ebpf", "userspace"]:
            data = latency_analysis[impl]
            if data["node_counts"] and data["read_p95"]:
                ax4.bar(
                    [x + (0.2 if impl == "userspace" else -0.2) for x in data["node_counts"]],
                    data["read_p95"],
                    width=0.4,
                    label=impl.title(),
                    color=self.config.colors[impl],
                    alpha=0.8,
                )

        ax4.set_xlabel("Number of Nodes")
        ax4.set_ylabel("Read P95 Latency (μs)")
        ax4.set_title("Read P95 Latency vs Node Count")
        ax4.legend()
        ax4.grid(True, alpha=0.3)

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(self.config.figures_dir / f"scalability_latency_analysis.{fmt}", dpi=300, bbox_inches="tight")
        plt.close()

    def _create_throughput_scaling_chart(self, throughput_analysis: Dict[str, Any]):
        """Create line chart showing throughput scaling with node count."""

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        fig.suptitle("Throughput Scaling Analysis", fontsize=16, fontweight="bold")

        # Max Throughput vs Node Count
        for impl in ["ebpf", "userspace"]:
            data = throughput_analysis[impl]
            if data["node_counts"] and data["rps_values"]:
                ax1.plot(
                    data["node_counts"],
                    data["rps_values"],
                    marker="o",
                    linewidth=2,
                    markersize=8,
                    label=impl.title(),
                    color=self.config.colors[impl],
                )

        ax1.set_xlabel("Number of Nodes")
        ax1.set_ylabel("Max Throughput (RPS)")
        ax1.set_title("Max Throughput vs Node Count")
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        # Throughput per Node
        for impl in ["ebpf", "userspace"]:
            data = throughput_analysis[impl]
            if data["node_counts"] and data["rps_values"]:
                throughput_per_node = [rps / nodes for rps, nodes in zip(data["rps_values"], data["node_counts"])]
                ax2.plot(
                    data["node_counts"],
                    throughput_per_node,
                    marker="s",
                    linewidth=2,
                    markersize=8,
                    label=impl.title(),
                    color=self.config.colors[impl],
                )

        ax2.set_xlabel("Number of Nodes")
        ax2.set_ylabel("Throughput per Node (RPS/Node)")
        ax2.set_title("Throughput Efficiency vs Node Count")
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(
                self.config.figures_dir / f"scalability_throughput_analysis.{fmt}", dpi=300, bbox_inches="tight"
            )
        plt.close()

    def _create_coordination_overhead_chart(self, coordination_analysis: Dict[str, Any]):
        """Create chart showing coordination overhead analysis."""

        fig, ax1 = plt.subplots(1, 1, figsize=(8, 6))
        fig.suptitle("Coordination Overhead Analysis", fontsize=16, fontweight="bold")

        # Coordination Cost vs Node Count
        for impl in ["ebpf", "userspace"]:
            metrics = coordination_analysis.get(impl, [])
            if metrics:
                node_counts = [m["node_count"] for m in metrics]
                coordination_costs = [m["coordination_cost"] * 100 for m in metrics]  # Convert to percentage

                ax1.plot(
                    node_counts,
                    coordination_costs,
                    marker="o",
                    linewidth=2,
                    markersize=8,
                    label=impl.title(),
                    color=self.config.colors[impl],
                )

        ax1.set_xlabel("Number of Nodes")
        ax1.set_ylabel("Coordination Overhead (\\%)")  # Use percent sign, not LaTeX
        ax1.set_title("Coordination Overhead vs Node Count")
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(
                self.config.figures_dir / f"scalability_coordination_analysis.{fmt}", dpi=300, bbox_inches="tight"
            )
        plt.close()

    def _create_performance_efficiency_chart(self, performance_trends: Dict[str, Any]):
        """Create chart showing performance efficiency trends."""

        fig, ax1 = plt.subplots(1, 1, figsize=(8, 6))
        fig.suptitle("Performance Efficiency Analysis", fontsize=16, fontweight="bold")

        # Performance Score vs Node Count
        for impl in ["ebpf", "userspace"]:
            perf_data = performance_trends[impl]["performance_data"]
            if perf_data:
                node_counts = [d["node_count"] for d in perf_data]
                # Calculate simple performance score
                scores = [d["throughput_rps"] / (1 + d["avg_write_latency"] / 1000) for d in perf_data]

                ax1.plot(
                    node_counts,
                    scores,
                    marker="o",
                    linewidth=2,
                    markersize=8,
                    label=impl.title(),
                    color=self.config.colors[impl],
                )

        ax1.set_xlabel("Number of Nodes")
        ax1.set_ylabel("Performance Score (RPS/Latency)")
        ax1.set_title("Overall Performance vs Node Count")
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(
                self.config.figures_dir / f"scalability_efficiency_analysis.{fmt}", dpi=300, bbox_inches="tight"
            )
        plt.close()

    def _create_scalability_dashboard(self, analysis: Dict[str, Any]):
        """Create comprehensive scalability dashboard."""

        fig = plt.figure(figsize=(20, 12))
        fig.suptitle("ABD Protocol Scalability Analysis Dashboard", fontsize=20, fontweight="bold")

        # Create a 3x3 grid of subplots
        gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)

        # 1. Latency Overview (top-left)
        ax1 = fig.add_subplot(gs[0, 0])
        for impl in ["ebpf", "userspace"]:
            data = analysis["latency_scaling"][impl]
            if data["node_counts"] and data["write_p50"]:
                ax1.plot(
                    data["node_counts"],
                    data["write_p50"],
                    marker="o",
                    label=f"{impl.title()} Write P50",
                    color=self.config.colors[impl],
                )
        ax1.set_title("Write Latency Scaling")
        ax1.set_xlabel("Nodes")
        ax1.set_ylabel("P50 Latency (μs)")
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        # 2. Throughput Overview (top-center)
        ax2 = fig.add_subplot(gs[0, 1])
        for impl in ["ebpf", "userspace"]:
            data = analysis["throughput_scaling"][impl]
            if data["node_counts"] and data["rps_values"]:
                ax2.plot(
                    data["node_counts"],
                    data["rps_values"],
                    marker="s",
                    label=f"{impl.title()}",
                    color=self.config.colors[impl],
                )
        ax2.set_title("Throughput Scaling")
        ax2.set_xlabel("Nodes")
        ax2.set_ylabel("Max RPS")
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # 3. Efficiency Overview (top-right)
        ax3 = fig.add_subplot(gs[0, 2])
        for impl in ["ebpf", "userspace"]:
            data = analysis["throughput_scaling"][impl]
            if data["node_counts"] and data["rps_values"]:
                efficiency = [rps / nodes for rps, nodes in zip(data["rps_values"], data["node_counts"])]
                ax3.plot(
                    data["node_counts"],
                    efficiency,
                    marker="^",
                    label=f"{impl.title()}",
                    color=self.config.colors[impl],
                )
        ax3.set_title("Throughput Efficiency")
        ax3.set_xlabel("Nodes")
        ax3.set_ylabel("RPS per Node")
        ax3.legend()
        ax3.grid(True, alpha=0.3)

        # 4-6. Individual latency metrics (middle row)
        metrics = [
            ("write_p95", "Write P95 Latency"),
            ("read_p50", "Read P50 Latency"),
            ("read_p95", "Read P95 Latency"),
        ]
        for i, (metric, title) in enumerate(metrics):
            ax = fig.add_subplot(gs[1, i])
            for impl in ["ebpf", "userspace"]:
                data = analysis["latency_scaling"][impl]
                if data["node_counts"] and data[metric]:
                    ax.plot(
                        data["node_counts"],
                        data[metric],
                        marker="o",
                        label=impl.title(),
                        color=self.config.colors[impl],
                    )
            ax.set_title(title)
            ax.set_xlabel("Nodes")
            ax.set_ylabel("Latency (μs)")
            ax.legend()
            ax.grid(True, alpha=0.3)

        # 7. Coordination overhead (bottom-left)
        ax7 = fig.add_subplot(gs[2, 0])
        for impl in ["ebpf", "userspace"]:
            metrics = analysis["coordination_overhead"].get(impl, [])
            if metrics and isinstance(metrics, list):
                node_counts = [m["node_count"] for m in metrics if isinstance(m, dict) and "node_count" in m]
                overhead = [
                    m["coordination_cost"] * 100 for m in metrics if isinstance(m, dict) and "coordination_cost" in m
                ]
                if node_counts and overhead and len(node_counts) == len(overhead):
                    ax7.plot(
                        node_counts,
                        overhead,
                        marker="o",
                        label=impl.title(),
                        color=self.config.colors[impl],
                    )
        ax7.set_title("Coordination Overhead")
        ax7.set_xlabel("Nodes")
        ax7.set_ylabel("Overhead (\\%)")
        ax7.legend()
        ax7.grid(True, alpha=0.3)

        # 8. (bottom-center) -- intentionally left blank (removed fault tolerance/majority graph)
        ax8 = fig.add_subplot(gs[2, 1])
        ax8.axis("off")

        # 9. (bottom-right) -- intentionally left blank (removed key insights)
        ax9 = fig.add_subplot(gs[2, 2])
        ax9.axis("off")

        # Save dashboard
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(self.config.figures_dir / f"scalability_dashboard.{fmt}", dpi=300, bbox_inches="tight")
        plt.close()

        logger.info("Scalability dashboard created successfully")
