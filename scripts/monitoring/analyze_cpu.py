#!/usr/bin/env python3
"""
CPU Utilization Analysis Tool for ABD Protocol Evaluation

This script analyzes CPU monitoring data collected during userspace ABD protocol
benchmarks and generates comprehensive reports and visualizations.

Usage:
    python3 scripts/analyze_cpu.py [--input-dir DIR] [--output-dir DIR] [--format FORMAT]

Author: ABD Protocol Research Team
"""

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Any

try:
    import pandas as pd
    import matplotlib.pyplot as plt
    import seaborn as sns
    import numpy as np

    ANALYSIS_AVAILABLE = True
except ImportError:
    ANALYSIS_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class CPUAnalyzer:
    """
    Analyzes CPU utilization data from ABD protocol monitoring.

    Provides comprehensive analysis including:
    - System-wide CPU utilization trends
    - Per-process CPU usage patterns
    - Per-core utilization distribution
    - Memory usage correlation
    - Statistical summaries and anomaly detection
    """

    def __init__(self, input_dir: Path, output_dir: Path):
        """
        Initialize CPU analyzer.

        Args:
            input_dir: Directory containing CPU monitoring JSON files
            output_dir: Directory to save analysis results
        """
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Data storage
        self.system_data = None
        self.process_data = None
        self.core_data = None
        self.metadata = {}

    def load_monitoring_data(self) -> bool:
        """
        Load CPU monitoring data from JSON files.

        Returns:
            True if data was successfully loaded, False otherwise
        """
        try:
            # Check for new monitoring subdirectory structure first
            monitoring_dir = self.input_dir / "monitoring"
            if monitoring_dir.exists():
                search_dir = monitoring_dir
                logger.info(f"Using monitoring subdirectory: {monitoring_dir}")
                # Look for new descriptive filenames
                system_files = list(search_dir.glob("*_cpu_system.json"))
                process_files = list(search_dir.glob("*_cpu_processes.json"))
                core_files = list(search_dir.glob("*_cpu_cores.json"))
            else:
                search_dir = self.input_dir
                logger.info(f"Using data directory: {search_dir}")
                # Look for old timestamp-based filenames
                system_files = list(search_dir.glob("cpu_monitor_system_*.json"))
                process_files = list(search_dir.glob("cpu_monitor_processes_*.json"))
                core_files = list(search_dir.glob("cpu_monitor_cores_*.json"))

            if not system_files:
                logger.error(f"No system CPU monitoring files found in {self.input_dir}")
                return False

            # Use the most recent files
            system_file = max(system_files, key=lambda f: f.stat().st_mtime)
            process_file = max(process_files, key=lambda f: f.stat().st_mtime) if process_files else None
            core_file = max(core_files, key=lambda f: f.stat().st_mtime) if core_files else None

            logger.info(f"Loading system data from {system_file}")

            # Load system data
            with open(system_file, "r") as f:
                system_data = json.load(f)
                self.system_data = pd.DataFrame(system_data["data"])
                self.metadata.update(system_data["metadata"])

            # Load process data if available
            if process_file:
                logger.info(f"Loading process data from {process_file}")
                with open(process_file, "r") as f:
                    process_data = json.load(f)
                    self.process_data = pd.DataFrame(process_data["data"])
                    self.metadata.update(process_data["metadata"])

            # Load core data if available
            if core_file:
                logger.info(f"Loading core data from {core_file}")
                with open(core_file, "r") as f:
                    core_data = json.load(f)
                    self.core_data = pd.DataFrame(core_data["data"])

            logger.info("CPU monitoring data loaded successfully")
            return True

        except Exception as e:
            logger.error(f"Error loading CPU monitoring data: {e}")
            return False

    def generate_analysis_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive analysis report.

        Returns:
            Dictionary containing analysis results
        """
        if self.system_data is None:
            logger.error("No system data available for analysis")
            return {}

        analysis = {
            "metadata": self.metadata,
            "system_analysis": self._analyze_system_metrics(),
            "process_analysis": self._analyze_process_metrics() if self.process_data is not None else {},
            "core_analysis": self._analyze_core_metrics() if self.core_data is not None else {},
            "correlations": self._analyze_correlations(),
            "recommendations": self._generate_recommendations(),
        }

        return analysis

    def _analyze_system_metrics(self) -> Dict[str, Any]:
        """Analyze system-wide CPU and memory metrics."""
        try:
            df = self.system_data

            # Basic statistics
            cpu_stats = {
                "mean": df["cpu_percent"].mean(),
                "median": df["cpu_percent"].median(),
                "std": df["cpu_percent"].std(),
                "min": df["cpu_percent"].min(),
                "max": df["cpu_percent"].max(),
                "p95": df["cpu_percent"].quantile(0.95),
                "p99": df["cpu_percent"].quantile(0.99),
            }

            memory_stats = {
                "mean": df["memory_percent"].mean(),
                "median": df["memory_percent"].median(),
                "std": df["memory_percent"].std(),
                "min": df["memory_percent"].min(),
                "max": df["memory_percent"].max(),
                "peak_usage_gb": df["memory_used_gb"].max(),
            }

            # Load average analysis
            load_stats = {}
            if "load_avg_1m" in df.columns:
                load_stats = {
                    "load_1m_mean": df["load_avg_1m"].mean(),
                    "load_5m_mean": df["load_avg_5m"].mean(),
                    "load_15m_mean": df["load_avg_15m"].mean(),
                    "load_1m_max": df["load_avg_1m"].max(),
                }

            # Time series analysis
            duration = df["relative_time"].max()
            sample_rate = len(df) / duration if duration > 0 else 0

            # Detect high CPU periods (>80%)
            high_cpu_mask = df["cpu_percent"] > 80
            high_cpu_periods = high_cpu_mask.sum()
            high_cpu_percentage = (high_cpu_periods / len(df)) * 100

            return {
                "cpu_statistics": cpu_stats,
                "memory_statistics": memory_stats,
                "load_average": load_stats,
                "time_analysis": {
                    "duration_seconds": duration,
                    "total_samples": len(df),
                    "sample_rate_hz": sample_rate,
                    "high_cpu_periods": high_cpu_periods,
                    "high_cpu_percentage": high_cpu_percentage,
                },
            }

        except Exception as e:
            logger.error(f"Error analyzing system metrics: {e}")
            return {}

    def _analyze_process_metrics(self) -> Dict[str, Any]:
        """Analyze per-process CPU utilization."""
        if self.process_data is None or self.process_data.empty:
            return {}

        try:
            df = self.process_data

            # Group by process name
            process_groups = df.groupby("name")

            process_analysis = {}
            for name, group in process_groups:
                process_analysis[name] = {
                    "cpu_mean": group["cpu_percent"].mean(),
                    "cpu_max": group["cpu_percent"].max(),
                    "cpu_std": group["cpu_percent"].std(),
                    "memory_mean_mb": group["memory_rss_mb"].mean(),
                    "memory_max_mb": group["memory_rss_mb"].max(),
                    "samples": len(group),
                    "duration": group["relative_time"].max() - group["relative_time"].min(),
                }

            # Find most CPU-intensive processes
            top_cpu_processes = sorted(process_analysis.items(), key=lambda x: x[1]["cpu_mean"], reverse=True)[:5]

            return {
                "process_statistics": process_analysis,
                "top_cpu_processes": dict(top_cpu_processes),
                "total_processes_tracked": len(process_analysis),
            }

        except Exception as e:
            logger.error(f"Error analyzing process metrics: {e}")
            return {}

    def _analyze_core_metrics(self) -> Dict[str, Any]:
        """Analyze per-core CPU utilization."""
        if self.core_data is None or self.core_data.empty:
            return {}

        try:
            # Extract core data
            core_columns = [col for col in self.core_data.columns if col.startswith("cores.")]
            if not core_columns:
                return {}

            core_stats = {}
            for core_col in core_columns:
                core_name = core_col.replace("cores.", "")
                core_values = pd.json_normalize(self.core_data["cores"])[core_name]

                core_stats[core_name] = {
                    "mean": core_values.mean(),
                    "max": core_values.max(),
                    "std": core_values.std(),
                    "utilization_distribution": {
                        "low": (core_values < 25).sum() / len(core_values) * 100,
                        "medium": ((core_values >= 25) & (core_values < 75)).sum() / len(core_values) * 100,
                        "high": (core_values >= 75).sum() / len(core_values) * 100,
                    },
                }

            # Calculate load balancing metrics
            core_means = [stats["mean"] for stats in core_stats.values()]
            load_balance_coefficient = np.std(core_means) / np.mean(core_means) if np.mean(core_means) > 0 else 0

            return {
                "core_statistics": core_stats,
                "load_balancing": {
                    "coefficient_of_variation": load_balance_coefficient,
                    "interpretation": "good" if load_balance_coefficient < 0.5 else "uneven",
                },
                "num_cores": len(core_stats),
            }

        except Exception as e:
            logger.error(f"Error analyzing core metrics: {e}")
            return {}

    def _analyze_correlations(self) -> Dict[str, Any]:
        """Analyze correlations between different metrics."""
        try:
            correlations = {}

            if self.system_data is not None:
                # CPU vs Memory correlation
                cpu_memory_corr = self.system_data["cpu_percent"].corr(self.system_data["memory_percent"])
                correlations["cpu_memory_correlation"] = cpu_memory_corr

                # Context switches vs CPU correlation
                if "ctx_switches" in self.system_data.columns:
                    # Calculate rate of context switches
                    ctx_switch_rate = (
                        self.system_data["ctx_switches"].diff() / self.system_data["relative_time"].diff()
                    )
                    ctx_cpu_corr = ctx_switch_rate.corr(self.system_data["cpu_percent"])
                    correlations["context_switches_cpu_correlation"] = ctx_cpu_corr

            return correlations

        except Exception as e:
            logger.error(f"Error analyzing correlations: {e}")
            return {}

    def _generate_recommendations(self) -> List[str]:
        """Generate performance recommendations based on analysis."""
        recommendations = []

        try:
            if self.system_data is not None:
                avg_cpu = self.system_data["cpu_percent"].mean()
                max_cpu = self.system_data["cpu_percent"].max()
                avg_memory = self.system_data["memory_percent"].mean()

                # CPU utilization recommendations
                if avg_cpu > 80:
                    recommendations.append(
                        "High average CPU utilization detected. Consider optimizing CPU-intensive operations."
                    )
                elif avg_cpu < 10:
                    recommendations.append(
                        "Low CPU utilization suggests the system may be I/O bound or underutilized."
                    )

                if max_cpu > 95:
                    recommendations.append(
                        "CPU saturation detected. This may cause performance degradation and increased latency."
                    )

                # Memory recommendations
                if avg_memory > 80:
                    recommendations.append("High memory usage detected. Monitor for potential memory leaks.")

                # Process-specific recommendations
                if self.process_data is not None:
                    process_groups = self.process_data.groupby("name")
                    for name, group in process_groups:
                        if group["cpu_percent"].mean() > 50:
                            recommendations.append(
                                f"Process '{name}' shows high CPU usage. "
                                "Consider profiling for optimization opportunities."
                            )

            if not recommendations:
                recommendations.append(
                    "System performance appears normal with no immediate optimization needs identified."
                )

        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            recommendations.append("Unable to generate recommendations due to analysis error.")

        return recommendations

    def create_visualizations(self):
        """Create comprehensive CPU utilization visualizations."""
        if not ANALYSIS_AVAILABLE:
            logger.warning("Visualization libraries not available. Install pandas, matplotlib, and seaborn.")
            return

        if self.system_data is None:
            logger.error("No data available for visualization")
            return

        # Set up plotting style
        plt.style.use("default")
        sns.set_palette("husl")

        # Create comprehensive dashboard
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle("ABD Protocol Userspace CPU Utilization Analysis", fontsize=16)

        # 1. CPU utilization over time
        axes[0, 0].plot(self.system_data["relative_time"], self.system_data["cpu_percent"], alpha=0.7)
        axes[0, 0].set_title("CPU Utilization Over Time")
        axes[0, 0].set_xlabel("Time (seconds)")
        axes[0, 0].set_ylabel("CPU %")
        axes[0, 0].grid(True, alpha=0.3)

        # 2. CPU utilization distribution
        axes[0, 1].hist(self.system_data["cpu_percent"], bins=50, alpha=0.7, edgecolor="black")
        axes[0, 1].set_title("CPU Utilization Distribution")
        axes[0, 1].set_xlabel("CPU %")
        axes[0, 1].set_ylabel("Frequency")
        axes[0, 1].axvline(self.system_data["cpu_percent"].mean(), color="red", linestyle="--", label="Mean")
        axes[0, 1].legend()

        # 3. Memory usage over time
        axes[0, 2].plot(
            self.system_data["relative_time"], self.system_data["memory_percent"], alpha=0.7, color="orange"
        )
        axes[0, 2].set_title("Memory Usage Over Time")
        axes[0, 2].set_xlabel("Time (seconds)")
        axes[0, 2].set_ylabel("Memory %")
        axes[0, 2].grid(True, alpha=0.3)

        # 4. CPU vs Memory scatter plot
        axes[1, 0].scatter(self.system_data["cpu_percent"], self.system_data["memory_percent"], alpha=0.5)
        axes[1, 0].set_title("CPU vs Memory Usage")
        axes[1, 0].set_xlabel("CPU %")
        axes[1, 0].set_ylabel("Memory %")
        axes[1, 0].grid(True, alpha=0.3)

        # 5. Process CPU usage (if available)
        if self.process_data is not None and not self.process_data.empty:
            process_means = (
                self.process_data.groupby("name")["cpu_percent"].mean().sort_values(ascending=False).head(5)
            )
            axes[1, 1].bar(range(len(process_means)), process_means.values)
            axes[1, 1].set_title("Top 5 Processes by CPU Usage")
            axes[1, 1].set_ylabel("Average CPU %")
            axes[1, 1].set_xticks(range(len(process_means)))
            axes[1, 1].set_xticklabels(process_means.index, rotation=45, ha="right")
        else:
            axes[1, 1].text(
                0.5, 0.5, "No process data available", ha="center", va="center", transform=axes[1, 1].transAxes
            )
            axes[1, 1].set_title("Process CPU Usage")

        # 6. Load average over time (if available)
        if "load_avg_1m" in self.system_data.columns:
            axes[1, 2].plot(
                self.system_data["relative_time"], self.system_data["load_avg_1m"], label="1min", alpha=0.7
            )
            axes[1, 2].plot(
                self.system_data["relative_time"], self.system_data["load_avg_5m"], label="5min", alpha=0.7
            )
            axes[1, 2].plot(
                self.system_data["relative_time"], self.system_data["load_avg_15m"], label="15min", alpha=0.7
            )
            axes[1, 2].set_title("System Load Average")
            axes[1, 2].set_xlabel("Time (seconds)")
            axes[1, 2].set_ylabel("Load Average")
            axes[1, 2].legend()
            axes[1, 2].grid(True, alpha=0.3)
        else:
            axes[1, 2].text(
                0.5, 0.5, "No load average data available", ha="center", va="center", transform=axes[1, 2].transAxes
            )
            axes[1, 2].set_title("System Load Average")

        plt.tight_layout()

        # Save the dashboard with descriptive naming
        for fmt in ["png", "pdf", "svg"]:
            output_file = self.output_dir / f"utilization_userspace_dashboard.{fmt}"
            plt.savefig(output_file, dpi=300, bbox_inches="tight")

        plt.close()
        logger.info(f"CPU analysis dashboard saved to {self.output_dir}")

    def save_analysis_report(self, analysis: Dict[str, Any]):
        """Save analysis report to JSON and markdown files."""
        # Create subdirectories for proper organization
        data_dir = self.output_dir.parent / "data"
        reports_dir = self.output_dir.parent / "reports"
        data_dir.mkdir(exist_ok=True)
        reports_dir.mkdir(exist_ok=True)

        # Save detailed JSON report to data directory
        json_file = data_dir / "utilization_userspace_report.json"
        with open(json_file, "w") as f:
            json.dump(analysis, f, indent=2, default=str)

        # Generate markdown report to reports directory
        md_file = reports_dir / "utilization_userspace_report.md"
        with open(md_file, "w") as f:
            f.write("# ABD Protocol CPU Utilization Analysis Report\n\n")
            f.write(f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # Metadata
            if analysis.get("metadata"):
                f.write("## Monitoring Session Information\n\n")
                metadata = analysis["metadata"]
                f.write(f"- **Duration**: {metadata.get('duration', 'N/A'):.1f} seconds\n")
                f.write(f"- **Sample Interval**: {metadata.get('sample_interval', 'N/A')} seconds\n")
                f.write(f"- **Total Samples**: {metadata.get('total_samples', 'N/A')}\n\n")

            # System analysis
            if analysis.get("system_analysis"):
                sys_analysis = analysis["system_analysis"]
                f.write("## System-Wide CPU Analysis\n\n")

                if "cpu_statistics" in sys_analysis:
                    cpu_stats = sys_analysis["cpu_statistics"]
                    f.write("### CPU Utilization Statistics\n\n")
                    f.write(f"- **Average**: {cpu_stats.get('mean', 0):.2f}%\n")
                    f.write(f"- **Maximum**: {cpu_stats.get('max', 0):.2f}%\n")
                    f.write(f"- **95th Percentile**: {cpu_stats.get('p95', 0):.2f}%\n")
                    f.write(f"- **Standard Deviation**: {cpu_stats.get('std', 0):.2f}%\n\n")

                if "memory_statistics" in sys_analysis:
                    mem_stats = sys_analysis["memory_statistics"]
                    f.write("### Memory Usage Statistics\n\n")
                    f.write(f"- **Average**: {mem_stats.get('mean', 0):.2f}%\n")
                    f.write(f"- **Peak Usage**: {mem_stats.get('peak_usage_gb', 0):.2f} GB\n\n")

            # Process analysis
            if analysis.get("process_analysis") and analysis["process_analysis"].get("top_cpu_processes"):
                f.write("## Process-Specific Analysis\n\n")
                f.write("### Top CPU Consuming Processes\n\n")
                for name, stats in analysis["process_analysis"]["top_cpu_processes"].items():
                    f.write(f"- **{name}**: {stats.get('cpu_mean', 0):.2f}% avg, {stats.get('cpu_max', 0):.2f}% max\n")
                f.write("\n")

            # Recommendations
            if analysis.get("recommendations"):
                f.write("## Performance Recommendations\n\n")
                for i, rec in enumerate(analysis["recommendations"], 1):
                    f.write(f"{i}. {rec}\n")
                f.write("\n")

        logger.info(f"Analysis reports saved to {json_file} and {md_file}")


def main():
    """Main entry point for CPU analysis tool."""
    parser = argparse.ArgumentParser(description="Analyze ABD Protocol CPU monitoring data")
    parser.add_argument(
        "--input-dir",
        default="evaluation_results/data",
        help="Directory containing CPU monitoring JSON files (default: evaluation_results/data)",
    )
    parser.add_argument(
        "--output-dir",
        default="evaluation_results/figures",
        help="Output directory for analysis results (default: evaluation_results/figures)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "both"],
        default="both",
        help="Output format for reports (default: both)",
    )

    args = parser.parse_args()

    if not ANALYSIS_AVAILABLE:
        logger.error("Required packages not available. Install with: pip install pandas matplotlib seaborn")
        return 1

    # Initialize analyzer
    analyzer = CPUAnalyzer(args.input_dir, args.output_dir)

    # Load data
    if not analyzer.load_monitoring_data():
        logger.error("Failed to load CPU monitoring data")
        return 1

    # Generate analysis
    logger.info("Generating CPU utilization analysis...")
    analysis = analyzer.generate_analysis_report()

    if not analysis:
        logger.error("Failed to generate analysis report")
        return 1

    # Create visualizations
    logger.info("Creating visualizations...")
    analyzer.create_visualizations()

    # Save reports
    logger.info("Saving analysis reports...")
    analyzer.save_analysis_report(analysis)

    logger.info("CPU analysis completed successfully!")
    return 0


if __name__ == "__main__":
    exit(main())
