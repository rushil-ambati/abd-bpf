#!/usr/bin/env python3
"""
eBPF Program Utilization Analysis Tool for ABD Protocol Evaluation

This script analyzes eBPF program monitoring data collected during eBPF ABD protocol
benchmarks and generates comprehensive reports and visualizations.

Usage:
    python3 scripts/analyze_ebpf.py [--input-dir DIR] [--output-dir DIR] [--format FORMAT]

Author: ABD Protocol Research Team
"""

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Dict, Any

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


class eBPFAnalyzer:
    """
    Analyzes eBPF program utilization data from ABD protocol monitoring.

    Provides comprehensive analysis including:
    - eBPF program run_time_ns trends
    - Per-program CPU utilization patterns
    - Program execution frequency analysis
    - Statistical summaries and performance insights
    """

    def __init__(self, input_dir: Path, output_dir: Path):
        """
        Initialize eBPF analyzer.

        Args:
            input_dir: Directory containing eBPF monitoring JSON files
            output_dir: Directory to save analysis results
        """
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.output_dir.mkdir(exist_ok=True)

        # Data storage
        self.raw_data = {}
        self.processed_data = {}
        self.summary_stats = {}

        logger.info(f"eBPF Analyzer initialized: input={input_dir}, output={output_dir}")

    def load_data(self) -> bool:
        """
        Load eBPF monitoring data from JSON files.

        Returns:
            True if data loaded successfully, False otherwise
        """
        try:
            ebpf_files = list(self.input_dir.glob("ebpf_monitor_*.json"))

            if not ebpf_files:
                logger.error(f"No eBPF monitoring files found in {self.input_dir}")
                return False

            logger.info(f"Found {len(ebpf_files)} eBPF monitoring files")

            for file_path in ebpf_files:
                try:
                    with open(file_path, "r") as f:
                        data = json.load(f)

                    file_key = file_path.stem
                    self.raw_data[file_key] = data
                    logger.info(f"Loaded {file_path.name}: {len(data.get('samples', []))} samples")

                except Exception as e:
                    logger.error(f"Failed to load {file_path}: {e}")
                    continue

            if not self.raw_data:
                logger.error("Failed to load any eBPF monitoring data")
                return False

            logger.info(f"Successfully loaded data from {len(self.raw_data)} files")
            return True

        except Exception as e:
            logger.error(f"Error loading eBPF data: {e}")
            return False

    def process_data(self):
        """Process raw eBPF data for analysis."""
        try:
            for file_key, data in self.raw_data.items():
                samples = data.get("samples", [])
                if not samples:
                    logger.warning(f"No samples found in {file_key}")
                    continue

                # Convert to DataFrame for easier analysis
                program_data = []
                for sample in samples:
                    timestamp = sample.get("timestamp", 0)
                    relative_time = sample.get("relative_time", 0)

                    for prog in sample.get("programs", []):
                        program_data.append(
                            {
                                "timestamp": timestamp,
                                "relative_time": relative_time,
                                "program_id": prog.get("id"),
                                "program_name": prog.get("name"),
                                "program_type": prog.get("type"),
                                "run_time_ns": prog.get("run_time_ns", 0),
                                "run_cnt": prog.get("run_cnt", 0),
                                "delta_run_time_ns": prog.get("delta_run_time_ns", 0),
                                "avg_time_per_run_ns": prog.get("avg_time_per_run_ns", 0),
                            }
                        )

                if program_data:
                    df = pd.DataFrame(program_data)
                    self.processed_data[file_key] = df
                    logger.info(f"Processed {len(program_data)} program samples from {file_key}")

            logger.info(f"Data processing completed for {len(self.processed_data)} datasets")

        except Exception as e:
            logger.error(f"Error processing eBPF data: {e}")

    def calculate_statistics(self):
        """Calculate comprehensive statistics for eBPF program utilization."""
        try:
            for file_key, df in self.processed_data.items():
                stats = {}

                # Overall statistics
                total_programs = df["program_id"].nunique()
                total_samples = len(df)
                duration = df["relative_time"].max() - df["relative_time"].min()

                stats["overview"] = {
                    "total_programs": int(total_programs),
                    "total_samples": int(total_samples),
                    "duration_seconds": float(duration),
                    "sample_rate": float(total_samples / duration) if duration > 0 else 0,
                }

                # Per-program statistics
                stats["programs"] = {}
                for prog_name in df["program_name"].unique():
                    if pd.isna(prog_name):
                        continue

                    prog_df = df[df["program_name"] == prog_name]

                    # Calculate utilization statistics
                    # total_delta_time = prog_df["delta_run_time_ns"].sum()
                    total_runtime_ns = prog_df["run_time_ns"].max() - prog_df["run_time_ns"].min()
                    total_runs = prog_df["run_cnt"].max() - prog_df["run_cnt"].min()

                    # Convert to more readable units
                    total_runtime_ms = total_runtime_ns / 1_000_000
                    avg_runtime_per_call_ns = total_runtime_ns / total_runs if total_runs > 0 else 0

                    stats["programs"][prog_name] = {
                        "total_runtime_ns": int(total_runtime_ns),
                        "total_runtime_ms": float(total_runtime_ms),
                        "total_runs": int(total_runs),
                        "avg_runtime_per_call_ns": float(avg_runtime_per_call_ns),
                        "avg_runtime_per_call_us": float(avg_runtime_per_call_ns / 1000),
                        "samples": int(len(prog_df)),
                        "program_type": prog_df["program_type"].iloc[0] if len(prog_df) > 0 else "unknown",
                    }

                # Calculate utilization rates and trends
                if len(df) > 1:
                    # Calculate per-second utilization
                    time_bins = np.arange(0, df["relative_time"].max() + 1, 1.0)
                    utilization_per_second = []

                    for i in range(len(time_bins) - 1):
                        bin_start = time_bins[i]
                        bin_end = time_bins[i + 1]

                        bin_df = df[(df["relative_time"] >= bin_start) & (df["relative_time"] < bin_end)]
                        total_delta_ns = bin_df["delta_run_time_ns"].sum()

                        utilization_per_second.append(
                            {
                                "time_bin": bin_start,
                                "total_utilization_ns": total_delta_ns,
                                "total_utilization_ms": total_delta_ns / 1_000_000,
                            }
                        )

                    stats["utilization_timeline"] = utilization_per_second

                self.summary_stats[file_key] = stats
                logger.info(f"Statistics calculated for {file_key}")

        except Exception as e:
            logger.error(f"Error calculating statistics: {e}")

    def generate_visualizations(self):
        """Generate visualizations for eBPF program utilization."""
        if not ANALYSIS_AVAILABLE:
            logger.warning("Visualization libraries not available. Install pandas, matplotlib, seaborn, numpy")
            return

        try:
            # Set up matplotlib style
            plt.style.use("default")
            sns.set_palette("husl")

            for file_key, df in self.processed_data.items():
                if df.empty:
                    continue

                # Create figure directory
                fig_dir = self.output_dir / "figures" / file_key
                fig_dir.mkdir(parents=True, exist_ok=True)

                # 1. Program Runtime Timeline
                self._plot_runtime_timeline(df, fig_dir, file_key)

                # 2. Program Utilization Comparison
                self._plot_program_comparison(df, fig_dir, file_key)

                # 3. Average Runtime per Call
                self._plot_avg_runtime(df, fig_dir, file_key)

                # 4. Program Execution Frequency
                self._plot_execution_frequency(df, fig_dir, file_key)

                logger.info(f"Visualizations generated for {file_key}")

        except Exception as e:
            logger.error(f"Error generating visualizations: {e}")

    def _plot_runtime_timeline(self, df: pd.DataFrame, fig_dir: Path, file_key: str):
        """Plot eBPF program runtime over time."""
        try:
            plt.figure(figsize=(12, 8))

            for prog_name in df["program_name"].unique():
                if pd.isna(prog_name):
                    continue

                prog_df = df[df["program_name"] == prog_name]
                plt.plot(
                    prog_df["relative_time"],
                    prog_df["delta_run_time_ns"] / 1_000_000,
                    label=prog_name,
                    marker="o",
                    alpha=0.7,
                )

            plt.xlabel("Time (seconds)")
            plt.ylabel("Delta Runtime (ms)")
            plt.title(f"eBPF Program Runtime Timeline - {file_key}")
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.tight_layout()

            # Save in multiple formats
            for fmt in ["png", "pdf", "svg"]:
                plt.savefig(fig_dir / f"runtime_timeline.{fmt}", dpi=300, bbox_inches="tight")

            plt.close()

        except Exception as e:
            logger.error(f"Error plotting runtime timeline: {e}")

    def _plot_program_comparison(self, df: pd.DataFrame, fig_dir: Path, file_key: str):
        """Plot comparison of program utilization."""
        try:
            # Calculate total runtime per program
            program_totals = df.groupby("program_name")["delta_run_time_ns"].sum() / 1_000_000

            if len(program_totals) == 0:
                return

            plt.figure(figsize=(10, 6))
            bars = plt.bar(program_totals.index, program_totals.values)

            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width() / 2.0, height, f"{height:.2f}ms", ha="center", va="bottom")

            plt.xlabel("eBPF Program")
            plt.ylabel("Total Runtime (ms)")
            plt.title(f"eBPF Program Runtime Comparison - {file_key}")
            plt.xticks(rotation=45)
            plt.tight_layout()

            # Save in multiple formats
            for fmt in ["png", "pdf", "svg"]:
                plt.savefig(fig_dir / f"program_comparison.{fmt}", dpi=300, bbox_inches="tight")

            plt.close()

        except Exception as e:
            logger.error(f"Error plotting program comparison: {e}")

    def _plot_avg_runtime(self, df: pd.DataFrame, fig_dir: Path, file_key: str):
        """Plot average runtime per call for each program."""
        try:
            # Calculate average runtime per call for each program
            avg_runtime = df.groupby("program_name")["avg_time_per_run_ns"].mean() / 1000  # Convert to microseconds

            if len(avg_runtime) == 0:
                return

            plt.figure(figsize=(10, 6))
            bars = plt.bar(avg_runtime.index, avg_runtime.values)

            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width() / 2.0, height, f"{height:.2f}μs", ha="center", va="bottom")

            plt.xlabel("eBPF Program")
            plt.ylabel("Average Runtime per Call (μs)")
            plt.title(f"eBPF Program Average Runtime per Call - {file_key}")
            plt.xticks(rotation=45)
            plt.tight_layout()

            # Save in multiple formats
            for fmt in ["png", "pdf", "svg"]:
                plt.savefig(fig_dir / f"avg_runtime_per_call.{fmt}", dpi=300, bbox_inches="tight")

            plt.close()

        except Exception as e:
            logger.error(f"Error plotting average runtime: {e}")

    def _plot_execution_frequency(self, df: pd.DataFrame, fig_dir: Path, file_key: str):
        """Plot execution frequency over time."""
        try:
            plt.figure(figsize=(12, 8))

            for prog_name in df["program_name"].unique():
                if pd.isna(prog_name):
                    continue

                prog_df = df[df["program_name"] == prog_name]
                # Calculate run count deltas (executions per sample period)
                run_deltas = prog_df["run_cnt"].diff().fillna(0)
                plt.plot(prog_df["relative_time"], run_deltas, label=prog_name, marker="o", alpha=0.7)

            plt.xlabel("Time (seconds)")
            plt.ylabel("Executions per Sample Period")
            plt.title(f"eBPF Program Execution Frequency - {file_key}")
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.tight_layout()

            # Save in multiple formats
            for fmt in ["png", "pdf", "svg"]:
                plt.savefig(fig_dir / f"execution_frequency.{fmt}", dpi=300, bbox_inches="tight")

            plt.close()

        except Exception as e:
            logger.error(f"Error plotting execution frequency: {e}")

    def generate_reports(self, output_format: str = "markdown"):
        """Generate comprehensive analysis reports."""
        try:
            if output_format == "markdown":
                self._generate_markdown_report()
            elif output_format == "json":
                self._generate_json_report()
            else:
                logger.error(f"Unsupported output format: {output_format}")

        except Exception as e:
            logger.error(f"Error generating reports: {e}")

    def _generate_markdown_report(self):
        """Generate detailed Markdown report."""
        try:
            report_path = self.output_dir / "ebpf_analysis_report.md"

            with open(report_path, "w") as f:
                f.write("# eBPF Program Utilization Analysis Report\n\n")
                f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Analysis Directory:** `{self.input_dir}`\n\n")

                for file_key, stats in self.summary_stats.items():
                    f.write(f"## Dataset: {file_key}\n\n")

                    # Overview
                    overview = stats.get("overview", {})
                    f.write("### Overview\n\n")
                    f.write(f"- **Total Programs Monitored:** {overview.get('total_programs', 0)}\n")
                    f.write(f"- **Total Samples:** {overview.get('total_samples', 0)}\n")
                    f.write(f"- **Monitoring Duration:** {overview.get('duration_seconds', 0):.2f} seconds\n")
                    f.write(f"- **Sample Rate:** {overview.get('sample_rate', 0):.2f} samples/second\n\n")

                    # Program Statistics
                    f.write("### Program Statistics\n\n")
                    f.write("| Program | Type | Total Runtime (ms) | Total Runs | Avg Runtime/Call (μs) | Samples |\n")
                    f.write("|---------|------|-------------------|------------|----------------------|----------|\n")

                    programs = stats.get("programs", {})
                    for prog_name, prog_stats in programs.items():
                        f.write(
                            f"| {prog_name} | {prog_stats.get('program_type', 'unknown')} | "
                            f"{prog_stats.get('total_runtime_ms', 0):.3f} | "
                            f"{prog_stats.get('total_runs', 0)} | "
                            f"{prog_stats.get('avg_runtime_per_call_us', 0):.3f} | "
                            f"{prog_stats.get('samples', 0)} |\n"
                        )

                    f.write("\n")

                    # Performance Insights
                    f.write("### Performance Insights\n\n")
                    self._write_performance_insights(f, programs)
                    f.write("\n")

            logger.info(f"Markdown report generated: {report_path}")

        except Exception as e:
            logger.error(f"Error generating Markdown report: {e}")

    def _write_performance_insights(self, f, programs: Dict[str, Any]):
        """Write performance insights to report."""
        if not programs:
            f.write("- No program data available for analysis\n")
            return

        # Find most utilized program
        most_utilized = max(programs.items(), key=lambda x: x[1].get("total_runtime_ms", 0))
        f.write(
            f"- **Most CPU-intensive program:** {most_utilized[0]} "
            f"({most_utilized[1].get('total_runtime_ms', 0):.3f} ms total runtime)\n"
        )

        # Find most frequently called program
        most_frequent = max(programs.items(), key=lambda x: x[1].get("total_runs", 0))
        f.write(
            f"- **Most frequently executed:** {most_frequent[0]} "
            f"({most_frequent[1].get('total_runs', 0)} total executions)\n"
        )

        # Find most efficient program (lowest avg runtime per call)
        efficient_programs = [(name, stats) for name, stats in programs.items() if stats.get("total_runs", 0) > 0]
        if efficient_programs:
            most_efficient = min(efficient_programs, key=lambda x: x[1].get("avg_runtime_per_call_us", float("inf")))
            f.write(
                f"- **Most efficient program:** {most_efficient[0]} "
                f"({most_efficient[1].get('avg_runtime_per_call_us', 0):.3f} μs average per call)\n"
            )

    def _generate_json_report(self):
        """Generate JSON format report."""
        try:
            report_path = self.output_dir / "ebpf_analysis_report.json"

            report_data = {
                "metadata": {
                    "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "analysis_directory": str(self.input_dir),
                    "datasets_analyzed": len(self.summary_stats),
                },
                "analysis_results": self.summary_stats,
            }

            with open(report_path, "w") as f:
                json.dump(report_data, f, indent=2)

            logger.info(f"JSON report generated: {report_path}")

        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")

    def run_analysis(self, output_format: str = "markdown") -> bool:
        """
        Run complete eBPF utilization analysis.

        Args:
            output_format: Output format for reports ('markdown' or 'json')

        Returns:
            True if analysis completed successfully, False otherwise
        """
        try:
            logger.info("Starting eBPF utilization analysis...")

            # Load data
            if not self.load_data():
                return False

            # Process data
            if not ANALYSIS_AVAILABLE:
                logger.warning("Analysis libraries not available. Skipping advanced processing.")
                return False

            self.process_data()
            self.calculate_statistics()
            self.generate_visualizations()
            self.generate_reports(output_format)

            logger.info("eBPF analysis completed successfully!")
            return True

        except Exception as e:
            logger.error(f"Error during eBPF analysis: {e}")
            return False


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Analyze eBPF program utilization data from ABD protocol monitoring")

    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("logs"),
        help="Directory containing eBPF monitoring JSON files (default: logs)",
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("ebpf_analysis"),
        help="Directory to save analysis results (default: ebpf_analysis)",
    )

    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format for reports (default: markdown)",
    )

    return parser.parse_args()


def main():
    """Main entry point for eBPF analysis tool."""
    args = parse_args()

    if not ANALYSIS_AVAILABLE:
        logger.error(
            "Required analysis libraries not available. Please install: pip install pandas matplotlib seaborn numpy"
        )
        return 1

    # Initialize analyzer
    analyzer = eBPFAnalyzer(args.input_dir, args.output_dir)

    # Run analysis
    success = analyzer.run_analysis(args.format)

    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
