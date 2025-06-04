#!/usr/bin/env python3
"""
ABD Protocol Comprehensive Evaluation Script

This script performs comprehensive benchmarks and analysis on both userspace and eBPF
implementations of the ABD protocol, including latency and throughput evaluation,
statistical analysis, and publication-quality visualizations for academic research.

Author: ABD Protocol Research Team
Version: 2.0.0
License: MIT
"""

import argparse
import logging
import time
from pathlib import Path
from typing import Any, Dict, List

import matplotlib.pyplot as plt
from evaluation.benchmark_runner import BenchmarkRunner
from evaluation.config import EvaluationConfig, setup_matplotlib
from evaluation.latency_analyzer import LatencyAnalyzer
from evaluation.report_generator import ReportGenerator
from evaluation.scalability_analyzer import ScalabilityAnalyzer
from evaluation.throughput_analyzer import ThroughputAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("evaluation.log")],
)
logger = logging.getLogger(__name__)


class ABDEvaluator:
    """
    Main evaluation orchestrator for ABD protocol implementations.

    Coordinates benchmarking, analysis, and reporting across latency and throughput
    dimensions to provide comprehensive performance evaluation.
    """

    def __init__(self, config: EvaluationConfig):
        """Initialize evaluator with configuration."""
        self.config = config
        self.config.output_dir.mkdir(exist_ok=True)

        # Initialize components
        self.benchmark_runner = BenchmarkRunner(config)
        self.latency_analyzer = LatencyAnalyzer(config)
        self.throughput_analyzer = ThroughputAnalyzer(config)
        self.scalability_analyzer = ScalabilityAnalyzer(config)
        self.report_generator = ReportGenerator(config)

        logger.info(f"Initialized ABD evaluator with output directory: {config.output_dir}")

    def run_full_evaluation(self, skip_benchmarks: bool = False) -> Dict[str, Any]:
        """
        Execute complete evaluation pipeline.

        Args:
            skip_benchmarks: If True, load existing results instead of running new benchmarks

        Returns:
            Dictionary containing all analysis results
        """
        logger.info("Starting ABD Protocol Comprehensive Evaluation")
        logger.info("=" * 60)

        start_time = time.time()

        try:
            # Step 1: Run or load benchmarks
            if skip_benchmarks:
                logger.info("Loading existing benchmark results...")
                benchmark_results = self.benchmark_runner.load_existing_results()
            else:
                logger.info("Running benchmarks...")
                benchmark_results = self.benchmark_runner.run_all_benchmarks()

            # Step 2: Perform analyses
            logger.info("Performing comprehensive analysis...")

            # Latency analysis
            logger.info("Analyzing latency data...")
            latency_analysis = self.latency_analyzer.analyze_results(
                benchmark_results["latency"]["ebpf"], benchmark_results["latency"]["userspace"]
            )

            # Throughput analysis
            logger.info("Analyzing throughput data...")
            throughput_analysis = self.throughput_analyzer.analyze_results(
                benchmark_results["throughput"]["ebpf"], benchmark_results["throughput"]["userspace"]
            )

            # Step 3: Generate visualizations
            logger.info("Generating visualizations...")

            # Latency visualizations
            self.latency_analyzer.create_all_visualizations(
                benchmark_results["latency"]["ebpf"], benchmark_results["latency"]["userspace"]
            )

            # Throughput visualizations
            self.throughput_analyzer.create_all_visualizations(
                benchmark_results["throughput"]["ebpf"],
                benchmark_results["throughput"]["userspace"],
                throughput_analysis,
            )

            # Combined analysis visualizations
            self._create_combined_visualizations(benchmark_results)

            # Step 4: Generate comprehensive report
            logger.info("Generating comprehensive report...")

            combined_analysis = {
                "latency": latency_analysis,
                "throughput": throughput_analysis,
                "benchmark_results": benchmark_results,
                "evaluation_metadata": {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "duration_seconds": time.time() - start_time,
                    "config": self.config.to_dict(),
                },
            }

            self.report_generator.generate_comprehensive_report(combined_analysis)

            # Step 5: Summary
            duration = time.time() - start_time
            logger.info(f"Evaluation completed successfully in {duration:.1f} seconds")
            logger.info(f"Results available in: {self.config.output_dir}")
            logger.info(f"Main report: {self.config.output_dir}/evaluation_report.md")

            return combined_analysis

        except Exception as e:
            logger.error(f"Evaluation failed: {e}")
            raise

    def run_scalability_evaluation(
        self, node_counts: List[int] = None, skip_benchmarks: bool = False
    ) -> Dict[str, Any]:
        """
        Execute comprehensive scalability evaluation.

        Args:
            node_counts: List of node counts to test (if None, auto-detect from existing results)
            skip_benchmarks: If True, skip benchmarks and load existing results

        Returns:
            Dictionary containing scalability analysis results
        """
        logger.info("Starting ABD Protocol Scalability Evaluation")
        logger.info("=" * 60)

        start_time = time.time()

        try:
            # Auto-detect node counts if not provided and skip_benchmarks is enabled
            if node_counts is None and skip_benchmarks:
                detected_counts = self.scalability_analyzer.detect_existing_node_counts()
                if detected_counts:
                    node_counts = detected_counts
                    logger.info(f"Auto-detected node counts from existing results: {node_counts}")
                else:
                    logger.warning("No existing results found, using default node counts")
                    node_counts = None  # Will use default in the analyzer

            # Step 1: Run scalability benchmarks
            logger.info("Running scalability benchmarks...")
            scalability_results = self.scalability_analyzer.run_scalability_benchmarks(
                node_counts, skip_benchmarks=skip_benchmarks
            )

            # Step 2: Analyze scalability results
            logger.info("Analyzing scalability data...")
            scalability_analysis = self.scalability_analyzer.analyze_scalability_results(scalability_results)

            # Step 3: Generate scalability visualizations
            logger.info("Generating scalability visualizations...")
            self.scalability_analyzer.create_scalability_visualizations(scalability_analysis)

            # Step 4: Combine with existing analysis format
            combined_analysis = {
                "scalability": {
                    "results": scalability_results,
                    "analysis": scalability_analysis,
                },
                "evaluation_metadata": {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "duration_seconds": time.time() - start_time,
                    "evaluation_type": "scalability",
                    "config": self.config.to_dict(),
                },
            }

            # Step 5: Generate scalability report
            logger.info("Generating scalability report...")
            self._generate_scalability_report(combined_analysis)

            # Step 6: Summary
            duration = time.time() - start_time
            logger.info(f"Scalability evaluation completed successfully in {duration:.1f} seconds")
            logger.info(f"Results available in: {self.config.output_dir}")

            return combined_analysis

        except Exception as e:
            logger.error(f"Scalability evaluation failed: {e}")
            raise

    def _create_combined_visualizations(self, benchmark_results: Dict):
        """Create visualizations that combine latency and throughput insights."""

        # Throughput vs Latency scatter plot
        _, ax = plt.subplots(figsize=(12, 8))

        for impl in ["ebpf", "userspace"]:
            throughput_data = benchmark_results["throughput"][impl]

            # Extract data points for scatter plot
            rps = throughput_data["summary"]["rps"]
            avg_latency = throughput_data["summary"]["latency_summary"]["avg_us"]

            # Use implementation-specific colors
            color = self.config.colors[impl]
            ax.scatter(rps, avg_latency, label=impl.title(), s=100, alpha=0.7, color=color)

        ax.set_xlabel("Throughput (RPS)")
        ax.set_ylabel("Average Latency (μs)")
        ax.set_title("Throughput vs Latency Trade-off")
        ax.legend()
        ax.grid(True, alpha=0.3)

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(self.config.figures_dir / f"throughput_latency_tradeoff.{fmt}", dpi=300, bbox_inches="tight")
        plt.close()

        logger.info("Generated combined throughput-latency visualization")

    def _generate_scalability_report(self, analysis: Dict[str, Any]):
        """Generate comprehensive scalability report."""

        report_path = self.config.reports_dir / "scalability_report.md"

        with open(report_path, "w", encoding="utf-8") as f:
            # Header
            f.write("# ABD Protocol Scalability Analysis\n")
            f.write("## Performance Scaling with Node Count\n\n")
            f.write("---\n\n")

            metadata = analysis.get("evaluation_metadata", {})
            f.write(f"**Generated:** {metadata.get('timestamp', 'N/A')}\n")
            f.write(f"**Analysis Duration:** {metadata.get('duration_seconds', 0):.1f} seconds\n")
            f.write("**Evaluation Type:** Scalability Benchmark\n\n")

            scalability_data = analysis.get("scalability", {})
            results = scalability_data.get("results", {})
            analysis_data = scalability_data.get("analysis", {})

            # Executive Summary
            f.write("## Executive Summary\n\n")
            node_counts = results.get("node_counts", [])
            f.write(f"**Node Counts Tested:** {', '.join(map(str, node_counts))}\n")

            recommendations = analysis_data.get("recommendations", [])
            f.write("\n### Key Findings\n\n")
            for rec in recommendations[:5]:  # Top 5 recommendations
                f.write(f"- {rec}\n")
            f.write("\n")

            # Latency Scaling Analysis
            f.write("## Latency Scaling Analysis\n\n")
            latency_scaling = analysis_data.get("latency_scaling", {})

            f.write("### Write Latency Trends\n\n")
            for impl in ["ebpf", "userspace"]:
                impl_data = latency_scaling.get(impl, {})
                scaling_trends = impl_data.get("scaling_trends", {})

                f.write(f"**{impl.title()} Implementation:**\n")
                if "write_correlation" in scaling_trends:
                    corr = scaling_trends["write_correlation"]
                    trend = "increases" if corr > 0 else "decreases" if corr < 0 else "remains stable"
                    f.write(f"- Write latency {trend} with node count (correlation: {corr:.3f})\n")
                f.write("\n")

            # Throughput Scaling Analysis
            f.write("## Throughput Scaling Analysis\n\n")
            throughput_scaling = analysis_data.get("throughput_scaling", {})

            for impl in ["ebpf", "userspace"]:
                impl_data = throughput_scaling.get(impl, {})
                scaling_efficiency = impl_data.get("scaling_efficiency", {})

                f.write(f"### {impl.title()} Throughput Scaling\n\n")

                node_counts = impl_data.get("node_counts", [])
                rps_values = impl_data.get("rps_values", [])

                if node_counts and rps_values:
                    f.write(f"- **Node Range:** {min(node_counts)} to {max(node_counts)} nodes\n")
                    f.write(f"- **Throughput Range:** {min(rps_values):.0f} to {max(rps_values):.0f} RPS\n")

                    if len(rps_values) >= 2:
                        improvement = ((rps_values[-1] - rps_values[0]) / rps_values[0]) * 100
                        f.write(f"- **Overall Improvement:** {improvement:+.1f}%\n")

                avg_efficiency = scaling_efficiency.get("average_efficiency", 0)
                if avg_efficiency:
                    f.write(f"- **Average Scaling Efficiency:** {avg_efficiency:.1f} RPS per additional node\n")

                f.write("\n")

            # Coordination Overhead
            f.write("## Coordination Overhead Analysis\n\n")
            coordination_analysis = analysis_data.get("coordination_overhead", {})

            for impl in ["ebpf", "userspace"]:
                metrics = coordination_analysis.get(impl, [])
                if metrics:
                    f.write(f"### {impl.title()} Coordination Costs\n\n")
                    for metric in metrics:
                        node_count = metric["node_count"]
                        majority_size = metric["majority_size"]
                        overhead = metric["coordination_cost"] * 100
                        f.write(f"- **{node_count} nodes:** {majority_size} majority, {overhead:.1f}% overhead\n")
                    f.write("\n")

            # Optimal Configuration
            f.write("## Optimal Configuration Recommendations\n\n")
            performance_trends = analysis_data.get("performance_trends", {})

            for impl in ["ebpf", "userspace"]:
                optimal_info = performance_trends.get(impl, {}).get("optimal_node_count", {})
                if isinstance(optimal_info, dict) and "optimal_count" in optimal_info:
                    optimal_count = optimal_info["optimal_count"]
                    reasoning = optimal_info.get("reasoning", "")
                    f.write(f"**{impl.title()}:** {optimal_count} nodes - {reasoning}\n\n")

            # Visualizations Index
            f.write("## Generated Visualizations\n\n")
            f.write("The following charts have been generated in the `figures/` directory:\n\n")
            f.write("- `scalability_latency_analysis.{png,svg,pdf}` - Latency scaling charts\n")
            f.write("- `scalability_throughput_analysis.{png,svg,pdf}` - Throughput scaling charts\n")
            f.write("- `scalability_coordination_analysis.{png,svg,pdf}` - Coordination overhead analysis\n")
            f.write("- `scalability_efficiency_analysis.{png,svg,pdf}` - Performance efficiency trends\n")
            f.write("- `scalability_dashboard.{png,svg,pdf}` - Comprehensive overview dashboard\n\n")

        logger.info(f"Scalability report generated: {report_path}")


def create_config_from_args(args) -> EvaluationConfig:
    """Create evaluation configuration from command line arguments."""
    return EvaluationConfig(
        output_dir=Path(args.output),
        debug=args.debug,
        skip_latex=args.skip_latex,
        num_nodes=args.num_nodes if hasattr(args, "num_nodes") else 3,
        sweep=args.sweep,
        scalability_mode=getattr(args, "scalability", False),
        scalability_node_counts=getattr(args, "node_counts", None),
    )


def main():
    """Main entry point for ABD evaluation script."""
    parser = argparse.ArgumentParser(
        description="ABD Protocol Comprehensive Evaluation Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Run full evaluation
  %(prog)s --skip-benchmarks         # Analyze existing results only
  %(prog)s --debug                   # Use debug builds
  %(prog)s --output my_results       # Custom output directory
  %(prog)s --skip-latex              # Disable LaTeX in plots
  %(prog)s --num-nodes 5             # Use 5 nodes for benchmarking
  %(prog)s --sweep                   # Enable sweep load testing
  %(prog)s --scalability             # Run scalability evaluation
  %(prog)s --scalability --node-counts 3 5 7 9 11  # Custom node counts for scalability
        """,
    )

    parser.add_argument(
        "--output", default="evaluation_results", help="Output directory for results (default: evaluation_results)"
    )
    parser.add_argument(
        "--skip-benchmarks", action="store_true", help="Skip running benchmarks and analyze existing results"
    )
    parser.add_argument("--debug", action="store_true", help="Use debug builds for benchmarking")
    parser.add_argument(
        "--skip-latex", action="store_true", help="Disable LaTeX rendering in plots (for systems without LaTeX)"
    )
    parser.add_argument(
        "--num-nodes", type=int, default=3, help="Number of nodes to use for benchmarking (default: 3)"
    )
    parser.add_argument("--sweep", action="store_true", help="Enable sweep load testing for throughput benchmarks")
    parser.add_argument(
        "--scalability", action="store_true", help="Run scalability evaluation across different node counts"
    )
    parser.add_argument(
        "--node-counts",
        type=int,
        nargs="+",
        default=[3, 5, 7, 9, 11],
        help="Node counts to test for scalability evaluation (default: 3 5 7 9 11)",
    )

    args = parser.parse_args()

    # Setup matplotlib
    setup_matplotlib(not args.skip_latex)

    # Create configuration and run evaluation
    config = create_config_from_args(args)
    evaluator = ABDEvaluator(config)

    try:
        if args.scalability:
            # Run scalability evaluation
            # If skip_benchmarks is enabled and no node_counts specified, auto-detect
            node_counts = (
                args.node_counts if not args.skip_benchmarks or args.node_counts != [3, 5, 7, 9, 11] else None
            )
            evaluator.run_scalability_evaluation(node_counts, skip_benchmarks=args.skip_benchmarks)
        else:
            # Run regular full evaluation
            evaluator.run_full_evaluation(skip_benchmarks=args.skip_benchmarks)
    except KeyboardInterrupt:
        logger.info("Evaluation interrupted by user")
    except Exception as e:
        logger.error(f"Evaluation failed: {e}")
        raise


if __name__ == "__main__":
    main()
