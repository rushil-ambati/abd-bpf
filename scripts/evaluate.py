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
from typing import Dict, Any

from evaluation.benchmark_runner import BenchmarkRunner
from evaluation.latency_analyzer import LatencyAnalyzer
from evaluation.throughput_analyzer import ThroughputAnalyzer
from evaluation.report_generator import ReportGenerator
from evaluation.config import EvaluationConfig, setup_matplotlib

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
                benchmark_results["latency"]["ebpf"], benchmark_results["latency"]["userspace"], latency_analysis
            )

            # Throughput visualizations
            self.throughput_analyzer.create_all_visualizations(
                benchmark_results["throughput"]["ebpf"],
                benchmark_results["throughput"]["userspace"],
                throughput_analysis,
            )

            # Combined analysis visualizations
            self._create_combined_visualizations(benchmark_results, latency_analysis, throughput_analysis)

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

    def _create_combined_visualizations(
        self, benchmark_results: Dict, latency_analysis: Dict, throughput_analysis: Dict
    ):
        """Create visualizations that combine latency and throughput insights."""
        import matplotlib.pyplot as plt

        # Throughput vs Latency scatter plot
        fig, ax = plt.subplots(figsize=(12, 8))

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


def create_config_from_args(args) -> EvaluationConfig:
    """Create evaluation configuration from command line arguments."""
    return EvaluationConfig(output_dir=Path(args.output), debug=args.debug, skip_latex=args.skip_latex)


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

    args = parser.parse_args()

    # Setup matplotlib
    setup_matplotlib(not args.skip_latex)

    # Create configuration and run evaluation
    config = create_config_from_args(args)
    evaluator = ABDEvaluator(config)

    try:
        evaluator.run_full_evaluation(skip_benchmarks=args.skip_benchmarks)
    except KeyboardInterrupt:
        logger.info("Evaluation interrupted by user")
    except Exception as e:
        logger.error(f"Evaluation failed: {e}")
        raise


if __name__ == "__main__":
    main()
