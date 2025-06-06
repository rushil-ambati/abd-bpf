"""
Report generation module for ABD protocol evaluation.

Generates comprehensive markdown reports combining latency and throughput
analysis with statistical insights and recommendations.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict

import pandas as pd

from .config import EvaluationConfig

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates comprehensive evaluation reports."""

    def __init__(self, config: EvaluationConfig):
        """Initialize report generator with configuration."""
        self.config = config

    def generate_comprehensive_report(self, analysis: Dict[str, Any]):
        """Generate comprehensive evaluation report combining all analyses."""
        logger.info("Generating comprehensive evaluation report")

        report_path = self.config.reports_dir / "evaluation_report.md"

        with open(report_path, "w", encoding="utf-8") as f:
            self._write_header(f, analysis)
            self._write_executive_summary(f, analysis)
            self._write_throughput_analysis(f, analysis)
            self._write_latency_analysis(f, analysis)
            self._write_combined_insights(f, analysis)
            self._write_statistical_analysis(f, analysis)
            self._write_configuration_details(f, analysis)
            self._write_recommendations(f, analysis)
            self._write_figures_index(f)
            self._write_methodology(f)
            self._write_appendices(f, analysis)

        logger.info(f"Comprehensive report generated: {report_path}")

        # Also generate summary tables as CSV
        self._export_summary_tables(analysis)

    def _write_header(self, f, analysis: Dict[str, Any]):
        """Write report header and metadata."""
        metadata = analysis.get("evaluation_metadata", {})

        f.write("# ABD Protocol Implementation Evaluation\n")
        f.write("## Comprehensive Performance Analysis: eBPF vs Userspace\n\n")
        f.write("---\n\n")
        f.write(f"**Generated:** {metadata.get('timestamp', 'N/A')}\n")
        f.write(f"**Analysis Duration:** {metadata.get('duration_seconds', 0):.1f} seconds\n")
        f.write("**Evaluation Framework Version:** 2.0.0\n")
        f.write("**Analysis Type:** Latency + Throughput Comprehensive Benchmark\n\n")

    def _write_executive_summary(self, f, analysis: Dict[str, Any]):
        """Write executive summary with key findings."""
        f.write("## Executive Summary\n\n")
        throughput_analysis = analysis.get("throughput", {})
        comparative = throughput_analysis.get("comparative_analysis", {})
        performance_improvements = comparative.get("performance_improvements", {})
        winner_analysis = comparative.get("winner_analysis", {})
        f.write("### Key Performance Indicators\n\n")
        throughput_improvement = performance_improvements.get("throughput_improvement_pct", 0)
        latency_improvement = performance_improvements.get("latency_improvement_pct", 0)
        error_improvement = performance_improvements.get("error_improvement_pct", 0)
        f.write(f"- **Throughput Performance**: eBPF shows {throughput_improvement:+.1f}% ")
        f.write(f"{'improvement' if throughput_improvement > 0 else 'degradation'} over userspace\n")
        f.write(f"- **Latency Performance**: eBPF shows {latency_improvement:+.1f}% ")
        f.write(f"{'improvement' if latency_improvement > 0 else 'degradation'} in latency under load\n")
        f.write(f"- **Reliability**: eBPF shows {error_improvement:+.1f}% ")
        f.write(f"{'improvement' if error_improvement > 0 else 'degradation'} in error rate\n\n")
        f.write("### Performance Leadership by Dimension\n\n")
        for dimension, winner in winner_analysis.items():
            f.write(f"- **{dimension.replace('_', ' ').title()}**: {winner.upper()}\n")
        f.write("\n")
        throughput_winner = winner_analysis.get("throughput", "unknown")
        latency_winner = winner_analysis.get("latency", "unknown")
        reliability_winner = winner_analysis.get("reliability", "unknown")
        if throughput_winner == latency_winner == reliability_winner:
            overall_winner = throughput_winner
            f.write("### Overall Recommendation\n\n")
            f.write(f"**{overall_winner.upper()}** implementation demonstrates superior performance ")
            f.write("across all key dimensions (throughput, latency, and reliability).\n\n")
        else:
            f.write("### Overall Assessment\n\n")
            f.write("Performance characteristics vary by dimension. Consider workload requirements:\n")
            f.write(f"- For **maximum throughput**: {throughput_winner.upper()}\n")
            f.write(f"- For **lowest latency**: {latency_winner.upper()}\n")
            f.write(f"- For **highest reliability**: {reliability_winner.upper()}\n\n")

    def _write_throughput_analysis(self, f, analysis: Dict[str, Any]):
        """Write detailed throughput analysis section."""
        f.write("## Throughput Analysis\n\n")

        throughput_analysis = analysis.get("throughput", {})
        ebpf_stats = throughput_analysis.get("ebpf", {}).get("summary_stats", {})
        user_stats = throughput_analysis.get("userspace", {}).get("summary_stats", {})
        comparative = throughput_analysis.get("comparative_analysis", {})

        f.write("### Overall Throughput Performance\n\n")

        # Create performance comparison table
        throughput_data = [
            ["Metric", "eBPF", "Userspace", "Difference"],
            [
                "Overall RPS",
                f"{ebpf_stats.get('overall_rps', 0):.0f}",
                f"{user_stats.get('overall_rps', 0):.0f}",
                f"{comparative.get('absolute_differences', {}).get('rps_difference', 0):+.0f}",
            ],
            ["Write RPS", f"{ebpf_stats.get('write_rps', 0):.0f}", f"{user_stats.get('write_rps', 0):.0f}", ""],
            ["Read RPS", f"{ebpf_stats.get('read_rps', 0):.0f}", f"{user_stats.get('read_rps', 0):.0f}", ""],
            [
                "Success Rate",
                f"{ebpf_stats.get('overall_success_rate', 0)*100:.3f}%",
                f"{user_stats.get('overall_success_rate', 0)*100:.3f}%",
                "",
            ],
            [
                "Error Rate",
                f"{ebpf_stats.get('failure_rate', 0)*100:.3f}%",
                f"{user_stats.get('failure_rate', 0)*100:.3f}%",
                "",
            ],
        ]

        f.write("| Metric | eBPF | Userspace | Difference |\n")
        f.write("|--------|------|-----------|------------|\n")
        for row in throughput_data[1:]:
            f.write(f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} |\n")
        f.write("\n")

        # Thread performance analysis
        ebpf_thread_stats = throughput_analysis.get("ebpf", {}).get("thread_stats", {})
        user_thread_stats = throughput_analysis.get("userspace", {}).get("thread_stats", {})

        f.write("### Thread Performance and Load Balancing\n\n")
        f.write(f"- **eBPF Thread Consistency**: CV = {ebpf_thread_stats.get('rps_stats', {}).get('cv', 0):.3f}\n")
        f.write(
            f"- **Userspace Thread Consistency**: CV = {user_thread_stats.get('rps_stats', {}).get('cv', 0):.3f}\n"
        )
        f.write(f"- **eBPF Load Balance Quality**: {ebpf_thread_stats.get('load_balance_quality', 0):.3f}\n")
        f.write(f"- **Userspace Load Balance Quality**: {user_thread_stats.get('load_balance_quality', 0):.3f}\n\n")

        # Timeline stability
        ebpf_timeline = throughput_analysis.get("ebpf", {}).get("timeline_stats", {})
        user_timeline = throughput_analysis.get("userspace", {}).get("timeline_stats", {})

        f.write("### Performance Stability Over Time\n\n")
        stability_ebpf = ebpf_timeline.get("stability_metrics", {})
        stability_user = user_timeline.get("stability_metrics", {})

        f.write(f"- **eBPF RPS Stability**: CV = {stability_ebpf.get('rps_cv', 0):.3f}\n")
        f.write(f"- **Userspace RPS Stability**: CV = {stability_user.get('rps_cv', 0):.3f}\n")
        f.write(f"- **eBPF Performance Trend**: {stability_ebpf.get('rps_trend', 0):+.2f} RPS/second\n")
        f.write(f"- **Userspace Performance Trend**: {stability_user.get('rps_trend', 0):+.2f} RPS/second\n\n")

    def _write_latency_analysis(self, f, analysis: Dict[str, Any]):
        """Write detailed latency analysis section."""
        f.write("## Latency Analysis\n\n")

        latency_analysis = analysis.get("latency", {})

        for operation in ["write", "read"]:
            if operation in latency_analysis.get("statistical_tests", {}):
                tests = latency_analysis["statistical_tests"][operation]
                if not tests:
                    continue

                ebpf_stats = latency_analysis.get("ebpf", {}).get("statistics", {}).get(operation, {})
                user_stats = latency_analysis.get("userspace", {}).get("statistics", {}).get(operation, {})

                f.write(f"### {operation.title()} Operation Latency\n\n")

                # Statistical significance
                p_value = tests.get("mann_whitney", {}).get("p_value", 1.0)
                cohens_d = tests.get("effect_size", {}).get("cohens_d", 0)
                interpretation = tests.get("effect_size", {}).get("interpretation", "unknown")

                f.write(f"- **Statistical Significance**: p = {p_value:.2e} ")
                f.write(f"({'significant' if p_value < 0.05 else 'not significant'})\n")
                f.write(f"- **Effect Size**: Cohen's d = {cohens_d:.3f} ({interpretation})\n\n")

                # Performance comparison
                if ebpf_stats and user_stats:
                    ebpf_mean = ebpf_stats.get("mean", 0)
                    user_mean = user_stats.get("mean", 0)
                    improvement = ((user_mean - ebpf_mean) / user_mean) * 100 if user_mean > 0 else 0

                    f.write("**Performance Summary:**\n")
                    f.write(f"- eBPF Mean: {ebpf_mean:.3f} μs\n")
                    f.write(f"- Userspace Mean: {user_mean:.3f} μs\n")
                    f.write(f"- eBPF shows {improvement:+.1f}% ")
                    f.write(f"{'improvement' if improvement > 0 else 'degradation'}\n\n")

                    # Percentile comparison
                    f.write("**Latency Percentiles:**\n\n")
                    percentiles = ["p50", "p90", "p95", "p99", "p99_9"]
                    f.write("| Percentile | eBPF (μs) | Userspace (μs) | Difference |\n")
                    f.write("|------------|-----------|----------------|------------|\n")
                    for p in percentiles:
                        ebpf_val = ebpf_stats.get(p, 0)
                        user_val = user_stats.get(p, 0)
                        diff = ebpf_val - user_val
                        p_label = p.replace("p", "P").replace("_", ".")
                        f.write(f"| {p_label} | {ebpf_val:.3f} | {user_val:.3f} | {diff:+.3f} |\n")
                    f.write("\n")

                    # Distribution characteristics
                    f.write("**Distribution Characteristics:**\n")
                    f.write(f"- eBPF Skewness: {ebpf_stats.get('skewness', 0):.3f}\n")
                    f.write(f"- Userspace Skewness: {user_stats.get('skewness', 0):.3f}\n")
                    f.write(f"- eBPF Coefficient of Variation: {ebpf_stats.get('cv', 0):.3f}\n")
                    f.write(f"- Userspace Coefficient of Variation: {user_stats.get('cv', 0):.3f}\n\n")

    def _write_combined_insights(self, f, analysis: Dict[str, Any]):
        """Write insights that combine latency and throughput analysis."""
        f.write("## Combined Performance Insights\n\n")

        throughput_analysis = analysis.get("throughput", {})
        comparative = throughput_analysis.get("comparative_analysis", {})
        efficiency_metrics = comparative.get("efficiency_metrics", {})

        f.write("### Latency-Throughput Trade-offs\n\n")

        # Efficiency analysis
        ebpf_efficiency = efficiency_metrics.get("throughput_per_latency_ebpf", 0)
        user_efficiency = efficiency_metrics.get("throughput_per_latency_userspace", 0)

        f.write(f"- **eBPF Efficiency**: {ebpf_efficiency:.3f} RPS per μs latency\n")
        f.write(f"- **Userspace Efficiency**: {user_efficiency:.3f} RPS per μs latency\n")

        if ebpf_efficiency > user_efficiency:
            improvement = ((ebpf_efficiency - user_efficiency) / user_efficiency) * 100
            f.write(f"- **eBPF** achieves {improvement:.1f}% better throughput-latency efficiency\n\n")
        else:
            degradation = ((user_efficiency - ebpf_efficiency) / user_efficiency) * 100
            f.write(f"- **Userspace** achieves {degradation:.1f}% better throughput-latency efficiency\n\n")

        # Performance characteristics under load
        ebpf_summary = throughput_analysis.get("ebpf", {}).get("summary_stats", {})
        user_summary = throughput_analysis.get("userspace", {}).get("summary_stats", {})

        f.write("### Performance Under Load\n\n")
        f.write(f"- **eBPF Latency under {ebpf_summary.get('overall_rps', 0):.0f} RPS**: ")
        f.write(f"{ebpf_summary.get('avg_latency_us', 0):.1f} μs average\n")
        f.write(f"- **Userspace Latency under {user_summary.get('overall_rps', 0):.0f} RPS**: ")
        f.write(f"{user_summary.get('avg_latency_us', 0):.1f} μs average\n\n")

        # Tail latency under load
        f.write("### Tail Latency Performance\n\n")
        f.write(f"- **eBPF P99 under load**: {ebpf_summary.get('p99_latency_us', 0):.1f} μs\n")
        f.write(f"- **Userspace P99 under load**: {user_summary.get('p99_latency_us', 0):.1f} μs\n")
        f.write(f"- **eBPF Max under load**: {ebpf_summary.get('max_latency_us', 0):.1f} μs\n")
        f.write(f"- **Userspace Max under load**: {user_summary.get('max_latency_us', 0):.1f} μs\n\n")

    def _write_statistical_analysis(self, f, analysis: Dict[str, Any]):
        """Write detailed statistical analysis section."""
        f.write("## Statistical Analysis\n\n")

        latency_analysis = analysis.get("latency", {})
        throughput_analysis = analysis.get("throughput", {})

        f.write("### Latency Statistical Tests\n\n")

        for operation in ["write", "read"]:
            tests = latency_analysis.get("statistical_tests", {}).get(operation, {})
            if not tests:
                continue

            f.write(f"#### {operation.title()} Operations\n\n")

            # Test results
            mw_test = tests.get("mann_whitney", {})
            t_test = tests.get("t_test", {})
            normality = tests.get("normality_tests", {})
            variance = tests.get("variance_test", {})
            effect_size = tests.get("effect_size", {})

            f.write("**Hypothesis Testing:**\n")
            f.write(f"- Mann-Whitney U: U = {mw_test.get('statistic', 0):.0f}, ")
            f.write(f"p = {mw_test.get('p_value', 1):.2e}\n")
            f.write(f"- Independent t-test: t = {t_test.get('statistic', 0):.3f}, ")
            f.write(f"p = {t_test.get('p_value', 1):.2e}\n\n")

            f.write("**Distribution Properties:**\n")
            f.write(f"- eBPF Normality (Shapiro): p = {normality.get('ebpf_shapiro', {}).get('p_value', 1):.2e}\n")
            f.write(
                f"- Userspace Normality (Shapiro): p = {normality.get('userspace_shapiro', {}).get('p_value', 1):.2e}\n"
            )
            f.write(f"- Equal Variance (Levene): p = {variance.get('levene_p_value', 1):.2e}\n\n")

            f.write("**Effect Size Analysis:**\n")
            f.write(
                f"- Cohen's d: {effect_size.get('cohens_d', 0):.3f} ({effect_size.get('interpretation', 'unknown')})\n"
            )
            f.write(f"- Hedge's g: {effect_size.get('hedges_g', 0):.3f}\n")
            f.write(f"- Glass's Δ: {effect_size.get('glass_delta', 0):.3f}\n\n")

        # Throughput statistical tests
        timeline_comparison = throughput_analysis.get("comparative_analysis", {}).get("timeline_comparison", {})
        if timeline_comparison:
            f.write("### Throughput Statistical Tests\n\n")
            rps_test = timeline_comparison.get("rps_mann_whitney", {})
            if rps_test:
                f.write("**Timeline RPS Comparison:**\n")
                f.write(f"- Mann-Whitney U: U = {rps_test.get('statistic', 0):.0f}, ")
                f.write(f"p = {rps_test.get('p_value', 1):.2e}\n")
                f.write(f"- Significant: {rps_test.get('significant', False)}\n\n")

    def _write_configuration_details(self, f, analysis: Dict[str, Any]):
        """Write benchmark configuration and system details."""
        f.write("## Configuration and Environment\n\n")

        # Try to extract configuration from benchmark results
        benchmark_results = analysis.get("benchmark_results", {})

        f.write("### Benchmark Configuration\n\n")

        # Latency benchmark config
        latency_config = benchmark_results.get("latency", {}).get("ebpf", {}).get("args", {})
        if latency_config:
            f.write("**Latency Benchmark:**\n")
            f.write(f"- Nodes: {latency_config.get('num_nodes', 'N/A')}\n")
            f.write(f"- Duration: {latency_config.get('duration', 'N/A')} seconds\n")
            f.write(f"- Threads per node: {latency_config.get('threads_per_node', 'N/A')}\n")
            f.write(f"- Timeout: {latency_config.get('timeout_ms', 'N/A')} ms\n\n")

        # Throughput benchmark config
        throughput_config = benchmark_results.get("throughput", {}).get("ebpf", {}).get("args", {})
        if throughput_config:
            f.write("**Throughput Benchmark:**\n")
            f.write(f"- Nodes: {throughput_config.get('num_nodes', 'N/A')}\n")
            f.write(f"- Duration: {throughput_config.get('duration', 'N/A')} seconds\n")
            f.write(f"- Threads per node: {throughput_config.get('threads_per_node', 'N/A')}\n")
            f.write(f"- Write ratio: {throughput_config.get('write_ratio', 'N/A')}\n")
            f.write(f"- Max in flight: {throughput_config.get('max_in_flight', 'N/A')}\n")
            f.write(f"- Timeout: {throughput_config.get('timeout_ms', 'N/A')} ms\n\n")

        # System information
        metadata = benchmark_results.get("throughput", {}).get("ebpf", {}).get("metadata", {})
        system_info = metadata.get("system_info", {})
        if system_info:
            f.write("### System Environment\n\n")
            f.write(f"- **Operating System**: {system_info.get('os', 'N/A')}\n")
            f.write(f"- **Architecture**: {system_info.get('arch', 'N/A')}\n")
            f.write(f"- **CPU Cores**: {system_info.get('cpu_cores', 'N/A')}\n")
            f.write(f"- **Memory**: {system_info.get('memory_mb', 'N/A')} MB\n")
            f.write(f"- **Git Commit**: {metadata.get('git_commit', 'N/A')}\n\n")

    def _write_recommendations(self, f, analysis: Dict[str, Any]):
        """Write recommendations based on analysis results."""
        f.write("## Recommendations\n\n")

        throughput_analysis = analysis.get("throughput", {})
        comparative = throughput_analysis.get("comparative_analysis", {})

        performance_improvements = comparative.get("performance_improvements", {})

        f.write("### Implementation Selection Guidelines\n\n")

        # Analyze patterns to provide recommendations
        throughput_improvement = performance_improvements.get("throughput_improvement_pct", 0)
        latency_improvement = performance_improvements.get("latency_improvement_pct", 0)
        error_improvement = performance_improvements.get("error_improvement_pct", 0)

        if throughput_improvement > 5 and latency_improvement > 5 and error_improvement > 5:
            f.write("**Strong Recommendation: eBPF Implementation**\n\n")
            f.write("eBPF demonstrates clear advantages across all performance dimensions:\n")
            f.write(f"- Superior throughput (+{throughput_improvement:.1f}%)\n")
            f.write(f"- Better latency performance (+{latency_improvement:.1f}%)\n")
            f.write(f"- Improved reliability (+{error_improvement:.1f}%)\n\n")
        elif throughput_improvement < -5 and latency_improvement < -5:
            f.write("**Recommendation: Userspace Implementation**\n\n")
            f.write("Userspace implementation shows better performance characteristics:\n")
            f.write(f"- Better throughput ({-throughput_improvement:.1f}% advantage)\n")
            f.write(f"- Lower latency ({-latency_improvement:.1f}% advantage)\n\n")
        else:
            f.write("**Conditional Recommendations**\n\n")

            f.write("**Choose eBPF when:**\n")
            if throughput_improvement > 0:
                f.write("- Maximum throughput is critical\n")
            if error_improvement > 0:
                f.write("- High reliability is required\n")
            f.write("- Kernel-space efficiency benefits outweigh complexity\n")
            f.write("- System resources are constrained\n\n")

            f.write("**Choose Userspace when:**\n")
            if latency_improvement < 0:
                f.write("- Lowest possible latency is required\n")
            f.write("- Easier debugging and development is preferred\n")
            f.write("- Kernel programming expertise is limited\n")
            f.write("- Deployment flexibility is important\n\n")

        f.write("### Performance Optimization Opportunities\n\n")

        # Thread performance analysis
        ebpf_thread_stats = throughput_analysis.get("ebpf", {}).get("thread_stats", {})
        user_thread_stats = throughput_analysis.get("userspace", {}).get("thread_stats", {})

        ebpf_cv = ebpf_thread_stats.get("rps_stats", {}).get("cv", 0)
        user_cv = user_thread_stats.get("rps_stats", {}).get("cv", 0)

        if ebpf_cv > 0.1:
            f.write("**eBPF Implementation:**\n")
            f.write(f"- Thread load balancing could be improved (CV = {ebpf_cv:.3f})\n")
            f.write("- Consider CPU affinity optimizations\n\n")

        if user_cv > 0.1:
            f.write("**Userspace Implementation:**\n")
            f.write(f"- Thread consistency needs attention (CV = {user_cv:.3f})\n")
            f.write("- Review thread pool configuration\n\n")

        # Error rate analysis
        ebpf_error_rate = throughput_analysis.get("ebpf", {}).get("error_analysis", {}).get("overall_error_rate", 0)
        user_error_rate = (
            throughput_analysis.get("userspace", {}).get("error_analysis", {}).get("overall_error_rate", 0)
        )

        if ebpf_error_rate > 0.01:  # 1% error rate
            f.write("**eBPF Reliability Improvements:**\n")
            f.write(f"- Current error rate: {ebpf_error_rate*100:.2f}%\n")
            f.write("- Review timeout configurations\n")
            f.write("- Investigate kernel buffer sizing\n\n")

        if user_error_rate > 0.01:
            f.write("**Userspace Reliability Improvements:**\n")
            f.write(f"- Current error rate: {user_error_rate*100:.2f}%\n")
            f.write("- Consider connection pooling optimizations\n")
            f.write("- Review socket buffer configurations\n\n")

    def _write_figures_index(self, f):
        """Write index of generated figures."""
        f.write("## Generated Figures\n\n")
        f.write("This evaluation generates comprehensive visualizations saved in multiple formats:\n\n")

        figure_categories = [
            (
                "Latency Analysis",
                [
                    "latency_write_comparison.{png,svg,pdf}",
                    "latency_read_comparison.{png,svg,pdf}",
                    "latency_write_percentiles.{png,svg,pdf}",
                    "latency_read_percentiles.{png,svg,pdf}",
                    "latency_write_distribution.{png,svg,pdf}",
                    "latency_read_distribution.{png,svg,pdf}",
                    "latency_*_by_node.{png,svg,pdf}",
                ],
            ),
            (
                "Throughput Analysis",
                [
                    "throughput_overview.{png,svg,pdf}",
                    "throughput_timeline.{png,svg,pdf}",
                    "throughput_latency_analysis.{png,svg,pdf}",
                    "throughput_error_analysis.{png,svg,pdf}",
                    "throughput_thread_analysis.{png,svg,pdf}",
                    "throughput_metrics_heatmap.{png,svg,pdf}",
                ],
            ),
            ("Combined Analysis", ["throughput_latency_tradeoff.{png,svg,pdf}"]),
        ]

        for category, figures in figure_categories:
            f.write(f"### {category}\n\n")
            for figure in figures:
                f.write(f"- `{figure}`\n")
            f.write("\n")

    def _write_methodology(self, f):
        """Write methodology section."""
        f.write("## Methodology\n\n")

        f.write("### Benchmarking Approach\n\n")
        f.write("This evaluation employs a comprehensive dual-benchmark approach:\n\n")
        f.write("1. **Latency Benchmarks**: Measure end-to-end request latency under controlled load\n")
        f.write("2. **Throughput Benchmarks**: Assess maximum sustainable request rate and performance under load\n\n")

        f.write("### Statistical Methods\n\n")

        f.write("**Hypothesis Testing:**\n")
        f.write("- Mann-Whitney U Test: Non-parametric comparison of distributions\n")
        f.write("- Independent t-test: Parametric comparison of means\n")
        f.write("- Shapiro-Wilk Test: Assessment of distribution normality\n")
        f.write("- Levene's Test: Homogeneity of variances\n\n")

        f.write("**Effect Size Measures:**\n")
        f.write("- Cohen's d: Standardized difference between means\n")
        f.write("- Hedge's g: Bias-corrected effect size for small samples\n")
        f.write("- Glass's Δ: Effect size using control group standard deviation\n\n")

        f.write("**Effect Size Interpretation (Cohen's d):**\n")
        f.write("- |d| < 0.2: Negligible effect\n")
        f.write("- 0.2 ≤ |d| < 0.5: Small effect\n")
        f.write("- 0.5 ≤ |d| < 0.8: Medium effect\n")
        f.write("- |d| ≥ 0.8: Large effect\n\n")

        f.write("### Performance Metrics\n\n")

        f.write("**Latency Metrics:**\n")
        f.write("- Mean, median, and percentile latencies (P50, P90, P95, P99, P99.9)\n")
        f.write("- Distribution characteristics (skewness, kurtosis, coefficient of variation)\n")
        f.write("- Statistical significance testing\n\n")

        f.write("**Throughput Metrics:**\n")
        f.write("- Requests per second (overall, read, write)\n")
        f.write("- Success rates and error analysis\n")
        f.write("- Thread performance consistency\n")
        f.write("- Temporal stability analysis\n")
        f.write("- Latency under load characteristics\n\n")

    def _write_appendices(self, f, analysis: Dict[str, Any]):
        """Write appendices with detailed data."""
        f.write("## Appendices\n\n")

        f.write("### Appendix A: Raw Statistical Data\n\n")

        # Latency statistics table
        latency_analysis = analysis.get("latency", {})

        f.write("#### Latency Statistics Summary\n\n")

        latency_table_data = []
        for impl in ["ebpf", "userspace"]:
            for operation in ["write", "read"]:
                stats = latency_analysis.get(impl, {}).get("statistics", {}).get(operation, {})
                if stats:
                    latency_table_data.append(
                        [
                            impl.upper(),
                            operation.title(),
                            f"{stats.get('count', 0)}",
                            f"{stats.get('mean', 0):.3f}",
                            f"{stats.get('median', 0):.3f}",
                            f"{stats.get('std', 0):.3f}",
                            f"{stats.get('p95', 0):.3f}",
                            f"{stats.get('p99', 0):.3f}",
                            f"{stats.get('cv', 0):.3f}",
                            f"{stats.get('skewness', 0):.3f}",
                        ]
                    )

        if latency_table_data:
            f.write(
                "| Implementation | Operation | Count | Mean (μs) | Median (μs) |"
                " Std Dev (μs) | P95 (μs) | P99 (μs) | CV | Skewness |\n"
            )
            f.write(
                "|----------------|-----------|-------|-----------|-------------|"
                "--------------|----------|----------|----|-----------|\n"
            )
            for row in latency_table_data:
                f.write(f"| {' | '.join(row)} |\n")
            f.write("\n")

        # Throughput summary
        f.write("#### Throughput Statistics Summary\n\n")

        throughput_analysis = analysis.get("throughput", {})
        for impl in ["ebpf", "userspace"]:
            summary_stats = throughput_analysis.get(impl, {}).get("summary_stats", {})
            if summary_stats:
                f.write(f"**{impl.upper()} Implementation:**\n")
                f.write(f"- Overall RPS: {summary_stats.get('overall_rps', 0):.2f}\n")
                f.write(f"- Write RPS: {summary_stats.get('write_rps', 0):.2f}\n")
                f.write(f"- Read RPS: {summary_stats.get('read_rps', 0):.2f}\n")
                f.write(f"- Success Rate: {summary_stats.get('overall_success_rate', 0)*100:.3f}%\n")
                f.write(f"- Average Latency: {summary_stats.get('avg_latency_us', 0):.3f} μs\n")
                f.write(f"- P95 Latency: {summary_stats.get('p95_latency_us', 0):.3f} μs\n")
                f.write(f"- P99 Latency: {summary_stats.get('p99_latency_us', 0):.3f} μs\n\n")

        f.write("### Appendix B: Configuration Details\n\n")

        # Export configuration as JSON
        config_data = analysis.get("evaluation_metadata", {}).get("config", {})
        if config_data:
            config_data_str = self._convert_paths_to_str(config_data)
            f.write("```json\n")
            f.write(json.dumps(config_data_str, indent=2))
            f.write("\n```")

        f.write("---\n\n")
        f.write("*Report generated by ABD Protocol Evaluation Framework v2.0.0*\n")

    def _export_summary_tables(self, analysis: Dict[str, Any]):
        """Export summary data as CSV files for further analysis."""
        logger.info("Exporting summary tables as CSV")

        # Latency summary table
        latency_analysis = analysis.get("latency", {})
        latency_rows = []

        for impl in ["ebpf", "userspace"]:
            for operation in ["write", "read"]:
                stats = latency_analysis.get(impl, {}).get("statistics", {}).get(operation, {})
                if stats:
                    latency_rows.append(
                        {
                            "Implementation": impl,
                            "Operation": operation,
                            "Count": stats.get("count", 0),
                            "Mean_us": stats.get("mean", 0),
                            "Median_us": stats.get("median", 0),
                            "Std_us": stats.get("std", 0),
                            "P50_us": stats.get("p50", 0),
                            "P95_us": stats.get("p95", 0),
                            "P99_us": stats.get("p99", 0),
                            "P99_9_us": stats.get("p99_9", 0),
                            "CV": stats.get("cv", 0),
                            "Skewness": stats.get("skewness", 0),
                            "Kurtosis": stats.get("kurtosis", 0),
                        }
                    )

        if latency_rows:
            latency_df = pd.DataFrame(latency_rows)
            latency_df.to_csv(self.config.data_dir / "latency_summary.csv", index=False)

        # Throughput summary table
        throughput_analysis = analysis.get("throughput", {})
        throughput_rows = []

        for impl in ["ebpf", "userspace"]:
            summary_stats = throughput_analysis.get(impl, {}).get("summary_stats", {})
            thread_stats = throughput_analysis.get(impl, {}).get("thread_stats", {})
            error_analysis = throughput_analysis.get(impl, {}).get("error_analysis", {})

            if summary_stats:
                throughput_rows.append(
                    {
                        "Implementation": impl,
                        "Overall_RPS": summary_stats.get("overall_rps", 0),
                        "Write_RPS": summary_stats.get("write_rps", 0),
                        "Read_RPS": summary_stats.get("read_rps", 0),
                        "Success_Rate": summary_stats.get("overall_success_rate", 0),
                        "Error_Rate": summary_stats.get("failure_rate", 0),
                        "Avg_Latency_us": summary_stats.get("avg_latency_us", 0),
                        "P95_Latency_us": summary_stats.get("p95_latency_us", 0),
                        "P99_Latency_us": summary_stats.get("p99_latency_us", 0),
                        "Thread_RPS_CV": thread_stats.get("rps_stats", {}).get("cv", 0),
                        "Load_Balance_Quality": thread_stats.get("load_balance_quality", 0),
                        "Error_Variance": error_analysis.get("error_variance", 0),
                    }
                )

        if throughput_rows:
            throughput_df = pd.DataFrame(throughput_rows)
            throughput_df.to_csv(self.config.data_dir / "throughput_summary.csv", index=False)

        logger.info("Summary tables exported to CSV files")

    def _convert_paths_to_str(self, obj):
        """Recursively convert all Path/PosixPath objects in a structure to strings."""
        if isinstance(obj, dict):
            return {k: self._convert_paths_to_str(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_paths_to_str(i) for i in obj]
        elif isinstance(obj, (Path,)):
            return str(obj)
        else:
            return obj
