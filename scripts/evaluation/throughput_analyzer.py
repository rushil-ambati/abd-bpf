"""
Throughput analysis module for ABD protocol evaluation.

Provides comprehensive analysis and visualization capabilities for throughput
benchmark results, including RPS analysis, load testing, and latency-throughput
trade-offs.
"""

import logging
from typing import Any, Dict, List

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats
from scipy.stats import mannwhitneyu

from .config import STATISTICAL_CONFIG, EvaluationConfig

logger = logging.getLogger(__name__)


class ThroughputAnalyzer:
    """Handles throughput data analysis and visualization."""

    def __init__(self, config: EvaluationConfig):
        """Initialize throughput analyzer with configuration."""
        self.config = config

    def analyze_results(self, ebpf_data: Dict, userspace_data: Dict) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of throughput benchmark results.

        Args:
            ebpf_data: eBPF benchmark results
            userspace_data: Userspace benchmark results

        Returns:
            Dictionary containing comprehensive throughput analysis
        """
        logger.info("Performing throughput statistical analysis")

        analysis = {
            "ebpf": {
                "summary_stats": self._extract_summary_stats(ebpf_data),
                "thread_stats": self._analyze_thread_performance(ebpf_data),
                "timeline_stats": self._analyze_timeline(ebpf_data),
                "error_analysis": self._analyze_errors(ebpf_data),
                "latency_under_load": self._analyze_latency_under_load(ebpf_data),
            },
            "userspace": {
                "summary_stats": self._extract_summary_stats(userspace_data),
                "thread_stats": self._analyze_thread_performance(userspace_data),
                "timeline_stats": self._analyze_timeline(userspace_data),
                "error_analysis": self._analyze_errors(userspace_data),
                "latency_under_load": self._analyze_latency_under_load(userspace_data),
            },
            "comparative_analysis": self._perform_comparative_analysis(ebpf_data, userspace_data),
            "metadata": {
                "analysis_timestamp": pd.Timestamp.now().isoformat(),
                "statistical_config": STATISTICAL_CONFIG,
            },
        }

        return analysis

    def _extract_summary_stats(self, data: Dict) -> Dict[str, Any]:
        """Extract and enhance summary statistics from benchmark results."""
        summary = data.get("summary", {})

        return {
            # Basic throughput metrics
            "total_requests": summary.get("total_sent", 0),
            "successful_requests": summary.get("total_received", 0),
            "failed_requests": summary.get("total_timeouts", 0),
            "overall_rps": summary.get("rps", 0),
            "write_rps": summary.get("write_rps", 0),
            "read_rps": summary.get("read_rps", 0),
            # Success rates
            "overall_success_rate": summary.get("success_rate", 0),
            "write_success_rate": summary.get("write_success_rate", 0),
            "read_success_rate": summary.get("read_success_rate", 0),
            # Latency under load
            "avg_latency_us": summary.get("latency_summary", {}).get("avg_us", 0),
            "p50_latency_us": summary.get("latency_summary", {}).get("p50_us", 0),
            "p95_latency_us": summary.get("latency_summary", {}).get("p95_us", 0),
            "p99_latency_us": summary.get("latency_summary", {}).get("p99_us", 0),
            "max_latency_us": summary.get("latency_summary", {}).get("max_us", 0),
            # Derived metrics
            "write_read_ratio": summary.get("write_rps", 0) / max(summary.get("read_rps", 1), 1),
            "failure_rate": 1 - summary.get("success_rate", 1),
            "requests_per_thread": summary.get("total_sent", 0) / max(len(data.get("stats", [])), 1),
        }

    def _analyze_thread_performance(self, data: Dict) -> Dict[str, Any]:
        """Analyze per-thread performance variations."""
        thread_stats = data.get("stats", [])
        if not thread_stats:
            return {}

        # Extract per-thread metrics
        thread_rps = []
        thread_success_rates = []
        thread_latencies = []

        for thread in thread_stats:
            duration = 10  # Assume 10 second benchmark from example
            rps = thread["received"] / duration
            success_rate = thread["received"] / max(thread["sent"], 1)
            avg_latency = thread.get("latency_stats", {}).get("avg_us", 0)

            thread_rps.append(rps)
            thread_success_rates.append(success_rate)
            thread_latencies.append(avg_latency)

        return {
            "thread_count": len(thread_stats),
            "rps_stats": {
                "mean": np.mean(thread_rps),
                "std": np.std(thread_rps),
                "min": np.min(thread_rps),
                "max": np.max(thread_rps),
                "cv": np.std(thread_rps) / np.mean(thread_rps) if np.mean(thread_rps) > 0 else 0,
            },
            "success_rate_stats": {
                "mean": np.mean(thread_success_rates),
                "std": np.std(thread_success_rates),
                "min": np.min(thread_success_rates),
                "max": np.max(thread_success_rates),
            },
            "latency_stats": {
                "mean": np.mean(thread_latencies),
                "std": np.std(thread_latencies),
                "min": np.min(thread_latencies),
                "max": np.max(thread_latencies),
            },
            "load_balance_quality": 1 - (np.std(thread_rps) / np.mean(thread_rps)) if np.mean(thread_rps) > 0 else 0,
        }

    def _analyze_timeline(self, data: Dict) -> Dict[str, Any]:
        """Analyze temporal performance patterns."""
        timeline = data.get("timeline", [])
        if not timeline:
            return {}

        rps_values = [entry["rps"] for entry in timeline]
        success_rates = [entry["success_rate"] for entry in timeline]
        latencies = [entry["avg_latency_us"] for entry in timeline]

        return {
            "stability_metrics": {
                "rps_cv": np.std(rps_values) / np.mean(rps_values) if np.mean(rps_values) > 0 else 0,
                "rps_trend": self._calculate_trend(rps_values),
                "latency_trend": self._calculate_trend(latencies),
                "success_rate_stability": np.std(success_rates),
            },
            "performance_over_time": {
                "avg_rps": np.mean(rps_values),
                "max_rps": np.max(rps_values),
                "min_rps": np.min(rps_values),
                "rps_range": np.max(rps_values) - np.min(rps_values),
                "avg_latency": np.mean(latencies),
                "latency_range": np.max(latencies) - np.min(latencies),
            },
            "warmup_analysis": self._analyze_warmup(timeline),
        }

    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate linear trend in time series data."""
        if len(values) < 2:
            return 0.0
        x = np.arange(len(values))
        slope, _, _, _, _ = stats.linregress(x, values)
        return float(slope)

    def _analyze_warmup(self, timeline: List[Dict]) -> Dict[str, Any]:
        """Analyze warmup effects in the timeline."""
        if len(timeline) < 3:
            return {}

        # Compare first third vs last third
        n = len(timeline)
        first_third = timeline[: n // 3]
        last_third = timeline[-n // 3 :]

        first_rps = np.mean([entry["rps"] for entry in first_third])
        last_rps = np.mean([entry["rps"] for entry in last_third])
        first_latency = np.mean([entry["avg_latency_us"] for entry in first_third])
        last_latency = np.mean([entry["avg_latency_us"] for entry in last_third])

        return {
            "warmup_effect": (last_rps - first_rps) / first_rps if first_rps > 0 else 0,
            "latency_warmup_effect": (first_latency - last_latency) / first_latency if first_latency > 0 else 0,
            "rps_improvement": last_rps - first_rps,
            "latency_improvement": first_latency - last_latency,
        }

    def _analyze_errors(self, data: Dict) -> Dict[str, Any]:
        """Analyze error patterns and failure modes."""
        summary = data.get("summary", {})
        thread_stats = data.get("stats", [])

        total_sent = summary.get("total_sent", 0)
        total_timeouts = summary.get("total_timeouts", 0)

        # Calculate actual dropped responses from sent vs received
        total_received = summary.get("total_received", 0)
        actual_dropped = total_sent - total_received

        # Per-node error analysis
        node_errors = {}
        for thread in thread_stats:
            node_id = thread.get("node_id", "unknown")
            node_errors[node_id] = {
                "sent": thread.get("sent", 0),
                "received": thread.get("received", 0),
                "timeouts": thread.get("timeouts", 0),
                "dropped": thread.get("sent", 0) - thread.get("received", 0),
                "error_rate": (thread.get("sent", 0) - thread.get("received", 0)) / max(thread.get("sent", 1), 1),
            }

        return {
            "overall_error_rate": actual_dropped / max(total_sent, 1),
            "timeout_rate": total_timeouts / max(total_sent, 1),
            "total_errors": actual_dropped,
            "node_error_distribution": node_errors,
            "error_variance": np.var([node["error_rate"] for node in node_errors.values()]),
            "max_node_error_rate": max([node["error_rate"] for node in node_errors.values()]) if node_errors else 0,
        }

    def _analyze_latency_under_load(self, data: Dict) -> Dict[str, Any]:
        """Analyze latency characteristics under load."""
        thread_stats = data.get("stats", [])
        if not thread_stats:
            return {}

        all_latencies = []
        for thread in thread_stats:
            latency_stats = thread.get("latency_stats", {})
            all_latencies.append(
                {
                    "avg": latency_stats.get("avg_us", 0),
                    "p50": latency_stats.get("p50_us", 0),
                    "p95": latency_stats.get("p95_us", 0),
                    "p99": latency_stats.get("p99_us", 0),
                    "max": latency_stats.get("max_us", 0),
                }
            )

        # Aggregate statistics
        avg_latencies = [lat["avg"] for lat in all_latencies]
        p95_latencies = [lat["p95"] for lat in all_latencies]
        p99_latencies = [lat["p99"] for lat in all_latencies]
        max_latencies = [lat["max"] for lat in all_latencies]

        return {
            "cross_thread_latency_variance": {
                "avg_variance": np.var(avg_latencies),
                "p95_variance": np.var(p95_latencies),
                "p99_variance": np.var(p99_latencies),
            },
            "worst_case_analysis": {
                "max_p99": np.max(p99_latencies),
                "max_observed": np.max(max_latencies),
                "p99_spread": np.max(p99_latencies) - np.min(p99_latencies),
            },
            "load_impact": {
                "avg_latency_consistency": (
                    1 - (np.std(avg_latencies) / np.mean(avg_latencies)) if np.mean(avg_latencies) > 0 else 0
                )
            },
        }

    def _perform_comparative_analysis(self, ebpf_data: Dict, userspace_data: Dict) -> Dict[str, Any]:
        """Perform statistical comparison between eBPF and userspace implementations."""
        ebpf_summary = self._extract_summary_stats(ebpf_data)
        userspace_summary = self._extract_summary_stats(userspace_data)

        # Throughput comparison
        rps_improvement = (ebpf_summary["overall_rps"] - userspace_summary["overall_rps"]) / max(
            userspace_summary["overall_rps"], 1
        )

        # Latency comparison
        latency_improvement = (userspace_summary["avg_latency_us"] - ebpf_summary["avg_latency_us"]) / max(
            userspace_summary["avg_latency_us"], 1
        )

        # Error rate comparison
        error_improvement = (userspace_summary["failure_rate"] - ebpf_summary["failure_rate"]) / max(
            userspace_summary["failure_rate"], 0.001
        )

        # Statistical tests on timeline data
        ebpf_timeline = ebpf_data.get("timeline", [])
        user_timeline = userspace_data.get("timeline", [])

        timeline_comparison = {}
        if ebpf_timeline and user_timeline:
            ebpf_rps = [entry["rps"] for entry in ebpf_timeline]
            user_rps = [entry["rps"] for entry in user_timeline]

            # Mann-Whitney U test for RPS
            if len(ebpf_rps) > 1 and len(user_rps) > 1:
                mw_stat, mw_p = mannwhitneyu(ebpf_rps, user_rps, alternative="two-sided")
                timeline_comparison["rps_mann_whitney"] = {
                    "statistic": float(mw_stat),
                    "p_value": float(mw_p),
                    "significant": mw_p < STATISTICAL_CONFIG["alpha"],
                }

        return {
            "performance_improvements": {
                "throughput_improvement_pct": rps_improvement * 100,
                "latency_improvement_pct": latency_improvement * 100,
                "error_improvement_pct": error_improvement * 100,
            },
            "absolute_differences": {
                "rps_difference": ebpf_summary["overall_rps"] - userspace_summary["overall_rps"],
                "latency_difference_us": ebpf_summary["avg_latency_us"] - userspace_summary["avg_latency_us"],
                "error_rate_difference": ebpf_summary["failure_rate"] - userspace_summary["failure_rate"],
            },
            "efficiency_metrics": {
                "throughput_per_latency_ebpf": ebpf_summary["overall_rps"] / max(ebpf_summary["avg_latency_us"], 1),
                "throughput_per_latency_userspace": userspace_summary["overall_rps"]
                / max(userspace_summary["avg_latency_us"], 1),
            },
            "timeline_comparison": timeline_comparison,
            "winner_analysis": self._determine_winner(ebpf_summary, userspace_summary),
        }

    def _determine_winner(self, ebpf_stats: Dict, userspace_stats: Dict) -> Dict[str, str]:
        """Determine which implementation performs better in different dimensions."""
        return {
            "throughput": "ebpf" if ebpf_stats["overall_rps"] > userspace_stats["overall_rps"] else "userspace",
            "latency": "ebpf" if ebpf_stats["avg_latency_us"] < userspace_stats["avg_latency_us"] else "userspace",
            "reliability": "ebpf" if ebpf_stats["failure_rate"] < userspace_stats["failure_rate"] else "userspace",
            "write_performance": "ebpf" if ebpf_stats["write_rps"] > userspace_stats["write_rps"] else "userspace",
            "read_performance": "ebpf" if ebpf_stats["read_rps"] > userspace_stats["read_rps"] else "userspace",
        }

    def create_all_visualizations(self, ebpf_data: Dict, userspace_data: Dict, analysis: Dict):
        """Create all throughput-related visualizations."""
        logger.info("Generating throughput visualizations")

        # Main performance comparison
        self.create_performance_overview(analysis)

        # Timeline analysis
        self.create_timeline_analysis(ebpf_data, userspace_data)

        # Throughput vs latency analysis
        self.create_throughput_latency_analysis(ebpf_data, userspace_data)

        # Error analysis
        self.create_error_analysis(analysis)

        # Thread performance analysis
        self.create_thread_performance_analysis(ebpf_data, userspace_data)

        # Detailed metrics comparison
        self.create_detailed_metrics_comparison(analysis)

        logger.info("Completed throughput visualizations")

    def create_performance_overview(self, analysis: Dict):
        """Create comprehensive performance overview dashboard."""
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle("Throughput Performance Overview: eBPF vs Userspace", fontsize=16, fontweight="bold")

        # Extract data
        ebpf_stats = analysis["ebpf"]["summary_stats"]
        user_stats = analysis["userspace"]["summary_stats"]

        # 1. Overall RPS comparison
        ax1 = axes[0, 0]
        implementations = ["eBPF", "Userspace"]
        rps_values = [ebpf_stats["overall_rps"], user_stats["overall_rps"]]
        bars1 = ax1.bar(
            implementations, rps_values, color=[self.config.colors["ebpf"], self.config.colors["userspace"]]
        )
        ax1.set_ylabel("Requests per Second")
        ax1.set_title("Overall Throughput")
        ax1.grid(True, alpha=0.3)

        # Add value labels
        for bar, value in zip(bars1, rps_values):
            ax1.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(rps_values) * 0.01,
                f"{value:.0f}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        # 2. Read vs Write RPS
        ax2 = axes[0, 1]
        x = np.arange(len(implementations))
        width = 0.35

        write_rps = [ebpf_stats["write_rps"], user_stats["write_rps"]]
        read_rps = [ebpf_stats["read_rps"], user_stats["read_rps"]]

        ax2.bar(x - width / 2, write_rps, width, label="Write", color=self.config.colors["accent"])
        ax2.bar(x + width / 2, read_rps, width, label="Read", color=self.config.colors["neutral"])

        ax2.set_ylabel("Requests per Second")
        ax2.set_title("Write vs Read Throughput")
        ax2.set_xticks(x)
        ax2.set_xticklabels(implementations)
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # 3. Success rates
        ax3 = axes[0, 2]
        success_rates = [ebpf_stats["overall_success_rate"] * 100, user_stats["overall_success_rate"] * 100]
        bars3 = ax3.bar(
            implementations, success_rates, color=[self.config.colors["ebpf"], self.config.colors["userspace"]]
        )
        ax3.set_ylabel("Success Rate (%)")
        ax3.set_title("Request Success Rate")
        ax3.set_ylim([min(success_rates) - 1, 100])
        ax3.grid(True, alpha=0.3)

        for bar, value in zip(bars3, success_rates):
            ax3.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.1,
                f"{value:.2f}%",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        # 4. Average latency under load
        ax4 = axes[1, 0]
        latencies = [ebpf_stats["avg_latency_us"], user_stats["avg_latency_us"]]
        bars4 = ax4.bar(
            implementations, latencies, color=[self.config.colors["ebpf"], self.config.colors["userspace"]]
        )
        ax4.set_ylabel("Average Latency (μs)")
        ax4.set_title("Latency Under Load")
        ax4.grid(True, alpha=0.3)

        for bar, value in zip(bars4, latencies):
            ax4.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(latencies) * 0.01,
                f"{value:.1f}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        # 5. P95 and P99 latencies
        ax5 = axes[1, 1]
        p95_values = [ebpf_stats["p95_latency_us"], user_stats["p95_latency_us"]]
        p99_values = [ebpf_stats["p99_latency_us"], user_stats["p99_latency_us"]]

        x = np.arange(len(implementations))
        ax5.bar(x - width / 2, p95_values, width, label="P95", color=self.config.colors["warning"])
        ax5.bar(x + width / 2, p99_values, width, label="P99", color=self.config.colors["error"])

        ax5.set_ylabel("Latency (μs)")
        ax5.set_title("Tail Latencies Under Load")
        ax5.set_xticks(x)
        ax5.set_xticklabels(implementations)
        ax5.legend()
        ax5.grid(True, alpha=0.3)

        # 6. Efficiency metric (RPS per unit latency)
        ax6 = axes[1, 2]
        efficiency_ebpf = ebpf_stats["overall_rps"] / max(ebpf_stats["avg_latency_us"], 1)
        efficiency_user = user_stats["overall_rps"] / max(user_stats["avg_latency_us"], 1)

        efficiency_values = [efficiency_ebpf, efficiency_user]
        bars6 = ax6.bar(
            implementations, efficiency_values, color=[self.config.colors["ebpf"], self.config.colors["userspace"]]
        )
        ax6.set_ylabel("RPS per μs Latency")
        ax6.set_title("Throughput Efficiency")
        ax6.grid(True, alpha=0.3)

        for bar, value in zip(bars6, efficiency_values):
            ax6.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(efficiency_values) * 0.01,
                f"{value:.2f}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(self.config.figures_dir / f"throughput_overview.{fmt}")
        plt.close()

    def create_timeline_analysis(self, ebpf_data: Dict, userspace_data: Dict):
        """Create timeline analysis showing performance over time."""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle("Performance Timeline Analysis", fontsize=16, fontweight="bold")

        # Extract timeline data
        ebpf_timeline = ebpf_data.get("timeline", [])
        user_timeline = userspace_data.get("timeline", [])

        if not ebpf_timeline or not user_timeline:
            logger.warning("Timeline data not available")
            plt.close()
            return

        ebpf_times = [entry["interval_start"] for entry in ebpf_timeline]
        user_times = [entry["interval_start"] for entry in user_timeline]
        ebpf_rps = [entry["rps"] for entry in ebpf_timeline]
        user_rps = [entry["rps"] for entry in user_timeline]
        ebpf_latency = [entry["avg_latency_us"] for entry in ebpf_timeline]
        user_latency = [entry["avg_latency_us"] for entry in user_timeline]
        ebpf_success = [entry["success_rate"] * 100 for entry in ebpf_timeline]
        user_success = [entry["success_rate"] * 100 for entry in user_timeline]

        # 1. RPS over time
        ax1 = axes[0, 0]
        ax1.plot(ebpf_times, ebpf_rps, label="eBPF", color=self.config.colors["ebpf"], linewidth=2)
        ax1.plot(user_times, user_rps, label="Userspace", color=self.config.colors["userspace"], linewidth=2)
        ax1.set_xlabel("Time (seconds)")
        ax1.set_ylabel("Requests per Second")
        ax1.set_title("Throughput Over Time")
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        # 2. Latency over time
        ax2 = axes[0, 1]
        ax2.plot(ebpf_times, ebpf_latency, label="eBPF", color=self.config.colors["ebpf"], linewidth=2)
        ax2.plot(user_times, user_latency, label="Userspace", color=self.config.colors["userspace"], linewidth=2)
        ax2.set_xlabel("Time (seconds)")
        ax2.set_ylabel("Average Latency (μs)")
        ax2.set_title("Latency Over Time")
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # 3. Success rate over time
        ax3 = axes[1, 0]
        ax3.plot(ebpf_times, ebpf_success, label="eBPF", color=self.config.colors["ebpf"], linewidth=2)
        ax3.plot(user_times, user_success, label="Userspace", color=self.config.colors["userspace"], linewidth=2)
        ax3.set_xlabel("Time (seconds)")
        ax3.set_ylabel("Success Rate (%)")
        ax3.set_title("Success Rate Over Time")
        ax3.legend()
        ax3.grid(True, alpha=0.3)

        # 4. Performance stability (coefficient of variation)
        ax4 = axes[1, 1]

        # Calculate rolling CV for stability analysis
        window_size = min(3, len(ebpf_rps) // 2)
        if window_size >= 2:
            ebpf_rolling_cv = [
                (
                    np.std(ebpf_rps[max(0, i - window_size + 1) : i + 1])
                    / np.mean(ebpf_rps[max(0, i - window_size + 1) : i + 1])
                    if np.mean(ebpf_rps[max(0, i - window_size + 1) : i + 1]) > 0
                    else 0
                )
                for i in range(len(ebpf_rps))
            ]
            user_rolling_cv = [
                (
                    np.std(user_rps[max(0, i - window_size + 1) : i + 1])
                    / np.mean(user_rps[max(0, i - window_size + 1) : i + 1])
                    if np.mean(user_rps[max(0, i - window_size + 1) : i + 1]) > 0
                    else 0
                )
                for i in range(len(user_rps))
            ]

            ax4.plot(ebpf_times, ebpf_rolling_cv, label="eBPF CV", color=self.config.colors["ebpf"], linewidth=2)
            ax4.plot(
                user_times, user_rolling_cv, label="Userspace CV", color=self.config.colors["userspace"], linewidth=2
            )

        ax4.set_xlabel("Time (seconds)")
        ax4.set_ylabel("Rolling CV")
        ax4.set_title("Performance Stability (CV)")
        ax4.legend()
        ax4.grid(True, alpha=0.3)

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(self.config.figures_dir / f"throughput_timeline.{fmt}")
        plt.close()

    def create_throughput_latency_analysis(self, ebpf_data: Dict, userspace_data: Dict):
        """Create throughput vs latency analysis."""
        fig, axes = plt.subplots(1, 2, figsize=(15, 6))
        fig.suptitle("Throughput vs Latency Analysis", fontsize=16, fontweight="bold")

        # Extract summary data
        ebpf_summary = ebpf_data.get("summary", {})
        user_summary = userspace_data.get("summary", {})

        # 1. Throughput vs Average Latency scatter
        ax1 = axes[0]

        ebpf_rps = ebpf_summary.get("rps", 0)
        ebpf_latency = ebpf_summary.get("latency_summary", {}).get("avg_us", 0)
        user_rps = user_summary.get("rps", 0)
        user_latency = user_summary.get("latency_summary", {}).get("avg_us", 0)

        ax1.scatter(
            ebpf_rps, ebpf_latency, s=200, alpha=0.8, color=self.config.colors["ebpf"], label="eBPF", marker="o"
        )
        ax1.scatter(
            user_rps,
            user_latency,
            s=200,
            alpha=0.8,
            color=self.config.colors["userspace"],
            label="Userspace",
            marker="s",
        )

        ax1.set_xlabel("Throughput (RPS)")
        ax1.set_ylabel("Average Latency (μs)")
        ax1.set_title("Throughput vs Latency Trade-off")
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        # Add annotations
        ax1.annotate(
            f"eBPF\n({ebpf_rps:.0f}, {ebpf_latency:.1f})",
            xy=(ebpf_rps, ebpf_latency),
            xytext=(10, 10),
            textcoords="offset points",
            fontsize=10,
        )
        ax1.annotate(
            f"Userspace\n({user_rps:.0f}, {user_latency:.1f})",
            xy=(user_rps, user_latency),
            xytext=(10, -20),
            textcoords="offset points",
            fontsize=10,
        )

        # 2. Latency percentiles comparison under load
        ax2 = axes[1]

        ebpf_latency_stats = ebpf_summary.get("latency_summary", {})
        user_latency_stats = user_summary.get("latency_summary", {})

        percentiles = ["P50", "P95", "P99", "Max"]
        ebpf_values = [
            ebpf_latency_stats.get("p50_us", 0),
            ebpf_latency_stats.get("p95_us", 0),
            ebpf_latency_stats.get("p99_us", 0),
            ebpf_latency_stats.get("max_us", 0),
        ]
        user_values = [
            user_latency_stats.get("p50_us", 0),
            user_latency_stats.get("p95_us", 0),
            user_latency_stats.get("p99_us", 0),
            user_latency_stats.get("max_us", 0),
        ]

        x = np.arange(len(percentiles))
        width = 0.35

        ax2.bar(x - width / 2, ebpf_values, width, label="eBPF", color=self.config.colors["ebpf"])
        ax2.bar(x + width / 2, user_values, width, label="Userspace", color=self.config.colors["userspace"])

        ax2.set_xlabel("Latency Percentiles")
        ax2.set_ylabel("Latency (μs)")
        ax2.set_title("Latency Distribution Under Load")
        ax2.set_xticks(x)
        ax2.set_xticklabels(percentiles)
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(self.config.figures_dir / f"throughput_latency_analysis.{fmt}")
        plt.close()

    def create_error_analysis(self, analysis: Dict):
        """Create error rate and reliability analysis."""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle("Error Analysis and Reliability", fontsize=16, fontweight="bold")

        # Extract error data
        ebpf_errors = analysis["ebpf"]["error_analysis"]
        user_errors = analysis["userspace"]["error_analysis"]

        # 1. Overall error rates
        ax1 = axes[0, 0]
        implementations = ["eBPF", "Userspace"]
        error_rates = [ebpf_errors["overall_error_rate"] * 100, user_errors["overall_error_rate"] * 100]

        bars1 = ax1.bar(
            implementations, error_rates, color=[self.config.colors["ebpf"], self.config.colors["userspace"]]
        )
        ax1.set_ylabel("Error Rate (%)")
        ax1.set_title("Overall Error Rate")
        ax1.grid(True, alpha=0.3)

        for bar, value in zip(bars1, error_rates):
            ax1.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.01,
                f"{value:.3f}%",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        # 2. Per-node error distribution
        ax2 = axes[0, 1]

        # Extract per-node error rates
        ebpf_node_errors = ebpf_errors.get("node_error_distribution", {})
        user_node_errors = user_errors.get("node_error_distribution", {})

        if ebpf_node_errors and user_node_errors:
            nodes = sorted(set(ebpf_node_errors.keys()) | set(user_node_errors.keys()))
            ebpf_node_rates = [ebpf_node_errors.get(node, {}).get("error_rate", 0) * 100 for node in nodes]
            user_node_rates = [user_node_errors.get(node, {}).get("error_rate", 0) * 100 for node in nodes]

            x = np.arange(len(nodes))
            width = 0.35

            ax2.bar(x - width / 2, ebpf_node_rates, width, label="eBPF", color=self.config.colors["ebpf"])
            ax2.bar(x + width / 2, user_node_rates, width, label="Userspace", color=self.config.colors["userspace"])

            ax2.set_xlabel("Node ID")
            ax2.set_ylabel("Error Rate (%)")
            ax2.set_title("Per-Node Error Rates")
            ax2.set_xticks(x)
            ax2.set_xticklabels([f"Node {node}" for node in nodes])
            ax2.legend()
            ax2.grid(True, alpha=0.3)

        # 3. Error variance analysis
        ax3 = axes[1, 0]
        error_variances = [ebpf_errors.get("error_variance", 0), user_errors.get("error_variance", 0)]

        ax3.bar(implementations, error_variances, color=[self.config.colors["ebpf"], self.config.colors["userspace"]])
        ax3.set_ylabel("Error Rate Variance")
        ax3.set_title("Error Rate Consistency Across Nodes")
        ax3.grid(True, alpha=0.3)

        # 4. Reliability score (combination of error rate and consistency)
        ax4 = axes[1, 1]

        # Calculate reliability scores (lower error rate + lower variance = higher reliability)
        ebpf_reliability = 100 - (
            ebpf_errors["overall_error_rate"] * 100 + ebpf_errors.get("error_variance", 0) * 1000
        )
        user_reliability = 100 - (
            user_errors["overall_error_rate"] * 100 + user_errors.get("error_variance", 0) * 1000
        )

        reliability_scores = [max(0, ebpf_reliability), max(0, user_reliability)]

        bars4 = ax4.bar(
            implementations, reliability_scores, color=[self.config.colors["success"], self.config.colors["warning"]]
        )
        ax4.set_ylabel("Reliability Score")
        ax4.set_title("Overall Reliability Assessment")
        ax4.set_ylim([0, 100])
        ax4.grid(True, alpha=0.3)

        for bar, value in zip(bars4, reliability_scores):
            ax4.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 1,
                f"{value:.1f}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(self.config.figures_dir / f"throughput_error_analysis.{fmt}")
        plt.close()

    def create_thread_performance_analysis(self, ebpf_data: Dict, userspace_data: Dict):
        """Create thread-level performance analysis."""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle("Thread Performance Analysis", fontsize=16, fontweight="bold")

        # Extract thread data
        ebpf_threads = ebpf_data.get("stats", [])
        user_threads = userspace_data.get("stats", [])

        if not ebpf_threads or not user_threads:
            logger.warning("Thread data not available")
            plt.close()
            return

        # Calculate per-thread RPS (assuming 10s duration)
        duration = 10
        ebpf_thread_rps = [thread["received"] / duration for thread in ebpf_threads]
        user_thread_rps = [thread["received"] / duration for thread in user_threads]

        # 1. Thread RPS distribution
        ax1 = axes[0, 0]
        ax1.boxplot([ebpf_thread_rps, user_thread_rps], tick_labels=["eBPF", "Userspace"], patch_artist=True)
        ax1.set_ylabel("Requests per Second")
        ax1.set_title("Per-Thread RPS Distribution")
        ax1.grid(True, alpha=0.3)

        # 2. Thread load balancing
        ax2 = axes[0, 1]
        thread_indices = range(max(len(ebpf_threads), len(user_threads)))

        if len(ebpf_threads) == len(user_threads):
            ax2.scatter(
                thread_indices[: len(ebpf_threads)],
                ebpf_thread_rps,
                label="eBPF",
                color=self.config.colors["ebpf"],
                s=60,
            )
            ax2.scatter(
                thread_indices[: len(user_threads)],
                user_thread_rps,
                label="Userspace",
                color=self.config.colors["userspace"],
                s=60,
            )

        ax2.set_xlabel("Thread Index")
        ax2.set_ylabel("Requests per Second")
        ax2.set_title("Thread Load Distribution")
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # 3. Thread performance consistency
        ax3 = axes[1, 0]
        ebpf_cv = np.std(ebpf_thread_rps) / np.mean(ebpf_thread_rps) if np.mean(ebpf_thread_rps) > 0 else 0
        user_cv = np.std(user_thread_rps) / np.mean(user_thread_rps) if np.mean(user_thread_rps) > 0 else 0

        cv_values = [ebpf_cv, user_cv]
        bars3 = ax3.bar(
            ["eBPF", "Userspace"], cv_values, color=[self.config.colors["ebpf"], self.config.colors["userspace"]]
        )
        ax3.set_ylabel("Coefficient of Variation")
        ax3.set_title("Thread Performance Consistency")
        ax3.grid(True, alpha=0.3)

        for bar, value in zip(bars3, cv_values):
            ax3.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.001,
                f"{value:.3f}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

        # 4. Per-thread latency comparison
        ax4 = axes[1, 1]
        ebpf_thread_latencies = [thread.get("latency_stats", {}).get("avg_us", 0) for thread in ebpf_threads]
        user_thread_latencies = [thread.get("latency_stats", {}).get("avg_us", 0) for thread in user_threads]

        ax4.boxplot(
            [ebpf_thread_latencies, user_thread_latencies], tick_labels=["eBPF", "Userspace"], patch_artist=True
        )
        ax4.set_ylabel("Average Latency (μs)")
        ax4.set_title("Per-Thread Latency Distribution")
        ax4.grid(True, alpha=0.3)

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(self.config.figures_dir / f"throughput_thread_analysis.{fmt}")
        plt.close()

    def create_detailed_metrics_comparison(self, analysis: Dict):
        """Create detailed metrics comparison heatmap."""
        _, ax = plt.subplots(figsize=(12, 8))

        # Prepare data for heatmap
        metrics = [
            "Overall RPS",
            "Write RPS",
            "Read RPS",
            "Success Rate (%)",
            "Avg Latency (μs)",
            "P95 Latency (μs)",
            "P99 Latency (μs)",
            "Error Rate (%)",
            "Thread Consistency",
            "Load Balance Quality",
        ]

        ebpf_stats = analysis["ebpf"]["summary_stats"]
        user_stats = analysis["userspace"]["summary_stats"]
        ebpf_thread = analysis["ebpf"]["thread_stats"]
        user_thread = analysis["userspace"]["thread_stats"]

        # Normalize values for comparison (percentage difference from userspace baseline)
        values = []
        for metric in metrics:
            if metric == "Overall RPS":
                ebpf_val = ebpf_stats["overall_rps"]
                user_val = user_stats["overall_rps"]
            elif metric == "Write RPS":
                ebpf_val = ebpf_stats["write_rps"]
                user_val = user_stats["write_rps"]
            elif metric == "Read RPS":
                ebpf_val = ebpf_stats["read_rps"]
                user_val = user_stats["read_rps"]
            elif metric == "Success Rate (%)":
                ebpf_val = ebpf_stats["overall_success_rate"] * 100
                user_val = user_stats["overall_success_rate"] * 100
            elif metric == "Avg Latency (μs)":
                # For latency, lower is better, so invert the comparison
                ebpf_val = user_stats["avg_latency_us"]
                user_val = ebpf_stats["avg_latency_us"]
            elif metric == "P95 Latency (μs)":
                ebpf_val = user_stats["p95_latency_us"]
                user_val = ebpf_stats["p95_latency_us"]
            elif metric == "P99 Latency (μs)":
                ebpf_val = user_stats["p99_latency_us"]
                user_val = ebpf_stats["p99_latency_us"]
            elif metric == "Error Rate (%)":
                # For error rate, lower is better, so invert
                ebpf_val = user_stats["failure_rate"] * 100
                user_val = ebpf_stats["failure_rate"] * 100
            elif metric == "Thread Consistency":
                ebpf_val = 1 - ebpf_thread.get("rps_stats", {}).get("cv", 1)
                user_val = 1 - user_thread.get("rps_stats", {}).get("cv", 1)
            elif metric == "Load Balance Quality":
                ebpf_val = ebpf_thread.get("load_balance_quality", 0)
                user_val = user_thread.get("load_balance_quality", 0)
            else:
                ebpf_val = user_val = 0

            # Calculate percentage improvement
            if user_val > 0:
                improvement = ((ebpf_val - user_val) / user_val) * 100
            else:
                improvement = 0

            values.append([improvement])

        # Create heatmap
        data = np.array(values)
        im = ax.imshow(data, cmap="RdYlGn", aspect="auto", vmin=-50, vmax=50)

        # Set ticks and labels
        ax.set_yticks(range(len(metrics)))
        ax.set_yticklabels(metrics)
        ax.set_xticks([0])
        ax.set_xticklabels(["eBPF vs Userspace"])

        # Add text annotations
        for i in range(len(metrics)):
            ax.text(0, i, f"{values[i][0]:.1f}%", ha="center", va="center", color="black", fontweight="bold")

        ax.set_title("Performance Improvement Matrix\n(eBPF vs Userspace Baseline)", fontsize=14, fontweight="bold")

        # Add colorbar
        cbar = plt.colorbar(im, ax=ax)
        cbar.set_label("Improvement (%)", rotation=270, labelpad=20)

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(self.config.figures_dir / f"throughput_metrics_heatmap.{fmt}")
        plt.close()
