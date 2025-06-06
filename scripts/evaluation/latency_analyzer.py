"""
Latency analysis module for ABD protocol evaluation.

Provides comprehensive statistical analysis and visualization capabilities
for latency benchmark results.
"""

import logging
from typing import Any, Dict, List

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats
from scipy.stats import levene, mannwhitneyu, shapiro, ttest_ind

from .config import STATISTICAL_CONFIG, EvaluationConfig

logger = logging.getLogger(__name__)


class LatencyAnalyzer:
    """Handles latency data analysis and visualization."""

    def __init__(self, config: EvaluationConfig):
        """Initialize latency analyzer with configuration."""
        self.config = config

    def analyze_results(self, ebpf_data: Dict, userspace_data: Dict) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of latency benchmark results.

        Args:
            ebpf_data: eBPF benchmark results
            userspace_data: Userspace benchmark results

        Returns:
            Dictionary containing statistical analysis results
        """
        logger.info("Performing latency statistical analysis")

        analysis = {
            "ebpf": {"statistics": {}},
            "userspace": {"statistics": {}},
            "statistical_tests": {},
            "metadata": {
                "analysis_timestamp": pd.Timestamp.now().isoformat(),
                "statistical_config": STATISTICAL_CONFIG,
            },
        }

        # Calculate statistics for each implementation and operation
        for impl, data in [("ebpf", ebpf_data), ("userspace", userspace_data)]:
            for operation in ["write", "read"]:
                latencies = self.extract_latencies(data, operation)
                if latencies:
                    analysis[impl]["statistics"][operation] = self.calculate_statistics(latencies)
                    logger.info(f"{impl.title()} {operation} operations: {len(latencies)} samples")
                else:
                    analysis[impl]["statistics"][operation] = {}
                    logger.warning(f"No {operation} latency data found for {impl}")

        # Perform comparative statistical tests
        for operation in ["write", "read"]:
            ebpf_latencies = self.extract_latencies(ebpf_data, operation)
            userspace_latencies = self.extract_latencies(userspace_data, operation)

            if ebpf_latencies and userspace_latencies:
                analysis["statistical_tests"][operation] = self.perform_statistical_tests(
                    ebpf_latencies, userspace_latencies
                )
                logger.info(f"Statistical tests completed for {operation} operations")
            else:
                analysis["statistical_tests"][operation] = {}
                logger.warning(f"Insufficient data for {operation} operation comparison")

        return analysis

    def extract_latencies(self, data: Dict, operation: str) -> List[float]:
        """
        Extract all latency values for an operation across all nodes.

        Args:
            data: Benchmark results data
            operation: Operation type ('write' or 'read')

        Returns:
            List of latency values in microseconds
        """
        latencies = []
        key = f"{operation}_latencies"

        if key in data:
            for node_latencies in data[key].values():
                latencies.extend(node_latencies)

        return latencies

    def calculate_statistics(self, latencies: List[float]) -> Dict[str, float]:
        """
        Calculate comprehensive statistics for latency data.

        Args:
            latencies: List of latency values

        Returns:
            Dictionary of statistical measures
        """
        if not latencies:
            return {}

        arr = np.array(latencies)

        return {
            "count": len(arr),
            "mean": float(np.mean(arr)),
            "median": float(np.median(arr)),
            "std": float(np.std(arr)),
            "var": float(np.var(arr)),
            "min": float(np.min(arr)),
            "max": float(np.max(arr)),
            "p25": float(np.percentile(arr, 25)),
            "p75": float(np.percentile(arr, 75)),
            "p90": float(np.percentile(arr, 90)),
            "p95": float(np.percentile(arr, 95)),
            "p99": float(np.percentile(arr, 99)),
            "p99_9": float(np.percentile(arr, 99.9)),
            "iqr": float(np.percentile(arr, 75) - np.percentile(arr, 25)),
            "cv": float(np.std(arr) / np.mean(arr)) if np.mean(arr) > 0 else 0,
            "skewness": float(stats.skew(arr)),
            "kurtosis": float(stats.kurtosis(arr)),
            "mad": float(np.median(np.abs(arr - np.median(arr)))),  # Median Absolute Deviation
        }

    def perform_statistical_tests(
        self, ebpf_latencies: List[float], userspace_latencies: List[float]
    ) -> Dict[str, Any]:
        """
        Perform comprehensive statistical tests comparing implementations.

        Args:
            ebpf_latencies: eBPF latency measurements
            userspace_latencies: Userspace latency measurements

        Returns:
            Dictionary containing test results
        """
        results = {}

        # Sample sizes
        results["sample_sizes"] = {
            "ebpf": len(ebpf_latencies),
            "userspace": len(userspace_latencies),
        }

        # Limit sample size for normality tests
        max_samples = STATISTICAL_CONFIG["normality_sample_limit"]
        ebpf_sample = ebpf_latencies[:max_samples] if len(ebpf_latencies) > max_samples else ebpf_latencies
        user_sample = (
            userspace_latencies[:max_samples] if len(userspace_latencies) > max_samples else userspace_latencies
        )

        # Normality tests
        ebpf_shapiro = shapiro(ebpf_sample)
        user_shapiro = shapiro(user_sample)

        results["normality_tests"] = {
            "ebpf_shapiro": {"statistic": float(ebpf_shapiro[0]), "p_value": float(ebpf_shapiro[1])},
            "userspace_shapiro": {"statistic": float(user_shapiro[0]), "p_value": float(user_shapiro[1])},
        }

        # Variance equality test
        levene_result = levene(ebpf_latencies, userspace_latencies)
        results["variance_test"] = {
            "levene_statistic": float(levene_result[0]),
            "levene_p_value": float(levene_result[1]),
        }

        # Mann-Whitney U test (non-parametric)
        mw_result = mannwhitneyu(ebpf_latencies, userspace_latencies, alternative="two-sided")
        results["mann_whitney"] = {"statistic": float(mw_result[0]), "p_value": float(mw_result[1])}

        # T-test (parametric)
        equal_var = levene_result[1] > STATISTICAL_CONFIG["alpha"]
        t_result = ttest_ind(ebpf_latencies, userspace_latencies, equal_var=equal_var)
        results["t_test"] = {
            "statistic": float(t_result[0]),
            "p_value": float(t_result[1]),
            "equal_var": equal_var,
        }

        # Effect size (Cohen's d)
        pooled_std = np.sqrt(
            (
                (len(ebpf_latencies) - 1) * np.var(ebpf_latencies, ddof=1)
                + (len(userspace_latencies) - 1) * np.var(userspace_latencies, ddof=1)
            )
            / (len(ebpf_latencies) + len(userspace_latencies) - 2)
        )

        cohens_d = (np.mean(ebpf_latencies) - np.mean(userspace_latencies)) / pooled_std
        results["effect_size"] = {
            "cohens_d": float(cohens_d),
            "interpretation": self._interpret_cohens_d(cohens_d),
        }

        # Additional effect size measures
        # Glass's Delta (using userspace as control)
        glass_delta = (np.mean(ebpf_latencies) - np.mean(userspace_latencies)) / np.std(userspace_latencies, ddof=1)
        results["effect_size"]["glass_delta"] = float(glass_delta)

        # Hedge's g (corrected Cohen's d for small samples)
        n1, n2 = len(ebpf_latencies), len(userspace_latencies)
        correction_factor = 1 - (3 / (4 * (n1 + n2) - 9))
        hedges_g = cohens_d * correction_factor
        results["effect_size"]["hedges_g"] = float(hedges_g)

        return results

    def _interpret_cohens_d(self, d: float) -> str:
        """Interpret Cohen's d effect size according to conventional thresholds."""
        abs_d = abs(d)
        if abs_d < 0.2:
            return "negligible"
        elif abs_d < 0.5:
            return "small"
        elif abs_d < 0.8:
            return "medium"
        else:
            return "large"

    def create_all_visualizations(self, ebpf_data: Dict, userspace_data: Dict):
        """Create all latency-related visualizations."""
        logger.info("Generating latency visualizations")

        for operation in ["write", "read"]:
            ebpf_latencies = self.extract_latencies(ebpf_data, operation)
            userspace_latencies = self.extract_latencies(userspace_data, operation)

            if ebpf_latencies and userspace_latencies:
                self.create_comparison_plots(ebpf_data, userspace_data, operation)
                self.create_percentile_comparison(ebpf_data, userspace_data, operation)
                self.create_distribution_analysis(ebpf_latencies, userspace_latencies, operation)
                logger.info(f"Generated {operation} latency visualizations")

        # Create per-node breakdown
        for impl, data in [("ebpf", ebpf_data), ("userspace", userspace_data)]:
            for operation in ["write", "read"]:
                if self.extract_latencies(data, operation):
                    self.create_node_breakdown(data, impl, operation)
                    logger.info(f"Generated {impl} {operation} node breakdown")

    def create_comparison_plots(self, ebpf_data: Dict, userspace_data: Dict, operation: str):
        """Create comprehensive comparison plots for latency data."""
        ebpf_latencies = self.extract_latencies(ebpf_data, operation)
        userspace_latencies = self.extract_latencies(userspace_data, operation)

        # Convert to numpy arrays for easier manipulation
        ebpf_us = np.array(ebpf_latencies)
        userspace_us = np.array(userspace_latencies)

        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle(
            f"{operation.title()} Latency Comparison: eBPF vs Userspace",
            fontsize=18,
            fontweight="bold",
        )

        # Box plot
        ax1 = axes[0, 0]
        data_to_plot = [ebpf_us, userspace_us]
        bp = ax1.boxplot(data_to_plot, tick_labels=["eBPF", "Userspace"], patch_artist=True)
        bp["boxes"][0].set_facecolor(self.config.colors["ebpf"])
        bp["boxes"][1].set_facecolor(self.config.colors["userspace"])
        ax1.set_ylabel("Latency (μs)")
        ax1.set_title("Distribution Comparison")
        ax1.grid(True, alpha=0.3)

        # Add statistical annotations
        median_ebpf = np.median(ebpf_us)
        median_user = np.median(userspace_us)
        ax1.text(
            0.02,
            0.98,
            f"eBPF Median: {median_ebpf:.1f}μs",
            transform=ax1.transAxes,
            verticalalignment="top",
            fontsize=10,
        )
        ax1.text(
            0.02,
            0.93,
            f"Userspace Median: {median_user:.1f}μs",
            transform=ax1.transAxes,
            verticalalignment="top",
            fontsize=10,
        )

        # Histogram with density
        ax2 = axes[0, 1]
        # max_val = max(np.max(ebpf_us), np.max(userspace_us))
        bins = np.linspace(0, np.percentile([*ebpf_us, *userspace_us], 95), 50)

        ax2.hist(ebpf_us, bins=bins, alpha=0.7, label="eBPF", color=self.config.colors["ebpf"], density=True)
        ax2.hist(
            userspace_us, bins=bins, alpha=0.7, label="Userspace", color=self.config.colors["userspace"], density=True
        )
        ax2.set_xlabel("Latency (μs)")
        ax2.set_ylabel("Density")
        ax2.set_title("Latency Distribution (95th Percentile)")
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # CDF
        ax3 = axes[1, 0]
        sorted_ebpf = np.sort(ebpf_us)
        sorted_user = np.sort(userspace_us)
        p_ebpf = np.arange(1, len(sorted_ebpf) + 1) / len(sorted_ebpf)
        p_user = np.arange(1, len(sorted_user) + 1) / len(sorted_user)

        ax3.plot(sorted_ebpf, p_ebpf, label="eBPF", color=self.config.colors["ebpf"], linewidth=2)
        ax3.plot(sorted_user, p_user, label="Userspace", color=self.config.colors["userspace"], linewidth=2)
        ax3.set_xlabel("Latency (μs)")
        ax3.set_ylabel("Cumulative Probability")
        ax3.set_title("Cumulative Distribution Function")
        ax3.legend()
        ax3.grid(True, alpha=0.3)

        # Q-Q plot
        ax4 = axes[1, 1]
        stats.probplot(ebpf_us, dist="norm", plot=ax4)
        ax4.get_lines()[0].set_markerfacecolor(self.config.colors["ebpf"])
        ax4.get_lines()[0].set_markeredgecolor(self.config.colors["ebpf"])
        ax4.get_lines()[0].set_label("eBPF")

        stats.probplot(userspace_us, dist="norm", plot=ax4)
        ax4.get_lines()[2].set_markerfacecolor(self.config.colors["userspace"])
        ax4.get_lines()[2].set_markeredgecolor(self.config.colors["userspace"])
        ax4.get_lines()[2].set_label("Userspace")

        ax4.set_title("Q-Q Plot (Normal Distribution)")
        ax4.legend()
        ax4.grid(True, alpha=0.3)

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(self.config.figures_dir / f"latency_{operation}_comparison.{fmt}")
        plt.close()

    def create_percentile_comparison(self, ebpf_data: Dict, userspace_data: Dict, operation: str):
        """Create percentile comparison chart."""
        ebpf_latencies = self.extract_latencies(ebpf_data, operation)
        userspace_latencies = self.extract_latencies(userspace_data, operation)

        percentiles = [50, 75, 90, 95, 99, 99.9]
        ebpf_percs = [np.percentile(ebpf_latencies, p) for p in percentiles]
        userspace_percs = [np.percentile(userspace_latencies, p) for p in percentiles]

        x = np.arange(len(percentiles))
        width = 0.35

        _, ax = plt.subplots(figsize=(12, 8))
        bars1 = ax.bar(x - width / 2, ebpf_percs, width, label="eBPF", color=self.config.colors["ebpf"])
        bars2 = ax.bar(x + width / 2, userspace_percs, width, label="Userspace", color=self.config.colors["userspace"])

        ax.set_xlabel("Percentile")
        ax.set_ylabel("Latency (μs)")
        ax.set_title(f"{operation.title()} Latency Percentiles Comparison")
        ax.set_xticks(x)
        ax.set_xticklabels([f"P{p}" for p in percentiles])
        ax.legend()
        ax.grid(True, alpha=0.3)

        # Add value labels on bars
        def autolabel(bars):
            for bar in bars:
                height = bar.get_height()
                ax.annotate(
                    f"{height:.1f}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    fontsize=9,
                )

        autolabel(bars1)
        autolabel(bars2)

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(self.config.figures_dir / f"latency_{operation}_percentiles.{fmt}")
        plt.close()

    def create_distribution_analysis(
        self, ebpf_latencies: List[float], userspace_latencies: List[float], operation: str
    ):
        """Create detailed distribution analysis plots."""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle(f"{operation.title()} Latency Distribution Analysis", fontsize=16, fontweight="bold")

        # Violin plot
        ax1 = axes[0, 0]
        parts = ax1.violinplot([ebpf_latencies, userspace_latencies], positions=[1, 2], showmeans=True)
        parts["bodies"][0].set_facecolor(self.config.colors["ebpf"])
        parts["bodies"][1].set_facecolor(self.config.colors["userspace"])
        ax1.set_xticks([1, 2])
        ax1.set_xticklabels(["eBPF", "Userspace"])
        ax1.set_ylabel("Latency (μs)")
        ax1.set_title("Distribution Shape Comparison")
        ax1.grid(True, alpha=0.3)

        # Log-scale histogram
        ax2 = axes[0, 1]
        ax2.hist(ebpf_latencies, bins=50, alpha=0.7, label="eBPF", color=self.config.colors["ebpf"], density=True)
        ax2.hist(
            userspace_latencies,
            bins=50,
            alpha=0.7,
            label="Userspace",
            color=self.config.colors["userspace"],
            density=True,
        )
        ax2.set_xlabel("Latency (μs)")
        ax2.set_ylabel("Density")
        ax2.set_yscale("log")
        ax2.set_title("Distribution (Log Scale)")
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # Tail comparison (99th percentile and above)
        ax3 = axes[1, 0]
        ebpf_p99 = np.percentile(ebpf_latencies, 99)
        user_p99 = np.percentile(userspace_latencies, 99)
        ebpf_tail = [x for x in ebpf_latencies if x >= ebpf_p99]
        user_tail = [x for x in userspace_latencies if x >= user_p99]

        if ebpf_tail and user_tail:
            ax3.hist(
                ebpf_tail,
                bins=30,
                alpha=0.7,
                label=f"eBPF (n={len(ebpf_tail)})",
                color=self.config.colors["ebpf"],
                density=True,
            )
            ax3.hist(
                user_tail,
                bins=30,
                alpha=0.7,
                label=f"Userspace (n={len(user_tail)})",
                color=self.config.colors["userspace"],
                density=True,
            )
            ax3.set_xlabel("Latency (μs)")
            ax3.set_ylabel("Density")
            ax3.set_title("Tail Latency Comparison (99th+ Percentile)")
            ax3.legend()
            ax3.grid(True, alpha=0.3)

        # Box plot with outliers
        ax4 = axes[1, 1]
        bp = ax4.boxplot(
            [ebpf_latencies, userspace_latencies],
            tick_labels=["eBPF", "Userspace"],
            patch_artist=True,
            showfliers=True,
        )
        bp["boxes"][0].set_facecolor(self.config.colors["ebpf"])
        bp["boxes"][1].set_facecolor(self.config.colors["userspace"])
        ax4.set_ylabel("Latency (μs)")
        ax4.set_title("Box Plot with Outliers")
        ax4.grid(True, alpha=0.3)

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(self.config.figures_dir / f"latency_{operation}_distribution.{fmt}")
        plt.close()

    def create_node_breakdown(self, data: Dict, implementation: str, operation: str):
        """Create per-node latency breakdown."""
        _, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

        node_data = []
        node_labels = []

        for node_id, latencies in data[f"{operation}_latencies"].items():
            node_data.append(latencies)
            node_labels.append(f"Node {node_id}")

        if not node_data:
            logger.warning(f"No node data available for {implementation} {operation}")
            plt.close()
            return

        # Box plot by node
        bp = ax1.boxplot(node_data, tick_labels=node_labels, patch_artist=True)
        color = self.config.colors["ebpf"] if implementation == "ebpf" else self.config.colors["userspace"]
        for box in bp["boxes"]:
            box.set_facecolor(color)
        ax1.set_ylabel("Latency (μs)")
        ax1.set_title(f"{implementation.title()} - {operation.title()} by Node")
        ax1.grid(True, alpha=0.3)

        # Mean latency by node
        means = [np.mean(data) for data in node_data]
        bars = ax2.bar(node_labels, means, color=color)
        ax2.set_ylabel("Mean Latency (μs)")
        ax2.set_title(f"{implementation.title()} - Mean {operation.title()} by Node")
        ax2.grid(True, alpha=0.3)

        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax2.annotate(
                f"{height:.1f}",
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
            )

        plt.tight_layout()

        # Save in multiple formats
        for fmt in ["png", "svg", "pdf"]:
            plt.savefig(self.config.figures_dir / f"latency_{implementation}_{operation}_by_node.{fmt}")
        plt.close()
