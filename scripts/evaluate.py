#!/usr/bin/env python3
"""
ABD Protocol Evaluation Script

This script performs comprehensive latency benchmarks on both userspace and eBPF
implementations of the ABD protocol, then conducts thorough statistical analysis
and generates publication-quality graphs for master's thesis evaluation.
"""
import argparse
import json
import os
import subprocess
import time
import shutil
import warnings
from pathlib import Path
from typing import Dict, List

# Third-party imports
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy import stats
from scipy.stats import mannwhitneyu, ttest_ind, shapiro, levene

# Suppress warnings for cleaner output
warnings.filterwarnings("ignore", category=RuntimeWarning)

# Set up matplotlib for publication quality
plt.rcParams.update(
    {
        "font.size": 12,
        "font.family": "serif",
        "font.serif": "cm",
        "text.usetex": True,  # Set to True if LaTeX is available
        "figure.figsize": (10, 6),
        "figure.dpi": 300,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.1,
        "axes.labelsize": 14,
        "axes.titlesize": 16,
        "xtick.labelsize": 12,
        "ytick.labelsize": 12,
        "legend.fontsize": 12,
        "lines.linewidth": 2,
        "axes.grid": True,
        "grid.alpha": 0.3,
    }
)

COLORS = {
    "ebpf": "#2E8B57",  # Sea Green
    "userspace": "#B22222",  # Fire Brick
    "neutral": "#4169E1",  # Royal Blue
}


class BenchmarkEvaluator:
    """Handles ABD evaluation, benchmarking, and reporting."""

    def __init__(self, output_dir: str = "evaluation_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.figures_dir = self.output_dir / "figures"
        self.figures_dir.mkdir(exist_ok=True)
        self.data_dir = self.output_dir / "data"
        self.data_dir.mkdir(exist_ok=True)

        # Results storage
        self.results = {}
        self.analysis_results = {}

    def run_benchmark(
        self,
        implementation: str,
        nodes: int,
        iterations: int,
        warmup: int,
        debug: bool = False,
    ) -> Dict:
        """Run benchmark for specified implementation."""
        print(f"\n{'='*60}")
        print(f"Running {implementation.upper()} benchmark...")
        print(f"Nodes: {nodes}, Iterations: {iterations}, Warmup: {warmup}")
        print(f"{'='*60}")

        # Prepare command
        cmd = ["python3", "scripts/run.py", "-s", str(nodes)]
        if debug:
            cmd.append("-d")
        if implementation == "userspace":
            cmd.append("-u")
        cmd.extend(["bench", "latency"])

        # Set environment variables for benchmark parameters
        env = os.environ.copy()
        env["BENCH_ITERATIONS"] = str(iterations)
        env["BENCH_WARMUP"] = str(warmup)

        try:
            # Run the benchmark
            start_time = time.time()
            result = subprocess.run(
                cmd,
                cwd=Path.cwd(),
                env=env,
                capture_output=True,
                text=True,
                timeout=600,
                check=True,
            )
            duration = time.time() - start_time

            if result.returncode != 0:
                print(f"Error running {implementation} benchmark:")
                print("STDOUT:", result.stdout)
                print("STDERR:", result.stderr)
                raise subprocess.CalledProcessError(result.returncode, cmd)

            print(f"Benchmark completed in {duration:.1f}s")

            # Load results
            results_file = Path("latency_results.json")
            if not results_file.exists():
                raise FileNotFoundError(f"Results file {results_file} not found")

            with open(results_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Archive results
            archive_path = self.data_dir / f"{implementation}_latency_results.json"
            shutil.copy2(results_file, archive_path)
            print(f"Results archived to {archive_path}")

            return data

        except subprocess.TimeoutExpired:
            print("Benchmark timeout after 10 minutes")
            raise
        except Exception as e:
            print(f"Failed to run {implementation} benchmark: {e}")
            raise

    def load_existing_results(self, implementation: str) -> Dict:
        """Load existing benchmark results."""
        results_file = self.data_dir / f"{implementation}_latency_results.json"
        if not results_file.exists():
            raise FileNotFoundError(f"No existing results for {implementation}")

        with open(results_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def extract_latencies(self, data: Dict, operation: str) -> List[float]:
        """Extract all latency values for an operation across all nodes."""
        latencies = []
        key = f"{operation}_latencies"
        for node_latencies in data[key].values():
            latencies.extend(node_latencies)
        return latencies

    def calculate_statistics(self, latencies: List[float]) -> Dict:
        """Calculate comprehensive statistics for latency data."""
        if not latencies:
            return {}

        arr = np.array(latencies)

        return {
            "count": len(arr),
            "mean": np.mean(arr),
            "median": np.median(arr),
            "std": np.std(arr),
            "min": np.min(arr),
            "max": np.max(arr),
            "p25": np.percentile(arr, 25),
            "p75": np.percentile(arr, 75),
            "p90": np.percentile(arr, 90),
            "p95": np.percentile(arr, 95),
            "p99": np.percentile(arr, 99),
            "iqr": np.percentile(arr, 75) - np.percentile(arr, 25),
            "cv": np.std(arr) / np.mean(arr),  # Coefficient of variation
            "skewness": stats.skew(arr),
            "kurtosis": stats.kurtosis(arr),
        }

    def perform_statistical_tests(self, ebpf_latencies: List[float], userspace_latencies: List[float]) -> Dict:
        """Perform comprehensive statistical tests comparing implementations."""
        results = {}

        # Sample sizes
        results["sample_sizes"] = {
            "ebpf": len(ebpf_latencies),
            "userspace": len(userspace_latencies),
        }

        # Normality tests
        ebpf_shapiro = shapiro(ebpf_latencies[:5000] if len(ebpf_latencies) > 5000 else ebpf_latencies)
        user_shapiro = shapiro(userspace_latencies[:5000] if len(userspace_latencies) > 5000 else userspace_latencies)

        results["normality_tests"] = {
            "ebpf_shapiro": {"statistic": ebpf_shapiro[0], "p_value": ebpf_shapiro[1]},
            "userspace_shapiro": {
                "statistic": user_shapiro[0],
                "p_value": user_shapiro[1],
            },
        }

        # Variance equality test
        levene_result = levene(ebpf_latencies, userspace_latencies)
        results["variance_test"] = {
            "levene_statistic": levene_result[0],
            "levene_p_value": levene_result[1],
        }

        # Mann-Whitney U test (non-parametric)
        mw_result = mannwhitneyu(ebpf_latencies, userspace_latencies, alternative="two-sided")
        results["mann_whitney"] = {"statistic": mw_result[0], "p_value": mw_result[1]}

        # T-test (parametric)
        equal_var = levene_result[1] > 0.05
        t_result = ttest_ind(ebpf_latencies, userspace_latencies, equal_var=equal_var)
        results["t_test"] = {
            "statistic": t_result[0],
            "p_value": t_result[1],
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
            "cohens_d": cohens_d,
            "interpretation": self._interpret_cohens_d(cohens_d),
        }

        return results

    def _interpret_cohens_d(self, d: float) -> str:
        """Interpret Cohen's d effect size."""
        abs_d = abs(d)
        if abs_d < 0.2:
            return "negligible"
        elif abs_d < 0.5:
            return "small"
        elif abs_d < 0.8:
            return "medium"
        else:
            return "large"

    def create_comparison_plots(self, ebpf_data: Dict, userspace_data: Dict, operation: str):
        """Create comprehensive comparison plots."""
        ebpf_latencies = self.extract_latencies(ebpf_data, operation)
        userspace_latencies = self.extract_latencies(userspace_data, operation)

        # Data is already in microseconds, do not multiply
        ebpf_us = ebpf_latencies
        userspace_us = userspace_latencies

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
        bp["boxes"][0].set_facecolor(COLORS["ebpf"])
        bp["boxes"][1].set_facecolor(COLORS["userspace"])
        ax1.set_ylabel("Latency ($\\mu$s)")
        ax1.set_title("Distribution Comparison")
        ax1.grid(True, alpha=0.3)

        # Histogram
        ax2 = axes[0, 1]
        # Use a flattened list to get the true max value across both lists (linter-friendly)
        max_val = max([*ebpf_us, *userspace_us])
        bins = np.linspace(0, max_val, 50)
        ax2.hist(
            ebpf_us,
            bins=bins,
            alpha=0.7,
            label="eBPF",
            color=COLORS["ebpf"],
            density=True,
        )
        ax2.hist(
            userspace_us,
            bins=bins,
            alpha=0.7,
            label="Userspace",
            color=COLORS["userspace"],
            density=True,
        )
        ax2.set_xlabel("Latency ($\\mu$s)")
        ax2.set_ylabel("Density")
        ax2.set_title("Latency Distribution")
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        # CDF
        ax3 = axes[1, 0]
        sorted_ebpf = np.sort(ebpf_us)
        sorted_user = np.sort(userspace_us)
        p_ebpf = np.arange(1, len(sorted_ebpf) + 1) / len(sorted_ebpf)
        p_user = np.arange(1, len(sorted_user) + 1) / len(sorted_user)
        ax3.plot(sorted_ebpf, p_ebpf, label="eBPF", color=COLORS["ebpf"], linewidth=2)
        ax3.plot(
            sorted_user,
            p_user,
            label="Userspace",
            color=COLORS["userspace"],
            linewidth=2,
        )
        ax3.set_xlabel("Latency ($\\mu$s)")
        ax3.set_ylabel("Cumulative Probability")
        ax3.set_title("Cumulative Distribution Function")
        ax3.legend()
        ax3.grid(True, alpha=0.3)

        # Q-Q plot
        ax4 = axes[1, 1]
        stats.probplot(ebpf_us, dist="norm", plot=ax4)
        ax4.get_lines()[0].set_markerfacecolor(COLORS["ebpf"])
        ax4.get_lines()[0].set_markeredgecolor(COLORS["ebpf"])
        ax4.get_lines()[0].set_label("eBPF")
        stats.probplot(userspace_us, dist="norm", plot=ax4)
        ax4.get_lines()[2].set_markerfacecolor(COLORS["userspace"])
        ax4.get_lines()[2].set_markeredgecolor(COLORS["userspace"])
        ax4.get_lines()[2].set_label("Userspace")
        ax4.set_title("Q-Q Plot (Normal Distribution)")
        ax4.legend()
        ax4.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(self.figures_dir / f"{operation}_comparison.png")
        plt.savefig(self.figures_dir / f"{operation}_comparison.pdf")
        plt.close()

    def create_percentile_comparison(self, ebpf_data: Dict, userspace_data: Dict, operation: str):
        """Create percentile comparison chart."""
        ebpf_latencies = self.extract_latencies(ebpf_data, operation)
        userspace_latencies = self.extract_latencies(userspace_data, operation)

        percentiles = [50, 90, 95, 99, 99.9]
        ebpf_percs = [np.percentile(ebpf_latencies, p) for p in percentiles]
        userspace_percs = [np.percentile(userspace_latencies, p) for p in percentiles]

        x = np.arange(len(percentiles))
        width = 0.35

        _, ax = plt.subplots(figsize=(12, 8))
        bars1 = ax.bar(x - width / 2, ebpf_percs, width, label="eBPF", color=COLORS["ebpf"])
        bars2 = ax.bar(
            x + width / 2,
            userspace_percs,
            width,
            label="Userspace",
            color=COLORS["userspace"],
        )

        ax.set_xlabel("Percentile")
        ax.set_ylabel("Latency ($\\mu$s)")
        ax.set_title(f"{operation.title()} Latency Percentiles Comparison")
        ax.set_xticks(x)
        ax.set_xticklabels([f"P{p}" for p in percentiles])
        ax.legend()
        ax.grid(True, alpha=0.3)

        # Add value labels on bars
        def autolabel(bar_containers):
            for rect in bar_containers:
                height = rect.get_height()
                ax.annotate(
                    f"{height:.2f}",
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                )

        autolabel(bars1)
        autolabel(bars2)

        plt.tight_layout()
        plt.savefig(self.figures_dir / f"{operation}_percentiles.png")
        plt.savefig(self.figures_dir / f"{operation}_percentiles.pdf")
        plt.close()

    def create_node_breakdown(self, data: Dict, implementation: str, operation: str):
        """Create per-node latency breakdown."""
        _, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

        node_data = []
        node_labels = []

        for node_id, latencies in data[f"{operation}_latencies"].items():
            if latencies:  # Only include nodes with data
                latencies_us = latencies  # Already in μs
                node_data.append(latencies_us)
                node_labels.append(f"Node {node_id}")

        if not node_data:
            print(f"No data for {operation} operation in {implementation}")
            return

        # Box plot by node
        bp = ax1.boxplot(node_data, tick_labels=node_labels, patch_artist=True)
        color = COLORS["ebpf"] if implementation == "ebpf" else COLORS["userspace"]
        for box in bp["boxes"]:
            box.set_facecolor(color)
        ax1.set_ylabel("Latency ($\\mu$s)")
        ax1.set_title(f"{implementation.title()} - {operation.title()} by Node")
        ax1.grid(True, alpha=0.3)

        # Mean latency by node
        means = [np.mean(data) for data in node_data]
        ax2.bar(node_labels, means, color=color)
        ax2.set_ylabel("Mean Latency ($\\mu$s)")
        ax2.set_title(f"{implementation.title()} - Mean {operation.title()} by Node")
        ax2.grid(True, alpha=0.3)

        # Add value labels
        for i, v in enumerate(means):
            ax2.text(i, v + max(means) * 0.01, f"{v:.2f}", ha="center", va="bottom")

        plt.tight_layout()
        plt.savefig(self.figures_dir / f"{implementation}_{operation}_by_node.png")
        plt.savefig(self.figures_dir / f"{implementation}_{operation}_by_node.pdf")
        plt.close()

    def create_summary_table(self, analysis: Dict) -> pd.DataFrame:
        """Create summary statistics table."""
        data = []
        for impl in ["ebpf", "userspace"]:
            for op in ["write", "read"]:
                op_stats = analysis[impl]["statistics"][op]
                if op_stats:  # Only include if we have data
                    data.append(
                        {
                            "Implementation": impl.title(),
                            "Operation": op.title(),
                            "Count": op_stats["count"],
                            "Mean (μs)": f"{op_stats['mean']:.3f}",
                            "Median (μs)": f"{op_stats['median']:.3f}",
                            "Std Dev (μs)": f"{op_stats['std']:.3f}",
                            "P95 (μs)": f"{op_stats['p95']:.3f}",
                            "P99 (μs)": f"{op_stats['p99']:.3f}",
                            "CV": f"{op_stats['cv']:.3f}",
                        }
                    )
        return pd.DataFrame(data)

    def generate_report(self, analysis: Dict):
        """Generate comprehensive evaluation report."""
        report_path = self.output_dir / "evaluation_report.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("# ABD Protocol Implementation Evaluation\n\n")
            f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("## Executive Summary\n\n")

            # Write operation analysis
            if "write" in analysis["statistical_tests"]:
                write_stats = analysis["statistical_tests"]["write"]
                cohens_d = write_stats["effect_size"]["cohens_d"]
                p_value = write_stats["mann_whitney"]["p_value"]

                f.write("### Write Operation Performance\n\n")
                f.write(f"- **Statistical Significance**: p-value = {p_value:.2e}\n")
                f.write(
                    f"- **Effect Size**: Cohen's d = {cohens_d:.3f} ({write_stats['effect_size']['interpretation']})\n"
                )

                ebpf_mean = analysis["ebpf"]["statistics"]["write"]["mean"]
                user_mean = analysis["userspace"]["statistics"]["write"]["mean"]
                improvement = ((user_mean - ebpf_mean) / user_mean) * 100

                f.write(
                    f"- **Performance**: eBPF shows {improvement:.1f}% "
                    f"{'improvement' if improvement > 0 else 'degradation'} in mean latency\n"
                )
                f.write(f"  - eBPF: {ebpf_mean:.3f} μs\n")
                f.write(f"  - Userspace: {user_mean:.3f} μs\n\n")

            # Read operation analysis
            if "read" in analysis["statistical_tests"]:
                read_stats = analysis["statistical_tests"]["read"]
                if read_stats:  # Check if we have read data
                    cohens_d = read_stats["effect_size"]["cohens_d"]
                    p_value = read_stats["mann_whitney"]["p_value"]

                    f.write("### Read Operation Performance\n\n")
                    f.write(f"- **Statistical Significance**: p-value = {p_value:.2e}\n")
                    f.write(
                        f"- **Effect Size**: Cohen's d = {cohens_d:.3f} "
                        f"({read_stats['effect_size']['interpretation']})\n"
                    )

                    ebpf_mean = analysis["ebpf"]["statistics"]["read"]["mean"]
                    user_mean = analysis["userspace"]["statistics"]["read"]["mean"]
                    improvement = ((user_mean - ebpf_mean) / user_mean) * 100

                    f.write(
                        f"- **Performance**: eBPF shows {improvement:.1f}% "
                        f"{'improvement' if improvement > 0 else 'degradation'} in mean latency\n"
                    )
                    f.write(f"  - eBPF: {ebpf_mean:.3f} μs\n")
                    f.write(f"  - Userspace: {user_mean:.3f} μs\n\n")

            f.write("## Detailed Statistics\n\n")
            summary_table = self.create_summary_table(analysis)
            f.write(summary_table.to_markdown(index=False))
            f.write("\n\n")

            f.write("## Statistical Tests\n\n")
            for operation in ["write", "read"]:
                if operation in analysis["statistical_tests"]:
                    tests = analysis["statistical_tests"][operation]
                    if tests:
                        f.write(f"### {operation.title()} Operation\n\n")
                        f.write(
                            f"- **Mann-Whitney U Test**: U = "
                            f"{tests['mann_whitney']['statistic']:.0f}, "
                            f"p = {tests['mann_whitney']['p_value']:.2e}\n"
                        )
                        f.write(
                            f"- **T-Test**: t = {tests['t_test']['statistic']:.3f}, "
                            f"p = {tests['t_test']['p_value']:.2e}\n"
                        )
                        f.write(f"- **Effect Size**: Cohen's d = {tests['effect_size']['cohens_d']:.3f}\n")
                        f.write(
                            f"- **Normality (eBPF)**: Shapiro p = "
                            f"{tests['normality_tests']['ebpf_shapiro']['p_value']:.2e}\n"
                        )
                        f.write(
                            f"- **Normality (Userspace)**: Shapiro p = "
                            f"{tests['normality_tests']['userspace_shapiro']['p_value']:.2e}\n"
                        )
                        f.write(
                            f"- **Equal Variance**: Levene p = " f"{tests['variance_test']['levene_p_value']:.2e}\n\n"
                        )

            f.write("## Figures\n\n")
            f.write("The following figures are generated for detailed analysis:\n\n")
            f.write("- `write_comparison.png/pdf`: Comprehensive write latency comparison\n")
            f.write("- `write_percentiles.png/pdf`: Write latency percentiles\n")
            f.write("- `read_comparison.png/pdf`: Comprehensive read latency comparison (if data available)\n")
            f.write("- `read_percentiles.png/pdf`: Read latency percentiles (if data available)\n")
            f.write("- `*_by_node.png/pdf`: Per-node breakdown for each implementation\n\n")

            f.write("## Methodology\n\n")
            f.write("### Statistical Tests Used\n\n")
            f.write("1. **Mann-Whitney U Test**: Non-parametric test for comparing distributions\n")
            f.write("2. **Independent t-test**: Parametric test for comparing means\n")
            f.write("3. **Shapiro-Wilk Test**: Test for normality of distributions\n")
            f.write("4. **Levene's Test**: Test for equality of variances\n")
            f.write("5. **Cohen's d**: Effect size measure\n\n")

            f.write("### Effect Size Interpretation (Cohen's d)\n\n")
            f.write("- |d| < 0.2: Negligible effect\n")
            f.write("- 0.2 ≤ |d| < 0.5: Small effect\n")
            f.write("- 0.5 ≤ |d| < 0.8: Medium effect\n")
            f.write("- |d| ≥ 0.8: Large effect\n\n")

        print(f"Evaluation report saved to {report_path}")

    def analyze_results(self, ebpf_data: Dict, userspace_data: Dict) -> Dict:
        """Perform comprehensive analysis of benchmark results."""
        analysis = {
            "ebpf": {"statistics": {}},
            "userspace": {"statistics": {}},
            "statistical_tests": {},
        }

        print("\nPerforming statistical analysis...")

        # Calculate statistics for each implementation and operation
        for impl, data in [("ebpf", ebpf_data), ("userspace", userspace_data)]:
            for operation in ["write", "read"]:
                latencies = self.extract_latencies(data, operation)
                analysis[impl]["statistics"][operation] = self.calculate_statistics(latencies)
                print(f"{impl.title()} {operation} operations: {len(latencies)} samples")

        # Perform comparative statistical tests
        for operation in ["write", "read"]:
            ebpf_latencies = self.extract_latencies(ebpf_data, operation)
            userspace_latencies = self.extract_latencies(userspace_data, operation)

            if ebpf_latencies and userspace_latencies:
                analysis["statistical_tests"][operation] = self.perform_statistical_tests(
                    ebpf_latencies, userspace_latencies
                )
                print(f"Statistical tests completed for {operation} operations")
            else:
                print(f"Insufficient data for {operation} operation comparison")

        return analysis

    def run_full_evaluation(
        self,
        nodes: int,
        iterations: int,
        warmup: int,
        debug: bool,
        skip_benchmarks: bool,
    ):
        """Run complete evaluation pipeline."""
        print("ABD Protocol Evaluation")
        print("=" * 50)

        if skip_benchmarks:
            print("Loading existing benchmark results...")
            try:
                ebpf_data = self.load_existing_results("ebpf")
                userspace_data = self.load_existing_results("userspace")
            except FileNotFoundError as e:
                print(f"Error: {e}")
                print("Run without --skip-benchmarks to generate new results.")
                return
        else:
            # Run benchmarks
            ebpf_data = self.run_benchmark("ebpf", nodes, iterations, warmup, debug)
            userspace_data = self.run_benchmark("userspace", nodes, iterations, warmup, debug)

        # Analyze results
        analysis = self.analyze_results(ebpf_data, userspace_data)

        # Generate visualizations
        print("\nGenerating visualizations...")

        # Main comparison plots
        for operation in ["write", "read"]:
            ebpf_latencies = self.extract_latencies(ebpf_data, operation)
            userspace_latencies = self.extract_latencies(userspace_data, operation)

            if ebpf_latencies and userspace_latencies:
                self.create_comparison_plots(ebpf_data, userspace_data, operation)
                self.create_percentile_comparison(ebpf_data, userspace_data, operation)
                print(f"Generated {operation} comparison plots")

        # Per-node breakdown
        for impl, data in [("ebpf", ebpf_data), ("userspace", userspace_data)]:
            for operation in ["write", "read"]:
                if self.extract_latencies(data, operation):
                    self.create_node_breakdown(data, impl, operation)
                    print(f"Generated {impl} {operation} node breakdown")

        # Generate report
        self.generate_report(analysis)

        print(f"\nEvaluation complete! Results saved to: {self.output_dir}")
        print(f"View the report: {self.output_dir}/evaluation_report.md")


def main():
    """Main entry point for ABD evaluation script."""
    parser = argparse.ArgumentParser(description="ABD Protocol Evaluation Script")
    parser.add_argument("--nodes", type=int, default=3, help="Number of nodes")
    parser.add_argument("--iterations", type=int, default=1000, help="Number of benchmark iterations")
    parser.add_argument("--warmup", type=int, default=50, help="Number of warmup iterations")
    parser.add_argument("--output", default="evaluation_results", help="Output directory")
    parser.add_argument("--skip-benchmarks", action="store_true", help="Skip running benchmarks")
    parser.add_argument("--debug", action="store_true", help="Use debug build")
    args = parser.parse_args()
    evaluator = BenchmarkEvaluator(args.output)
    evaluator.run_full_evaluation(args.nodes, args.iterations, args.warmup, args.debug, args.skip_benchmarks)


if __name__ == "__main__":
    main()
