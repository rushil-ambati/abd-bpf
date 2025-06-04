"""
Configuration management for ABD protocol evaluation.

Defines configuration classes and setup functions for consistent evaluation
parameters across all analysis modules.
"""

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict

import matplotlib.pyplot as plt


@dataclass
class EvaluationConfig:
    """Configuration for ABD protocol evaluation."""

    # Directories
    output_dir: Path

    # Number of nodes
    num_nodes: int = 3

    # Benchmark settings
    debug: bool = False
    sweep: bool = False

    # Visualization settings
    skip_latex: bool = False

    # Color scheme for consistent plotting
    colors: Dict[str, str] = None

    def __post_init__(self):
        """Initialize derived attributes."""
        if self.colors is None:
            self.colors = {
                "ebpf": "#2E8B57",  # Sea Green
                "userspace": "#B22222",  # Fire Brick
                "neutral": "#4169E1",  # Royal Blue
                "accent": "#FF6B35",  # Orange Red
                "success": "#28A745",  # Success Green
                "warning": "#FFC107",  # Warning Yellow
                "error": "#DC3545",  # Error Red
            }

        # Ensure output_dir is a Path object
        if isinstance(self.output_dir, str):
            self.output_dir = Path(self.output_dir)

        # Create subdirectories
        self.figures_dir = self.output_dir / "figures"
        self.data_dir = self.output_dir / "data"
        self.reports_dir = self.output_dir / "reports"

        # Create directories
        for directory in [self.figures_dir, self.data_dir, self.reports_dir]:
            directory.mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)


def setup_matplotlib(use_latex: bool = True):
    """
    Configure matplotlib for publication-quality figures.

    Args:
        use_latex: Whether to enable LaTeX rendering (requires LaTeX installation)
    """
    plt.rcParams.update(
        {
            "font.size": 12,
            "font.family": "serif",
            "font.serif": ["Computer Modern Roman", "Times New Roman", "serif"],
            "text.usetex": use_latex,
            "text.latex.preamble": r"\DeclareUnicodeCharacter{03BC}{\ensuremath{\mu}}",
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
            "axes.axisbelow": True,
            "axes.edgecolor": "black",
            "axes.linewidth": 1.2,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
        }
    )


# Statistical test configuration
STATISTICAL_CONFIG = {
    "alpha": 0.05,  # Significance level
    "normality_sample_limit": 5000,  # Max samples for Shapiro-Wilk test
    "bootstrap_iterations": 10000,  # Bootstrap resampling iterations
    "confidence_interval": 0.95,  # Confidence interval level
}


# Benchmark configuration defaults
BENCHMARK_DEFAULTS = {
    "latency": {"timeout_seconds": 600, "archive_results": True},
    "throughput": {"timeout_seconds": 300, "archive_results": True},
}
