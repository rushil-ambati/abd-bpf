"""
Benchmark execution and result loading for ABD protocol evaluation.

Handles running both latency and throughput benchmarks for eBPF and userspace
implementations, with proper error handling and result archival.
"""

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict

from .config import BENCHMARK_DEFAULTS, EvaluationConfig

logger = logging.getLogger(__name__)


class BenchmarkRunner:
    """Manages benchmark execution and result collection."""

    def __init__(self, config: EvaluationConfig):
        """Initialize benchmark runner with configuration."""
        self.config = config
        self.workspace_root = Path.cwd()

    def run_all_benchmarks(self) -> Dict[str, Dict[str, Any]]:
        """
        Run all benchmarks (latency and throughput) for both implementations.

        Returns:
            Dictionary with structure: {benchmark_type: {implementation: data}}
        """
        results = {"latency": {}, "throughput": {}}

        # Run benchmarks for each implementation
        for implementation in ["ebpf", "userspace"]:
            logger.info(f"Running benchmarks for {implementation} implementation")

            # Run latency benchmark
            try:
                results["latency"][implementation] = self._run_latency_benchmark(implementation)
                logger.info(f"Latency benchmark completed for {implementation}")
            except Exception as e:
                logger.error(f"Latency benchmark failed for {implementation}: {e}")
                raise

            # Run throughput benchmark
            try:
                results["throughput"][implementation] = self._run_throughput_benchmark(implementation)
                logger.info(f"Throughput benchmark completed for {implementation}")
            except Exception as e:
                logger.error(f"Throughput benchmark failed for {implementation}: {e}")
                raise

        return results

    def load_existing_results(self) -> Dict[str, Dict[str, Any]]:
        """
        Load existing benchmark results from data directory.

        Returns:
            Dictionary with structure: {benchmark_type: {implementation: data}}

        Raises:
            FileNotFoundError: If required result files are missing
        """
        results = {"latency": {}, "throughput": {}}

        required_files = [
            ("latency", "ebpf", "ebpf_latency_results.json"),
            ("latency", "userspace", "userspace_latency_results.json"),
            ("throughput", "ebpf", "ebpf_throughput_results.json"),
            ("throughput", "userspace", "userspace_throughput_results.json"),
        ]

        for benchmark_type, implementation, filename in required_files:
            file_path = self.config.data_dir / filename
            if not file_path.exists():
                raise FileNotFoundError(
                    f"Missing benchmark results: {file_path}. "
                    f"Run without --skip-benchmarks to generate new results."
                )

            with open(file_path, "r", encoding="utf-8") as f:
                results[benchmark_type][implementation] = json.load(f)

            logger.info(f"Loaded {benchmark_type} results for {implementation}")

        return results

    def _run_latency_benchmark(self, implementation: str) -> Dict[str, Any]:
        """Run latency benchmark for specified implementation."""
        logger.info(f"Running latency benchmark for {implementation}")

        # Prepare command
        cmd = ["python3", "scripts/run.py"]
        if self.config.debug:
            cmd.append("-d")
        if implementation == "userspace":
            cmd.append("-u")
        cmd.extend(["bench", "latency"])

        # Set environment variables
        env = os.environ.copy()
        output_filename = f"{implementation}_latency_results.json"
        env["ABD_BENCH_OUTPUT"] = output_filename

        if self.config.debug:
            env["RUST_LOG"] = "debug"
        else:
            env["RUST_LOG"] = "info"

        return self._execute_benchmark(
            cmd, env, output_filename, BENCHMARK_DEFAULTS["latency"]["timeout_seconds"], "latency"
        )

    def _run_throughput_benchmark(self, implementation: str) -> Dict[str, Any]:
        """Run throughput benchmark for specified implementation."""
        logger.info(f"Running throughput benchmark for {implementation} with sweep load testing")

        # Prepare command
        cmd = ["python3", "scripts/run.py"]
        if self.config.debug:
            cmd.append("-d")
        if implementation == "userspace":
            cmd.append("-u")
        cmd.extend(["bench", "throughput"])

        # Set environment variables
        env = os.environ.copy()
        output_filename = f"{implementation}_throughput_results.json"
        env["ABD_BENCH_OUTPUT"] = output_filename

        # Set sweep load testing environment variables
        env["ABD_BENCH_SWEEP_LOAD"] = ""
        env["ABD_BENCH_DURATION"] = "5"

        if self.config.debug:
            env["RUST_LOG"] = "debug"
        else:
            env["RUST_LOG"] = "info"

        return self._execute_benchmark(
            cmd, env, output_filename, BENCHMARK_DEFAULTS["throughput"]["timeout_seconds"], "throughput"
        )

    def _execute_benchmark(
        self,
        cmd: list,
        env: dict,
        output_filename: str,
        timeout_seconds: int,
        benchmark_type: str,
    ) -> Dict[str, Any]:
        """
        Execute a benchmark command and handle results.

        Args:
            cmd: Command to execute
            env: Environment variables
            output_filename: Expected output file name
            timeout_seconds: Timeout for benchmark execution
            benchmark_type: Type of benchmark (latency/throughput)
            implementation: Implementation type (ebpf/userspace)

        Returns:
            Parsed benchmark results

        Raises:
            subprocess.CalledProcessError: If benchmark command fails
            subprocess.TimeoutExpired: If benchmark times out
            FileNotFoundError: If results file is not created
        """
        start_time = time.time()

        try:
            # Execute benchmark
            result = subprocess.run(
                cmd,
                cwd=self.workspace_root,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=True,
            )

            duration = time.time() - start_time
            logger.info(f"Benchmark completed in {duration:.1f}s")

            if result.returncode != 0:
                logger.error(f"Benchmark failed with return code {result.returncode}")
                logger.error(f"STDOUT: {result.stdout}")
                logger.error(f"STDERR: {result.stderr}")
                raise subprocess.CalledProcessError(result.returncode, cmd)

            # Load and archive results
            results_file = self.workspace_root / output_filename
            if not results_file.exists():
                raise FileNotFoundError(f"Results file {results_file} not found")

            with open(results_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Archive results
            if BENCHMARK_DEFAULTS[benchmark_type]["archive_results"]:
                archive_path = self.config.data_dir / output_filename
                shutil.move(results_file, archive_path)
                logger.info(f"Results archived to {archive_path}")

            return data

        except subprocess.TimeoutExpired:
            logger.error(f"Benchmark timeout after {timeout_seconds} seconds")
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"Benchmark command failed: {e}")
            logger.error(f"Command: {' '.join(cmd)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during benchmark execution: {e}")
            raise
