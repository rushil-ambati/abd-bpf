"""
eBPF CPU Utilization Monitoring Module for ABD Protocol Evaluation

This module provides eBPF-specific CPU utilization monitoring by capturing
run_time_ns metrics from abd_tc and abd_xdp programs using bpftool.

Author: ABD Protocol Research Team
"""

import json
import logging
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class eBPFMonitor:
    """
    Monitors eBPF program CPU utilization using bpftool prog show.

    This class tracks run_time_ns metrics for ABD-specific eBPF programs:
    - abd_tc (sched_cls type)
    - abd_xdp (xdp type)
    """

    def __init__(self, sample_interval: float = 1.0, output_dir: Path = None):
        """
        Initialize eBPF monitor.

        Args:
            sample_interval: Sampling interval in seconds (default: 1.0s)
            output_dir: Directory to save monitoring data (default: logs/)
        """
        self.sample_interval = sample_interval
        self.output_dir = output_dir or Path("logs")
        self.output_dir.mkdir(exist_ok=True)

        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        self.start_time = None

        # Data storage
        self.ebpf_data = []
        self.program_baselines = {}  # program_id -> initial_run_time_ns

        # Program tracking
        self.target_programs = ["abd_tc", "abd_xdp"]

        logger.info(f"eBPF Monitor initialized with {sample_interval}s sampling interval")

    def start_monitoring(self):
        """Start eBPF monitoring in a background thread."""
        if self.is_monitoring:
            logger.warning("eBPF monitoring is already running")
            return

        self.is_monitoring = True
        self.start_time = time.time()

        # Clear previous data
        self.ebpf_data.clear()
        self.program_baselines.clear()

        # Get initial baseline measurements
        self._capture_baseline()

        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

        logger.info("eBPF monitoring started")

    def stop_monitoring(self):
        """Stop eBPF monitoring and save data."""
        if not self.is_monitoring:
            logger.warning("eBPF monitoring is not running")
            return

        self.is_monitoring = False

        # Wait for monitoring thread to finish
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)

        # Save monitoring data
        self._save_data()

        logger.info("eBPF monitoring stopped and data saved")

    def _monitor_loop(self):
        """Main monitoring loop running in background thread."""
        logger.info("eBPF monitoring loop started")

        while self.is_monitoring:
            try:
                timestamp = time.time()
                relative_time = timestamp - self.start_time

                # Collect eBPF program metrics
                self._collect_ebpf_metrics(timestamp, relative_time)

                # Sleep until next sample
                time.sleep(self.sample_interval)

            except Exception as e:
                logger.error(f"Error in eBPF monitoring loop: {e}")
                if self.is_monitoring:  # Only sleep if still monitoring
                    time.sleep(self.sample_interval)

    def _capture_baseline(self):
        """Capture baseline run_time_ns values for all ABD programs."""
        try:
            programs = self._get_bpf_programs()

            for prog in programs:
                if self._is_abd_program(prog):
                    prog_id = prog.get("id")
                    run_time_ns = prog.get("run_time_ns", 0)

                    if prog_id is not None:
                        self.program_baselines[prog_id] = run_time_ns
                        logger.debug(f"Baseline for program {prog_id} ({prog.get('name')}): {run_time_ns} ns")

            logger.info(f"Captured baselines for {len(self.program_baselines)} ABD programs")

        except Exception as e:
            logger.error(f"Failed to capture eBPF program baselines: {e}")

    def _collect_ebpf_metrics(self, timestamp: float, relative_time: float):
        """Collect eBPF program run_time_ns metrics."""
        try:
            programs = self._get_bpf_programs()
            sample_data = {"timestamp": timestamp, "relative_time": relative_time, "programs": []}

            for prog in programs:
                if self._is_abd_program(prog):
                    prog_id = prog.get("id")
                    prog_name = prog.get("name")
                    prog_type = prog.get("type")
                    run_time_ns = prog.get("run_time_ns", 0)
                    run_cnt = prog.get("run_cnt", 0)

                    # Calculate delta since baseline
                    baseline = self.program_baselines.get(prog_id, 0)
                    delta_run_time_ns = run_time_ns - baseline

                    # Calculate average time per run
                    avg_time_per_run = run_time_ns / run_cnt if run_cnt > 0 else 0

                    prog_data = {
                        "id": prog_id,
                        "name": prog_name,
                        "type": prog_type,
                        "run_time_ns": run_time_ns,
                        "run_cnt": run_cnt,
                        "delta_run_time_ns": delta_run_time_ns,
                        "avg_time_per_run_ns": avg_time_per_run,
                        "pids": prog.get("pids", []),
                    }

                    sample_data["programs"].append(prog_data)

            self.ebpf_data.append(sample_data)

            logger.debug(
                f"Collected metrics for {len(sample_data['programs'])} ABD programs at t={relative_time:.2f}s"
            )

        except Exception as e:
            logger.error(f"Failed to collect eBPF metrics: {e}")

    def _get_bpf_programs(self) -> List[Dict[str, Any]]:
        """Get all BPF programs using bpftool prog show -j."""
        try:
            result = subprocess.run(
                ["sudo", "bpftool", "prog", "show", "-j"], capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                logger.error(f"bpftool command failed: {result.stderr}")
                return []

            programs = json.loads(result.stdout)
            return programs

        except subprocess.TimeoutExpired:
            logger.error("bpftool command timed out")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse bpftool JSON output: {e}")
            return []
        except Exception as e:
            logger.error(f"Error running bpftool: {e}")
            return []

    def _is_abd_program(self, prog: Dict[str, Any]) -> bool:
        """Check if a program is an ABD-related program."""
        prog_name = prog.get("name", "")
        # prog_type = prog.get("type", "")

        # Check for ABD programs
        if prog_name in self.target_programs:
            return True

        # Additional check for programs attached to ABD processes
        pids = prog.get("pids", [])
        for pid_info in pids:
            comm = pid_info.get("comm", "")
            if "abd-ebpf" in comm:
                return True

        return False

    def _save_data(self):
        """Save eBPF monitoring data to JSON file."""
        if not self.ebpf_data:
            logger.warning("No eBPF monitoring data to save")
            return

        try:
            # Save raw data
            output_file = self.output_dir / f"ebpf_monitor_{int(self.start_time)}.json"

            monitoring_data = {
                "metadata": {
                    "start_time": self.start_time,
                    "end_time": time.time(),
                    "sample_interval": self.sample_interval,
                    "total_samples": len(self.ebpf_data),
                    "target_programs": self.target_programs,
                    "program_baselines": self.program_baselines,
                },
                "samples": self.ebpf_data,
            }

            with open(output_file, "w") as f:
                json.dump(monitoring_data, f, indent=2)

            logger.info(f"eBPF monitoring data saved to {output_file}")

            # Generate summary statistics
            self._save_summary_stats(monitoring_data)

        except Exception as e:
            logger.error(f"Failed to save eBPF monitoring data: {e}")

    def _save_summary_stats(self, monitoring_data: Dict[str, Any]):
        """Generate and save summary statistics."""
        try:
            summary_file = self.output_dir / f"ebpf_summary_{int(self.start_time)}.json"

            # Calculate per-program statistics
            program_stats = {}

            for sample in self.ebpf_data:
                for prog in sample["programs"]:
                    prog_id = prog["id"]
                    prog_name = prog["name"]

                    if prog_id not in program_stats:
                        program_stats[prog_id] = {
                            "name": prog_name,
                            "type": prog["type"],
                            "delta_run_times": [],
                            "run_counts": [],
                            "avg_times_per_run": [],
                        }

                    program_stats[prog_id]["delta_run_times"].append(prog["delta_run_time_ns"])
                    program_stats[prog_id]["run_counts"].append(prog["run_cnt"])
                    program_stats[prog_id]["avg_times_per_run"].append(prog["avg_time_per_run_ns"])

            # Generate summary for each program
            summary = {"metadata": monitoring_data["metadata"], "program_summaries": {}}

            for prog_id, stats in program_stats.items():
                if stats["delta_run_times"]:
                    final_delta = stats["delta_run_times"][-1]
                    final_run_count = stats["run_counts"][-1]

                    # Calculate rate of CPU time consumption
                    duration = monitoring_data["metadata"]["end_time"] - monitoring_data["metadata"]["start_time"]
                    cpu_time_rate_ns_per_sec = final_delta / duration if duration > 0 else 0

                    summary["program_summaries"][prog_id] = {
                        "name": stats["name"],
                        "type": stats["type"],
                        "total_cpu_time_ns": final_delta,
                        "total_run_count": final_run_count,
                        "avg_time_per_run_ns": final_delta / final_run_count if final_run_count > 0 else 0,
                        "cpu_time_rate_ns_per_sec": cpu_time_rate_ns_per_sec,
                        "cpu_utilization_percent": (cpu_time_rate_ns_per_sec / 1_000_000_000)
                        * 100,  # Convert to percentage
                    }

            with open(summary_file, "w") as f:
                json.dump(summary, f, indent=2)

            logger.info(f"eBPF summary statistics saved to {summary_file}")

        except Exception as e:
            logger.error(f"Failed to save eBPF summary statistics: {e}")

    def get_summary_stats(self) -> Dict[str, Any]:
        """Get current summary statistics."""
        if not self.ebpf_data:
            return {}

        # Calculate basic statistics from collected data
        total_samples = len(self.ebpf_data)
        duration = time.time() - self.start_time if self.start_time else 0

        # Get latest program statistics
        latest_programs = {}
        if self.ebpf_data:
            latest_sample = self.ebpf_data[-1]
            for prog in latest_sample["programs"]:
                latest_programs[prog["id"]] = {
                    "name": prog["name"],
                    "type": prog["type"],
                    "total_cpu_time_ns": prog["delta_run_time_ns"],
                    "total_runs": prog["run_cnt"],
                    "avg_time_per_run_ns": prog["avg_time_per_run_ns"],
                }

        return {
            "duration_seconds": duration,
            "total_samples": total_samples,
            "sample_interval": self.sample_interval,
            "programs": latest_programs,
        }


# Global eBPF monitor instance
_ebpf_monitor: Optional[eBPFMonitor] = None


def start_ebpf_monitoring(sample_interval: float = 1.0, output_dir: Path = None):
    """
    Start global eBPF monitoring for ABD programs.

    Args:
        sample_interval: Sampling interval in seconds
        output_dir: Directory to save monitoring data
    """
    global _ebpf_monitor

    if _ebpf_monitor is not None:
        logger.warning("eBPF monitoring is already running")
        return

    try:
        _ebpf_monitor = eBPFMonitor(sample_interval, output_dir)
        _ebpf_monitor.start_monitoring()
        logger.info("Global eBPF monitoring started")
    except Exception as e:
        logger.error(f"Failed to start eBPF monitoring: {e}")
        _ebpf_monitor = None


def stop_ebpf_monitoring():
    """Stop global eBPF monitoring and save data."""
    global _ebpf_monitor

    if _ebpf_monitor is None:
        logger.warning("eBPF monitoring is not running")
        return

    try:
        _ebpf_monitor.stop_monitoring()
        logger.info("Global eBPF monitoring stopped")
    except Exception as e:
        logger.error(f"Failed to stop eBPF monitoring: {e}")
    finally:
        _ebpf_monitor = None


def get_ebpf_monitor_stats() -> Dict[str, Any]:
    """Get current eBPF monitoring statistics."""
    global _ebpf_monitor

    if _ebpf_monitor is None:
        return {}

    return _ebpf_monitor.get_summary_stats()
