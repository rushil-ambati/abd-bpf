"""
CPU Utilization Monitoring Module for ABD Protocol Evaluation

This module provides comprehensive CPU utilization monitoring specifically
designed for userspace ABD protocol implementations. It tracks both system-wide
and process-specific CPU metrics with high temporal resolution.

Author: ABD Protocol Research Team
"""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger(__name__)


class CPUMonitor:
    """
    Monitors CPU utilization for ABD protocol processes and system-wide metrics.

    This class provides detailed CPU monitoring capabilities including:
    - System-wide CPU utilization
    - Per-process CPU usage for ABD nodes
    - Per-core CPU utilization
    - Memory usage correlation
    - High-resolution sampling with configurable intervals
    """

    def __init__(self, sample_interval: float = 0.1, output_dir: Path = None):
        """
        Initialize CPU monitor.

        Args:
            sample_interval: Sampling interval in seconds (default: 0.1s for 10Hz)
            output_dir: Directory to save monitoring data (default: logs/)
        """
        if psutil is None:
            raise ImportError("psutil is required for CPU monitoring. Install with: pip install psutil")

        self.sample_interval = sample_interval
        self.output_dir = output_dir or Path("logs")
        self.output_dir.mkdir(exist_ok=True)

        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        self.start_time = None

        # Data storage
        self.system_data = []
        self.process_data = []
        self.core_data = []

        # Process tracking
        self.tracked_processes = {}  # pid -> process_info
        self.process_patterns = ["abd-userspace", "bench", "client"]

        logger.info(f"CPU Monitor initialized with {sample_interval}s sampling interval")

    def start_monitoring(self):
        """Start CPU monitoring in a background thread."""
        if self.is_monitoring:
            logger.warning("CPU monitoring is already running")
            return

        self.is_monitoring = True
        self.start_time = time.time()

        # Clear previous data
        self.system_data.clear()
        self.process_data.clear()
        self.core_data.clear()
        self.tracked_processes.clear()

        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

        logger.info("CPU monitoring started")

    def stop_monitoring(self):
        """Stop CPU monitoring and save data."""
        if not self.is_monitoring:
            logger.warning("CPU monitoring is not running")
            return

        self.is_monitoring = False

        # Wait for monitoring thread to finish
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)

        # Save monitoring data
        self._save_data()

        logger.info("CPU monitoring stopped and data saved")

    def _monitor_loop(self):
        """Main monitoring loop running in background thread."""
        logger.info("CPU monitoring loop started")

        while self.is_monitoring:
            try:
                timestamp = time.time()
                relative_time = timestamp - self.start_time

                # Collect system-wide metrics
                self._collect_system_metrics(timestamp, relative_time)

                # Collect per-core metrics
                self._collect_core_metrics(timestamp, relative_time)

                # Collect process-specific metrics
                self._collect_process_metrics(timestamp, relative_time)

                # Sleep until next sample
                time.sleep(self.sample_interval)

            except Exception as e:
                logger.error(f"Error in CPU monitoring loop: {e}")
                time.sleep(self.sample_interval)

    def _collect_system_metrics(self, timestamp: float, relative_time: float):
        """Collect system-wide CPU and memory metrics."""
        try:
            # CPU utilization
            cpu_percent = psutil.cpu_percent(interval=None)

            # Memory information
            memory = psutil.virtual_memory()

            # Load average (Linux/Unix)
            try:
                load_avg = psutil.getloadavg()
            except AttributeError:
                load_avg = [0.0, 0.0, 0.0]  # Windows doesn't have load average

            # Context switches and interrupts
            cpu_stats = psutil.cpu_stats()

            system_record = {
                "timestamp": timestamp,
                "relative_time": relative_time,
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024**3),
                "memory_used_gb": memory.used / (1024**3),
                "memory_total_gb": memory.total / (1024**3),
                "load_avg_1m": load_avg[0],
                "load_avg_5m": load_avg[1],
                "load_avg_15m": load_avg[2],
                "ctx_switches": cpu_stats.ctx_switches,
                "interrupts": cpu_stats.interrupts,
                "soft_interrupts": cpu_stats.soft_interrupts,
            }

            self.system_data.append(system_record)

        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")

    def _collect_core_metrics(self, timestamp: float, relative_time: float):
        """Collect per-core CPU utilization metrics."""
        try:
            # Per-core CPU utilization
            cpu_percents = psutil.cpu_percent(interval=None, percpu=True)

            core_record = {"timestamp": timestamp, "relative_time": relative_time, "cores": {}}

            for i, cpu_percent in enumerate(cpu_percents):
                core_record["cores"][f"core_{i}"] = cpu_percent

            self.core_data.append(core_record)

        except Exception as e:
            logger.error(f"Error collecting core metrics: {e}")

    def _collect_process_metrics(self, timestamp: float, relative_time: float):
        """Collect metrics for ABD-related processes."""
        try:
            # Update tracked processes
            self._update_tracked_processes()

            # Collect metrics for each tracked process
            for pid, proc_info in self.tracked_processes.items():
                try:
                    process = proc_info["process"]

                    # Skip if process is no longer running
                    if not process.is_running():
                        continue

                    # CPU and memory usage
                    cpu_percent = process.cpu_percent()
                    memory_info = process.memory_info()

                    # I/O statistics (if available)
                    try:
                        io_counters = process.io_counters()
                        read_bytes = io_counters.read_bytes
                        write_bytes = io_counters.write_bytes
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        read_bytes = write_bytes = 0

                    # Number of file descriptors
                    try:
                        num_fds = process.num_fds()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                        num_fds = 0

                    # Number of threads
                    try:
                        num_threads = process.num_threads()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        num_threads = 0

                    process_record = {
                        "timestamp": timestamp,
                        "relative_time": relative_time,
                        "pid": pid,
                        "name": proc_info["name"],
                        "cmdline": proc_info["cmdline"],
                        "cpu_percent": cpu_percent,
                        "memory_rss_mb": memory_info.rss / (1024**2),
                        "memory_vms_mb": memory_info.vms / (1024**2),
                        "memory_percent": process.memory_percent(),
                        "io_read_bytes": read_bytes,
                        "io_write_bytes": write_bytes,
                        "num_fds": num_fds,
                        "num_threads": num_threads,
                    }

                    self.process_data.append(process_record)

                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.debug(f"Process {pid} no longer accessible: {e}")
                    continue

        except Exception as e:
            logger.error(f"Error collecting process metrics: {e}")

    def _update_tracked_processes(self):
        """Update the list of tracked ABD-related processes."""
        try:
            # Remove dead processes
            dead_pids = []
            for pid, proc_info in self.tracked_processes.items():
                if not proc_info["process"].is_running():
                    dead_pids.append(pid)

            for pid in dead_pids:
                del self.tracked_processes[pid]

            # Find new processes
            for process in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    pid = process.info["pid"]
                    name = process.info["name"]
                    cmdline = process.info["cmdline"]

                    if pid in self.tracked_processes:
                        continue

                    # Check if this is an ABD-related process
                    if self._is_abd_process(name, cmdline):
                        self.tracked_processes[pid] = {
                            "process": process,
                            "name": name,
                            "cmdline": " ".join(cmdline) if cmdline else "",
                        }
                        logger.info(f"Now tracking process: {name} (PID: {pid})")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            logger.error(f"Error updating tracked processes: {e}")

    def _is_abd_process(self, name: str, cmdline: List[str]) -> bool:
        """Check if a process is ABD-related based on name and command line."""
        if not name or not cmdline:
            return False

        # Check process name
        for pattern in self.process_patterns:
            if pattern in name:
                return True

        # Check command line arguments
        cmdline_str = " ".join(cmdline).lower()
        abd_indicators = ["abd-userspace", "bench", "client", "cluster_config.json"]

        for indicator in abd_indicators:
            if indicator in cmdline_str:
                return True

        return False

    def _save_data(self):
        """Save monitoring data to JSON files."""
        try:
            timestamp_str = time.strftime("%Y%m%d_%H%M%S")

            # Save system data
            if self.system_data:
                system_file = self.output_dir / f"cpu_monitor_system_{timestamp_str}.json"
                with open(system_file, "w") as f:
                    json.dump(
                        {
                            "metadata": {
                                "start_time": self.start_time,
                                "sample_interval": self.sample_interval,
                                "total_samples": len(self.system_data),
                                "duration": time.time() - self.start_time,
                            },
                            "data": self.system_data,
                        },
                        f,
                        indent=2,
                    )
                logger.info(f"Saved system CPU data to {system_file}")

            # Save process data
            if self.process_data:
                process_file = self.output_dir / f"cpu_monitor_processes_{timestamp_str}.json"
                with open(process_file, "w") as f:
                    json.dump(
                        {
                            "metadata": {
                                "start_time": self.start_time,
                                "sample_interval": self.sample_interval,
                                "total_samples": len(self.process_data),
                                "duration": time.time() - self.start_time,
                                "tracked_processes": {
                                    pid: {"name": info["name"], "cmdline": info["cmdline"]}
                                    for pid, info in self.tracked_processes.items()
                                },
                            },
                            "data": self.process_data,
                        },
                        f,
                        indent=2,
                    )
                logger.info(f"Saved process CPU data to {process_file}")

            # Save core data
            if self.core_data:
                core_file = self.output_dir / f"cpu_monitor_cores_{timestamp_str}.json"
                with open(core_file, "w") as f:
                    json.dump(
                        {
                            "metadata": {
                                "start_time": self.start_time,
                                "sample_interval": self.sample_interval,
                                "total_samples": len(self.core_data),
                                "duration": time.time() - self.start_time,
                                "num_cores": psutil.cpu_count(),
                            },
                            "data": self.core_data,
                        },
                        f,
                        indent=2,
                    )
                logger.info(f"Saved core CPU data to {core_file}")

        except Exception as e:
            logger.error(f"Error saving CPU monitoring data: {e}")

    def get_summary_stats(self) -> Dict:
        """Get summary statistics of the monitoring session."""
        if not self.system_data:
            return {}

        try:
            # System stats
            cpu_values = [record["cpu_percent"] for record in self.system_data]
            memory_values = [record["memory_percent"] for record in self.system_data]

            # Process stats
            process_cpu_by_name = {}
            for record in self.process_data:
                name = record["name"]
                if name not in process_cpu_by_name:
                    process_cpu_by_name[name] = []
                process_cpu_by_name[name].append(record["cpu_percent"])

            summary = {
                "duration": time.time() - self.start_time if self.start_time else 0,
                "total_samples": len(self.system_data),
                "sample_interval": self.sample_interval,
                "system": {
                    "cpu_avg": sum(cpu_values) / len(cpu_values),
                    "cpu_max": max(cpu_values),
                    "cpu_min": min(cpu_values),
                    "memory_avg": sum(memory_values) / len(memory_values),
                    "memory_max": max(memory_values),
                },
                "processes": {},
            }

            # Add process summaries
            for name, cpu_values in process_cpu_by_name.items():
                if cpu_values:
                    summary["processes"][name] = {
                        "cpu_avg": sum(cpu_values) / len(cpu_values),
                        "cpu_max": max(cpu_values),
                        "samples": len(cpu_values),
                    }

            return summary

        except Exception as e:
            logger.error(f"Error generating summary stats: {e}")
            return {}


# Global CPU monitor instance
_cpu_monitor: Optional[CPUMonitor] = None


def start_cpu_monitoring(sample_interval: float = 0.1, output_dir: Path = None):
    """
    Start global CPU monitoring for userspace ABD processes.

    Args:
        sample_interval: Sampling interval in seconds
        output_dir: Directory to save monitoring data
    """
    global _cpu_monitor

    if _cpu_monitor is not None:
        logger.warning("CPU monitoring is already active")
        return

    try:
        _cpu_monitor = CPUMonitor(sample_interval, output_dir)
        _cpu_monitor.start_monitoring()
        logger.info("Global CPU monitoring started")
    except Exception as e:
        logger.error(f"Failed to start CPU monitoring: {e}")
        _cpu_monitor = None


def stop_cpu_monitoring():
    """Stop global CPU monitoring and save data."""
    global _cpu_monitor

    if _cpu_monitor is None:
        logger.warning("CPU monitoring is not active")
        return

    try:
        summary = _cpu_monitor.get_summary_stats()
        _cpu_monitor.stop_monitoring()

        logger.info("CPU monitoring stopped")
        if summary:
            logger.info(
                f"Monitoring summary: {summary['duration']:.1f}s, "
                f"{summary['total_samples']} samples, "
                f"avg CPU: {summary['system']['cpu_avg']:.1f}%"
            )

        _cpu_monitor = None

    except Exception as e:
        logger.error(f"Error stopping CPU monitoring: {e}")
