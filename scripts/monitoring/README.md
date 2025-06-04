# ABD Protocol Monitoring Package

This package provides comprehensive monitoring capabilities for evaluating the performance of ABD protocol implementations in both userspace and eBPF modes.

## Overview

The monitoring package consists of four main modules:

- **`cpu_monitor.py`**: System-wide CPU and memory monitoring for userspace implementations
- **`ebpf_monitor.py`**: eBPF program runtime monitoring using bpftool
- **`analyze_cpu.py`**: Analysis and visualization tools for CPU monitoring data
- **`analyze_ebpf.py`**: Analysis and visualization tools for eBPF monitoring data

## Usage

### CPU Monitoring (Userspace Mode)

```python
from monitoring import start_cpu_monitoring, stop_cpu_monitoring

# Start monitoring with 0.1s sampling interval
start_cpu_monitoring(sample_interval=0.1, output_dir=Path("logs"))

# Your benchmark/test code here...

# Stop monitoring and save data
stop_cpu_monitoring()
```

### eBPF Monitoring (eBPF Mode)

```python
from monitoring import start_ebpf_monitoring, stop_ebpf_monitoring

# Start monitoring with 1.0s sampling interval
start_ebpf_monitoring(sample_interval=1.0, output_dir=Path("logs"))

# Your benchmark/test code here...

# Stop monitoring and save data
stop_ebpf_monitoring()
```

## Data Collection

### CPU Monitoring Data

- System-wide CPU utilization (per-core and aggregate)
- Memory usage (RSS, VMS, percentage)
- Process-specific metrics for ABD-related processes
- 0.1s sampling interval for high-resolution data

### eBPF Monitoring Data

- Program runtime metrics (`run_time_ns`) from bpftool
- Delta calculations from baseline measurements
- Specific tracking of `abd_tc` and `abd_xdp` programs
- 1.0s sampling interval for program statistics

## Output Files

Both monitors save data in JSON format with metadata and timestamped samples:

- `cpu_monitoring_<timestamp>.json` - CPU monitoring data
- `cpu_summary_<timestamp>.json` - CPU monitoring summary
- `ebpf_monitoring_<timestamp>.json` - eBPF monitoring data
- `ebpf_summary_<timestamp>.json` - eBPF monitoring summary

## Analysis Tools

### CPU Analysis

```bash
python3 scripts/monitoring/analyze_cpu.py logs/cpu_monitoring_*.json
```

### eBPF Analysis

```bash
python3 scripts/monitoring/analyze_ebpf.py logs/ebpf_monitoring_*.json
```

Both analysis tools generate:

- Statistical summaries
- Visualization plots (PNG/PDF/SVG)
- Markdown reports
- Performance recommendations

## Integration

The monitoring package is automatically integrated into:

- `run.py` - Starts appropriate monitoring based on mode (`-u` for userspace)
- `benchmark_runner.py` - Manages monitoring during benchmark execution
- Evaluation pipeline - Includes monitoring data in performance analysis

## Dependencies

- **psutil** >= 5.8.0 for CPU monitoring
- **pandas**, **matplotlib**, **seaborn** for analysis (optional)
- **bpftool** system utility for eBPF monitoring
