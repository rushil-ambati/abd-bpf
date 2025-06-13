#!/usr/bin/env python3
"""
ABD Cluster Orchestrator Script (Python)

This script automates the setup, configuration, and orchestration of an ABD
cluster for both eBPF and userspace modes. It handles network namespace setup,
veth pairs, configuration file generation, node launching, and test/benchmark
execution.

Usage:
    python3 scripts/run.py [-n NUM_NODES] [-d] [-w] [-u] [test|bench [latency|throughput]]

Options:
    -n NUM_NODES   Number of replica nodes (default: 3)
    -d             Use debug build
    -w             Wait for background services after client finishes
    -u             Use userspace implementation instead of eBPF
    test           Run the test scenario (default)
    bench          Run the benchmark (latency or throughput)

Environment Variables for Benchmarks:
    Environment variables with the ABD_BENCH_ prefix are converted to CLI arguments, e.g.
        ABD_BENCH_ITERATIONS=1000       → --iterations 1000

    This allows flexible configuration without modifying the script.

This script requires sudo privileges for network namespace operations.
"""
import atexit
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import List

# Import monitoring capabilities
try:
    from monitoring import start_cpu_monitoring, stop_cpu_monitoring, start_ebpf_monitoring, stop_ebpf_monitoring

    CPU_MONITORING_AVAILABLE = True
    EBPF_MONITORING_AVAILABLE = True
except ImportError as e:
    CPU_MONITORING_AVAILABLE = False
    EBPF_MONITORING_AVAILABLE = False
    print(f"Warning: Monitoring not available. Install psutil for monitoring support: {e}")

# --- Constants ---
ROOT = Path(__file__).resolve().parent.parent
LOGS = ROOT / "logs"
CONFIG_FILE = ROOT / "cluster_config.json"
TESTENV = ["sudo", "-n", str(ROOT / "scripts/testenv/testenv.sh")]

# --- Globals ---
bg_procs: List[subprocess.Popen] = []


def run_bg(name: str, *cmd: str) -> subprocess.Popen:
    """Run a background command and log output to a file."""
    logfile = LOGS / f"{name}.log"
    with open(logfile, "w", encoding="utf-8") as f:
        # pylint: disable=subprocess-popen-preexec-fn
        proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, preexec_fn=os.setpgrp)
    bg_procs.append(proc)
    return proc


def cleanup(*_):
    """Terminate all background processes on exit or signal."""
    # Stop CPU monitoring if it's running
    if CPU_MONITORING_AVAILABLE:
        try:
            stop_cpu_monitoring()
        except Exception as e:
            print(f"  Warning: could not stop CPU monitoring: {e}")

    # Stop eBPF monitoring if it's running
    if EBPF_MONITORING_AVAILABLE:
        try:
            stop_ebpf_monitoring()
        except Exception as e:
            print(f"  Warning: could not stop eBPF monitoring: {e}")

    if not bg_procs:
        return
    for proc in bg_procs:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError as e:
            print(f"  Warning: could not SIGTERM process {proc.pid}: {e}")
    # Wait for graceful exit
    for proc in bg_procs:
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                print(f"  Escalating to SIGKILL for process group {os.getpgid(proc.pid)} (pid {proc.pid})")
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError as e:
                print(f"  Warning: could not SIGKILL process {proc.pid}: {e}")
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
    bg_procs.clear()
    # Restore default signal handlers to avoid double cleanup
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


# Register cleanup for normal exit and signals
atexit.register(cleanup)
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


def parse_args():
    """Parse command-line arguments, supporting environment variables as fallback."""
    parser = argparse.ArgumentParser(description="ABD cluster orchestrator")
    parser.add_argument(
        "-n",
        "--num-nodes",
        type=int,
        default=3,
        dest="num_nodes",
        help="Number of replica nodes (default: 3)",
    )
    parser.add_argument("-d", action="store_true", dest="debug", help="Use debug build")
    parser.add_argument(
        "-w",
        "--wait",
        action="store_true",
        dest="wait",
        help="Wait for background services after client finishes",
    )
    parser.add_argument(
        "-u",
        "--userspace",
        action="store_true",
        dest="userspace",
        help="Use userspace implementation instead of eBPF",
    )
    parser.add_argument(
        "subcommand",
        nargs="?",
        choices=["test", "bench"],
        help="Subcommand: test or bench",
    )
    parser.add_argument(
        "bench_mode",
        nargs="?",
        default="latency",
        help="Bench mode: latency or throughput (for bench subcommand)",
    )
    return parser.parse_args()


def sudo_check():
    """Ensure the script has sudo privileges."""
    try:
        subprocess.run(["sudo", "-v"], check=True)
    except subprocess.CalledProcessError:
        print("need sudo", file=sys.stderr)
        sys.exit(1)


def build_targets(debug: bool) -> Path:
    """Build the Rust targets in debug or release mode."""
    target_dir = ROOT / ("target/debug" if debug else "target/release")
    build_cmd = ["cargo", "build"]
    if not debug:
        build_cmd.append("--release")
    subprocess.run(build_cmd, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    return target_dir


def setup_netns(num_nodes: int, userspace: bool, target_dir: Path):
    """Set up network namespaces and veth pairs for each node."""
    for i in range(1, num_nodes + 1):
        env = f"node{i}"
        # Check if netns already exists
        try:
            ns_list = subprocess.check_output(["sudo", "ip", "netns", "list"]).decode()
        except subprocess.CalledProcessError:
            ns_list = ""
        if env not in ns_list:
            subprocess.run(
                TESTENV + ["setup", "--name", env, "--legacy-ip"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
        subprocess.run(
            TESTENV
            + [
                "exec",
                "-n",
                env,
                "--",
                "bash",
                "-c",
                "ethtool -K veth0 tx-checksum-ip-generic off || true",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        if not userspace:
            run_bg(
                f"xdp_pass_{env}",
                *TESTENV,
                "exec",
                "-n",
                env,
                "--",
                "bash",
                "-c",
                f"RUST_LOG=off {target_dir}/xdp-pass --iface veth0",
            )


def get_node_info(i: int) -> dict:
    """Get network and interface info for a node."""
    iface = f"node{i}"
    link_json = subprocess.check_output(["ip", "-json", "link", "show", "dev", iface]).decode()
    ifindex = json.loads(link_json)[0]["ifindex"]
    ip_json = subprocess.check_output(["ip", "-4", "-json", "addr", "show", "dev", iface]).decode()
    ip = json.loads(ip_json)[0]["addr_info"][0]["local"]
    mac = (
        subprocess.check_output(
            [
                "sudo",
                "ip",
                "netns",
                "exec",
                iface,
                "cat",
                "/sys/class/net/veth0/address",
            ]
        )
        .decode()
        .strip()
    )
    return {
        "node_id": i,
        "ipv4": ip,
        "mac": mac,
        "ifindex": ifindex,
        "interface": iface,
    }


def generate_config(num_nodes: int, userspace: bool):
    """Generate the cluster configuration JSON file."""
    nodes = [get_node_info(i) for i in range(1, num_nodes + 1)]
    mode = "userspace" if userspace else "ebpf"
    config = {"num_nodes": num_nodes, "nodes": nodes, "mode": mode}
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def launch_nodes(num_nodes: int, userspace: bool, target_dir: Path):
    """Launch ABD nodes in the background."""
    for i in range(1, num_nodes + 1):
        exe = "abd-userspace" if userspace else "abd-ebpf"
        run_bg(
            f"node{i}",
            "sudo",
            "-E",
            "bash",
            "-c",
            f"RUST_LOG=info {target_dir}/{exe} --node-id {i} --config {CONFIG_FILE}",
        )


def run_test(num_nodes: int, userspace: bool, target_dir: Path):
    """Run the test scenario: write and read from all nodes."""
    value_base = (
        "int=88 text=world ip=2001:0db8:85a3:0000:0000:8a2e:0370:7334 "
        "duration=3600 point=(-0.3,4.1) person=(Alice,30)"
    )
    with open(CONFIG_FILE, encoding="utf-8") as f:
        config = json.load(f)
    for i in range(1, num_nodes + 1):
        env = f"node{i}"
        node_ip = next(n["ipv4"] for n in config["nodes"] if n["node_id"] == i)
        val = f"{value_base} hashmap={{author:node{i};version:1.0;license:MIT}}"
        if not userspace:
            subprocess.run(
                TESTENV
                + [
                    "exec",
                    "-n",
                    env,
                    "--",
                    "bash",
                    "-c",
                    f"RUST_LOG=info {target_dir}/client write {node_ip} '{val}'",
                ],
                check=True,
            )
        else:
            subprocess.run(
                [
                    "bash",
                    "-c",
                    f"RUST_LOG=info {target_dir}/client write {node_ip} '{val}'",
                ],
                check=True,
            )
        print()
        for j in range(1, num_nodes + 1):
            read_ip = next(n["ipv4"] for n in config["nodes"] if n["node_id"] == j)
            if not userspace:
                subprocess.run(
                    TESTENV
                    + [
                        "exec",
                        "-n",
                        f"node{j}",
                        "--",
                        "bash",
                        "-c",
                        f"RUST_LOG=info {target_dir}/client read {read_ip}",
                    ],
                    check=True,
                )
            else:
                subprocess.run(
                    ["bash", "-c", f"RUST_LOG=info {target_dir}/client read {read_ip}"],
                    check=True,
                )
            print()


def env_to_cli_args(prefix: str = "ABD_BENCH_") -> List[str]:
    """
    Convert environment variables to CLI arguments.

    Environment variables with the given prefix are converted to CLI arguments:
    - ABD_BENCH_CONFIG=file.json → --config file.json
    - ABD_BENCH_ITERATIONS=1000 → --iterations 1000
    - ABD_BENCH_THREADS_PER_NODE=4 → --threads-per-node 4

    Args:
        prefix: Environment variable prefix to look for

    Returns:
        List of CLI arguments
    """
    args = []
    for key, value in os.environ.items():
        if key.startswith(prefix):
            # Remove prefix and convert to kebab-case
            arg_name = key[len(prefix) :].lower().replace("_", "-")
            args.extend([f"--{arg_name}", value])
    return args


def run_bench(bench_mode: str, target_dir: Path):
    """Run the benchmark in the specified mode (latency or throughput)."""
    bench_log = LOGS / f"bench_{bench_mode}.log"

    # Build benchmark command with environment-based arguments
    env_args = env_to_cli_args("ABD_BENCH_")

    # Base command
    bench_cmd_parts = ["RUST_LOG=info", str(target_dir / "bench"), bench_mode, "--config", str(CONFIG_FILE)]

    # Add environment-based arguments
    bench_cmd_parts.extend(env_args)

    bench_cmd = " ".join(bench_cmd_parts)

    with open(bench_log, "w", encoding="utf-8") as f:
        proc = subprocess.Popen(
            [
                "sudo",
                "-E",
                "bash",
                "-c",
                bench_cmd,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        if proc.stdout is not None:
            for line in proc.stdout:
                sys.stdout.buffer.write(line)
                f.buffer.write(line)
        proc.wait()
    print()


def main():
    """Main entry point for the orchestrator script."""
    args = parse_args()
    sudo_check()
    LOGS.mkdir(exist_ok=True)
    for f in LOGS.glob("*"):
        f.unlink()
    target_dir = build_targets(args.debug)
    setup_netns(args.num_nodes, args.userspace, target_dir)
    generate_config(args.num_nodes, args.userspace)

    # Start CPU monitoring for userspace mode
    if CPU_MONITORING_AVAILABLE:
        print("Starting CPU utilization monitoring for userspace mode...")
        try:
            start_cpu_monitoring(sample_interval=0.1, output_dir=LOGS)
            print("CPU monitoring active")
        except Exception as e:
            print(f"Warning: Could not start CPU monitoring: {e}")
    elif args.userspace and not CPU_MONITORING_AVAILABLE:
        print("Warning: CPU monitoring not available. Install psutil for monitoring support.")

    # Start eBPF monitoring for eBPF mode
    if not args.userspace and EBPF_MONITORING_AVAILABLE:
        print("Starting eBPF program utilization monitoring for eBPF mode...")
        try:
            start_ebpf_monitoring(sample_interval=1.0, output_dir=LOGS)
            print("eBPF monitoring active")
        except Exception as e:
            print(f"Warning: Could not start eBPF monitoring: {e}")
    elif not args.userspace and not EBPF_MONITORING_AVAILABLE:
        print("Warning: eBPF monitoring not available.")

    launch_nodes(args.num_nodes, args.userspace, target_dir)
    time.sleep(1)
    print()
    # Only run test or bench if explicitly requested
    if args.subcommand == "test":
        run_test(args.num_nodes, args.userspace, target_dir)
    elif args.subcommand == "bench":
        run_bench(args.bench_mode, target_dir)
    # Default: just spin up and wait (unless -w is not set)
    if args.wait or (args.subcommand not in ("test", "bench")):
        for proc in bg_procs:
            try:
                proc.wait()
            except subprocess.TimeoutExpired:
                pass


if __name__ == "__main__":
    main()
