# ABD BPF

Implementation of the ABD algorithm using eBPF.

## Setup

[Install dependencies](setup_dependencies.org)

Compile the project.

```bash
./configure
make
```

For convenience, alias `testenv` tool.

```bash
echo "alias testenv=sudo $(pwd)/tools/testenv/testenv.sh" >> ~/.bashrc
```

Create a test environment named `abd`.

```bash
testenv setup --name abd
```

## Usage

Load the server program into the test environment.

```bash
cd server
testenv load -n abd -- --pin-path /sys/fs/bpf/abd --prog-name xdp_abd_server xdp_prog_kern.o
```

Attach a dummy XDP program to the peer device of the test environment.
See [here](https://github.com/xdp-project/xdp-tutorial/tree/main/packet03-redirecting#sending-packets-back-to-the-interface-they-came-from) for why this is necessary.

```bash
testenv exec -n abd -- ./xdp-loader load --prog-name xdp_pass_func veth0 xdp_prog_kern.o
```

Verify that the server program is loaded.

```bash
testenv exec -n abd -- ./xdp-loader status
# ...
# veth0                  xdp_dispatcher    native   635  4d7e87c0d30db711
```

View the XDP statistics.

```bash
testenv stats -n abd
```

Open a new terminal and use the client to send requests inside the test environment.

```bash
cd client
testenv exec -n abd -- ./abd_client fc00:dead:cafe:1::1 write 1 42 1
# Sent WRITE request to fc00:dead:cafe:1::1
# Received WRITE_ACK response from fc00:dead:cafe:1::1

testenv exec -n abd -- ./abd_client fc00:dead:cafe:1::1 read 1
# Sent READ request to fc00:dead:cafe:1::1
# Received READ_ACK response from fc00:dead:cafe:1::1: value=42
```

There should be debug output at `trace_pipe`

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
# <...>-76445   [002] ..s2. 59058.221717: bpf_trace_printk: ABD message: type=0, tag=1, value=42, counter=1
# <...>-76641   [003] ..s2. 59072.511563: bpf_trace_printk: ABD message: type=2, tag=0, value=0, counter=1
```
