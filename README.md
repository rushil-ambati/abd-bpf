# abdBPF

An implementation of the Attiya, Bar-Noy, Dolev (ABD) distributed algorithm utilising the [eBPF](https://ebpf.io/) technology with the [Aya](https://aya-rs.dev/) framework to fully offload all logic to kernel space.

## Project Structure

```shell
abdBPF/
├── abd/                    # Userspace loaders
├── abd-common/             # Common data types, structs, and constants
├── abd-ebpf/               # eBPF programs implementing ABD logic
├── client/                 # CLI for interacting with ABD nodes
├── tools/                  # Testing utilities and environment setup scripts
├── scripts/                # Helper scripts
```

## Getting Started

### Prerequisites

Ensure you have the following dependencies installed:

* **Rust toolchains**:

  ```shell
  rustup toolchain install stable
  rustup toolchain install nightly --component rust-src
  ```

* **bpf-linker**:

  ```shell
  cargo install bpf-linker
  ```

* **Cross-compiling dependencies** *(Optional, macOS example)*:

  ```shell
  brew install llvm
  brew install filosottile/musl-cross/musl-cross
  rustup target add x86_64-unknown-linux-musl
  ```

### Build and Run

Build the project using Cargo:

```shell
cargo build --release
```

Run using the provided script:

```shell
scripts/run [-s NUM_NODES] [-d] [-w]
```

* `-s`: Number of replica nodes (default: 3)
* `-d`: Debug build (optional)
* `-w`: Wait for services after client operations (optional)

Example:

```shell
scripts/run -s 5
```

### Cleanup

To clean up the environment, run:

```shell
scripts/cleanup [-a]
```

* `-a`: Also teardown all test environments

## ABD Algorithm Summary

The ABD algorithm provides distributed fault tolerance via replicated storage. Nodes maintain a local value and a numerical "tag" (which acts as a virtual timestamp) to resolve conflicts and order updates. Additionally, counters are used throughout to distinguish messages relating to a particular request.

* **Writer**:

  * Increment tag and broadcast `(value, tag)` to servers
  * Wait for acknowledgment from a majority

* **Reader**:

  * Phase 1: Query servers for their `(value, tag)` pairs
  * Choose the maximum tag and its associated value
  * Phase 2: Propagate the chosen `(value, tag)` to servers
  * Wait for acknowledgments from a majority

* **Server**:

  * Respond to reads with local `(value, tag)`
  * Update local `(value, tag)` if an incoming write has a higher tag

Detailed explanation: [ABD Algorithm](https://cs.neea.dev/distributed/abd/)
