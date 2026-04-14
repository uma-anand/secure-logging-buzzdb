# LETHAL: Low-latency Tamper-Evident Hybrid Audit Logging

A low-latency, tamper-evident secure logging system designed for ARIES-based relational databases. Developed for CS6423 at the Georgia Institute of Technology.

## Project Overview
Modern relational databases rely on the ARIES protocol and Write-Ahead Logging (WAL) to guarantee ACID transactions. However, standard ARIES assumes the underlying storage medium is trusted and tamper-proof—an assumption that frequently fails in decoupled cloud environments. An attacker with file-system access could silently modify, delete, or reorder log records to forge database state, effectively turning the database's own recovery mechanism into an attack vector.

**LETHAL** mitigates this by making the logging layer tamper-proof. It balances security with latency by avoiding the heavy bottlenecks of traditional linear hash chains or Merkle trees. Instead, it utilizes hardware-accelerated, LSN-bound authentication to protect the critical write path.

## Key Features

* **LSN-bound Authentication:** Every log record (`BEGIN`, `UPDATE`, `COMMIT`, `ABORT`, `CHECKPOINT`) is authenticated using AES-256-GCM. The Message Authentication Code (MAC) is bound to the data, the previous hash, and the Log Sequence Number (LSN) to strictly prevent record reordering, modification, and deletion.
  
  $$H_{i} = \text{MAC}(\text{Data}_{i} \parallel H_{i-1} \parallel \text{LSN}_{i})$$

* **Hardware-Accelerated Cryptography:** Leverages OpenSSL's `EVP` API to tap directly into AES-NI hardware instructions, significantly reducing CPU cycles compared to software-based hashing.
* **Checkpoint Piggybacking:** Anchors the hash chain to ARIES fuzzy checkpoints by appending the master MAC directly to the checkpoint record, bypassing the need for additional costly `fsync` operations.
* **Tamper-Evident Recovery Phase:** The database recovery sequence dynamically recomputes and verifies the AES-GMAC signature for every log record, halting and throwing a runtime error immediately upon detecting compromised state.
* **Multithreaded Buffering:** Includes full threading support and buffer management to scale concurrent transactions.

## Performance and Benchmarks

LETHAL includes a custom multi-threaded microbenchmark suite built with Google Benchmark (`SimulatedTPCCTransaction`) to mimic industry-standard OLTP workloads. 

Initial performance evaluations scaling from 1 to 16 threads demonstrate that while cryptographic operations introduce some short-term synchronization contention, they do not fundamentally limit scalability. At high concurrency (16 threads), the secured prototype achieves an average throughput of ~341 items/s, successfully amortizing the cryptographic overhead.

*Note: Future updates will include a transition to a fully asynchronous background auditor thread to further remove MAC computation from the critical write path.*

## Tech Stack

* **Language:** C++
* **Cryptography:** OpenSSL (`EVP_aes_256_gcm`)
* **Benchmarking:** Google Benchmark
* **Build System:** CMake

## Getting Started

### Prerequisites
Ensure you have the following installed on your system:
* `g++` (or any C++17 compatible compiler)
* `cmake` (v3.10+)
* `openssl` (libssl-dev)
Or use the dev container provided with Docker.

### Build Instructions
Clone the repository and build the project using CMake:

```bash
git clone [https://github.com/uma-anand/secure-logging-buzzdb.git](https://github.com/uma-anand/secure-logging-buzzdb.git)
cd secure-logging-buzzdb
mkdir build && cd build
cmake ..
make
