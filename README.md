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
* **Asynchronous Verification & I/O Offloading:** Cryptographic work and disk I/O are completely removed from the database's critical write path. A concurrent, lock-free multi-producer queue batches MAC computations to an asynchronous background auditor thread, preventing serialization bottlenecks during high-frequency transaction commits.

## Performance and Benchmarks

LETHAL includes a custom multi-threaded microbenchmark suite built with Google Benchmark (`SimulatedTPCCTransaction`) to mimic industry-standard OLTP workloads. 

We have implemented three baselines to compare against. These are all in the `src/log` folder.
* Unsecured WAL (`unsecured_wal.cc`)
* Synchronous Hash Chain (`sync_hashchain.cc`)
* Merkle Tree Blockchain (`merkle_blockchain.cc`) 

The LETHAL manager is in `src/log/lethal.cc`.

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
```

To build and run the tests, use
```bash
cd build
make log_benchmark -j4
./log_benchmark
```

To test baselines, copy paste appropriate code into `log_manager.cc`.
