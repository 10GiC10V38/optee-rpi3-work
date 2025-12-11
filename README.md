# SHA-256 Secure Benchmark on OP-TEE (ARM TrustZone)

![Platform](https://img.shields.io/badge/Platform-ARMv8%20%7C%20RPi3-blue)
![Environment](https://img.shields.io/badge/Environment-OP--TEE-green)
![Language](https://img.shields.io/badge/Language-C%20%7C%20Assembly-orange)

A high-performance implementation of the SHA-256 Secure Hash Algorithm running inside a **Trusted Execution Environment (TEE)** using OP-TEE. 

This project goes beyond standard implementation by designing a **custom benchmarking framework** to measure the exact "Cost of Security"—isolating World Switching latency, memory copying overhead, and pure algorithmic execution time using cycle-accurate hardware counters.

## 🚀 Key Features

* **Trusted Application (TA):** Securely computes SHA-256 hashes isolated from the Rich OS (Linux).
* **Dual-Mode Processing:**
    * **Single-Shot:** Low latency for small payloads (< 4MB).
    * **Chunked Streaming:** Efficient memory management for large files (Tested up to 52MB+).
* **Precision Timing:** Uses inline ARM64 assembly (`cntpct_el0`) to capture nanosecond-precision timing inside the Secure World.
* **Performance Metrics:** Automatically calculates Total TEE Time, Pure Algo Time, and System Overhead per operation.

## 📊 Performance Analysis

Benchmarks conducted on a **Raspberry Pi 3 (ARM Cortex-A53)**.

| Metric | Measured Value | Description |
| :--- | :--- | :--- |
| **Throughput (Secure)** | ~11 MB/s | Speed of hashing inside TEE |
| **System Latency** | ~131 µs | Fixed cost of World Switch (EL0 $\to$ S-EL0) |
| **Base Algo Cost** | ~66.8 µs | SHA-256 Initialization & Padding cost |
| **Internal Overhead** | ~1.6 µs | Cost of custom TA wrapper logic |

### The "Cost of Security"
Compared to native Linux `sha256sum`, the Secure World implementation incurs a **1.4x performance penalty** (38% overhead). This overhead is primarily due to memory copying between Normal World and Secure World, proving the system is efficient enough for real-time verification tasks.

## 🛠️ Technical Challenges & Solutions

### The `0xdeadbeef` Panic (Privilege Escalation)
**Problem:** Attempting to read the Performance Monitor Cycle Counter (`pmccntr_el0`) from the Trusted Application (running in User Mode / S-EL0) caused a secure panic (`0xdeadbeef`).

**Root Cause:** ARMv8 architecture disables User Mode access to PMU registers by default for security.

**Solution:** Modified the TEE Core (Kernel level) initialization to explicitly enable User Mode access by writing to the `PMUSERENR_EL0` register via inline assembly.

```c
/* Enable User-Mode Access to PMU */
static void enable_el0_counters(void) {
    uint64_t val;
    // Unlock Cycle Counter
    val = (1 << 0) | (1 << 2); 
    __asm__ volatile("msr pmuserenr_el0, %0" :: "r" (val));
}
