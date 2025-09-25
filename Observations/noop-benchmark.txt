calculated the single call from normal world to the secure world.
this is roundtrip time.
and it is calculated only after the initial setup except for the first case.


# optee_example_secure_hash --benchmark-noop
D/TC:? 0 tee_ta_init_pseudo_ta_session:296 Lookup pseudo TA eb0ab446-a63c-4ad5-aada-c665de645221
D/TC:? 0 ldelf_load_ldelf:96 ldelf load address 0x40006000
D/LD:  ldelf:134 Loading TS eb0ab446-a63c-4ad5-aada-c665de645221
D/TC:? 0 ldelf_syscall_open_bin:142 Lookup user TA ELF eb0ab446-a63c-4ad5-aada-c665de645221 (early TA)
D/TC:? 0 ldelf_syscall_open_bin:146 res=0xffff0008
D/TC:? 0 ldelf_syscall_open_bin:142 Lookup user TA ELF eb0ab446-a63c-4ad5-aada-c665de645221 (Secure Storage TA)
D/TC:? 0 ldelf_syscall_open_bin:146 res=0xffff0008
D/TC:? 0 ldelf_syscall_open_bin:142 Lookup user TA ELF eb0ab446-a63c-4ad5-aada-c665de645221 (REE)
D/TC:? 0 ldelf_syscall_open_bin:146 res=0
D/LD:  ldelf:168 ELF (eb0ab446-a63c-4ad5-aada-c665de645221) at 0x40075000
D/TA:  TA_CreateEntryPoint:458 Secure Hash TA: Creating entry point with enhanced monitoring
I/TA: TA initialized with stack base at: 0x400186b0
D/TA:  TA_OpenSessionEntryPoint:491 Secure Hash TA: Opening session with enhanced tracking
I/TA: Secure Hash TA session opened successfully
I/TA: Session context allocated at: 0x400ad5c0
I/TA: Session stack base: 0x400186b0

Running D/TA:  TA_InvokeCommandEntryPoint:558 Command invoked: 7
NOOP Benchmark..D/TA:  TA_InvokeCommandEntryPoint:582 Calling basic functionality
.
-------------D/TA:  benchmark_noop:131 Benchmark NOOP command executed.
----------------D/TC:? 0 tee_ta_close_session:510 csess 0x10189f30 id 1
--------D/TC:? 0 tee_ta_close_session:529 Destroy session
---
NOOI/TA: Session closing stats:
P Benchmark succI/TA:   Session duration: 47000 us
essful.
Total tI/TA:   Total bytes processed: 0
ime for a singleI/TA:   Operation active: No
 round-trip IPC I/TA: Secure Hash TA session closed
call: 20549 us (D/TA:  TA_DestroyEntryPoint:475 Secure Hash TA: Destroying entry point
20.55 ms)
I/TA: Final stats - Max stack usage: 0 bytes, Total hash ops: 0
D/TC:? 0 destroy_context:307 Destroy TA ctx (0x10189ed0)
# 





did simple print operation along with an increment in the secure world 1000 times and then averaged and got 18 ms as the roundtrip time.

this is just the time for going to secure world and coming back.

--- NOOPD/TC:? 0 tee_ta_close_session:510 csess 0x1018aa00 id 1
 BenchmaD/TC:? 0 tee_ta_close_session:529 Destroy session
rk ResulI/TA: Session closing stats:
ts ---
Total tiI/TA:   Session duration: 18135000 us
me for 1000 callI/TA:   Total bytes processed: 0
s: 18088304 us
I/TA:   Operation active: No
Average round-trI/TA: Secure Hash TA session closed
ip IPC latency: D/TA:  TA_DestroyEntryPoint:475 Secure Hash TA: Destroying entry point
18088.30 us (18.I/TA: Final stats - Max stack usage: 0 bytes, Total hash ops: 0
0883 ms)
D/TC:? 0 destroy_context:307 Destroy TA ctx (0x1018a9a0)
# 



same thing when run with just increment operation by removing the debug print.
like calling from the main function of the secure_hash ta.

got nearly 12.3 ms

--- NOOPD/TC:? 0 tee_ta_close_session:510 csess 0x1018aa00 id 1
 BenchmaD/TC:? 0 tee_ta_close_session:529 Destroy session
rk ResulI/TA: Session closing stats:
ts ---
Total tiI/TA:   Session
=== ENHANCED PERFORMANCE ANALYSIS REPORT (Chunked) ===

--- Host Application Stats ---
File Read I/O Time: 82443 us
Context Switches: 130
Voluntary Context Switches: 0
Involuntary Context Switches: 130
Total Time: 3785648 us
CPU Time: 3779137 us (99.83%)
Memory Peak: 4344 KB

--- Trusted Application Stats ---
IPC Calls: 16
RPC Count: 1
Secure Storage Access: 1
TEE Stack Usage: 112 bytes
Hash Operations: 1
Hash Compute Time: 3246000 us
TEE Time Delta: 3766000 us
REE Time Delta: 3767000 us

--- Enhanced Performance Metrics ---
Memory Efficiency (Peak TA Memory/Input Size): 2.74 bytes per MB processed
Total Time: 3785648 us
Pure Hash Compute Time: 3246000 us
Total Overhead: 457205 us (12.08% of total time)
Average Latency per IPC Call: 236603.00 us
Average time per hash operation: 3785648.00 us
CPU Utilization: 99.83%
I/O vs Compute Time Ratio: 0.03:1
Overall Throughput: 10.79 MB/s
Hash Compute Throughput: 12.58 MB/s

=== END ENHANCED REPORT ===

Secure hash computation completed.
# 
 duration: 1271000 us
me for 100 callsI/TA:   Total bytes processed: 0
: 1231030 us
AvI/TA:   Operation active: No
erage round-tripI/TA: Secure Hash TA session closed
 IPC latency: 12D/TA:  TA_DestroyEntryPoint:474 Secure Hash TA: Destroying entry point
310.30 us (12.31I/TA: Final stats - Max stack usage: 0 bytes, Total hash ops: 0
03 ms)
D/TC:? 0 destroy_context:307 Destroy TA ctx (0x1018a9a0)
# 





this time tried with nothing in the fucntion other than returning TEE_SUCCESS.
and got almost similar time as to increment operation.

got 12.24 ms


--- NOOPD/TC:? 0 tee_ta_close_session:510 csess 0x10189f30 id 1
 BenchmaD/TC:? 0 tee_ta_close_session:529 Destroy session
rk ResulI/TA: Session closing stats:
ts ---
Total tiI/TA:   Session duration: 1264000 us
me for 100 callsI/TA:   Total bytes processed: 0
: 1224391 us
AvI/TA:   Operation active: No
erage round-tripI/TA: Secure Hash TA session closed
 IPC latency: 12D/TA:  TA_DestroyEntryPoint:474 Secure Hash TA: Destroying entry point
243.91 us (12.24I/TA: Final stats - Max stack usage: 0 bytes, Total hash ops: 0
39 ms)
D/TC:? 0 destroy_context:307 Destroy TA ctx (0x10189ed0)
# 





these are the stats with hash computation.


=== ENHANCED PERFORMANCE ANALYSIS REPORT (Chunked) ===

--- Host Application Stats ---
File Read I/O Time: 82443 us
Context Switches: 130
Voluntary Context Switches: 0
Involuntary Context Switches: 130
Total Time: 3785648 us
CPU Time: 3779137 us (99.83%)
Memory Peak: 4344 KB

--- Trusted Application Stats ---
IPC Calls: 16
RPC Count: 1
=== ENHANCED PERFORMANCE ANALYSIS REPORT (Chunked) ===

--- Host Application Stats ---
File Read I/O Time: 82443 us
Context Switches: 130
Voluntary Context Switches: 0
Involuntary Context Switches: 130
Total Time: 3785648 us
CPU Time: 3779137 us (99.83%)
Memory Peak: 4344 KB

--- Trusted Application Stats ---
IPC Calls: 16
RPC Count: 1
Secure Storage Access: 1
TEE Stack Usage: 112 bytes
Hash Operations: 1
Hash Compute Time: 3246000 us
TEE Time Delta: 3766000 us
REE Time Delta: 3767000 us

--- Enhanced Performance Metrics ---
Memory Efficiency (Peak TA Memory/Input Size): 2.74 bytes per MB processed
Total Time: 3785648 us
Pure Hash Compute Time: 3246000 us
Total Overhead: 457205 us (12.08% of total time)
Average Latency per IPC Call: 236603.00 us
Average time per hash operation: 3785648.00 us
CPU Utilization: 99.83%
I/O vs Compute Time Ratio: 0.03:1
Overall Throughput: 10.79 MB/s
Hash Compute Throughput: 12.58 MB/s

=== END ENHANCED REPORT ===

Secure hash computation completed.
# 

Secure Storage Access: 1
TEE Stack Usage: 112 bytes
Hash Operations: 1
Hash Compute Time: 3246000 us
TEE Time Delta: 3766000 us
REE Time Delta: 3767000 us

--- Enhanced Performance Metrics ---
Memory Efficiency (Peak TA Memory/Input Size): 2.74 bytes per MB processed
Total Time: 3785648 us
Pure Hash Compute Time: 3246000 us
Total Overhead: 457205 us (12.08% of total time)
Average Latency per IPC Call: 236603.00 us
Average time per hash operation: 3785648.00 us
CPU Utilization: 99.83%
I/O vs Compute Time Ratio: 0.03:1
Overall Throughput: 10.79 MB/s
Hash Compute Throughput: 12.58 MB/s

=== END ENHANCED REPORT ===

Secure hash computation completed.
# 


here we can observe that avg latency is around 457 ms.
whereas in case of noop it was around 18 ms.
