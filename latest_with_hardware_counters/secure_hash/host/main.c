#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <errno.h>
#include <tee_client_api.h>

/* --- CONFIGURATION --- */
#define TA_SECURE_HASH_UUID \
    { 0xeb0ab446, 0xa63c, 0x4ad5, \
        { 0xaa, 0xda, 0xc6, 0x65, 0xde, 0x64, 0x52, 0x21} }

/* Command IDs (Must match TA) */
#define CMD_HASH_SINGLE_SHOT        1
#define CMD_GET_PERFORMANCE         2
#define CMD_RESET_COUNTERS          3
#define CMD_HASH_INIT               4
#define CMD_HASH_UPDATE             5
#define CMD_HASH_FINAL              6
#define CMD_BENCHMARK_NOOP          7

/* Limits */
#define SINGLE_SHOT_LIMIT           (4 * 1024 * 1024) // 4 MB
#define DEFAULT_CHUNK_SIZE          (1 * 1024 * 1024) // 1 MB

/* --- DATA STRUCTURES --- */

/* Stats received from TA (Raw Hardware Counters) */
typedef struct {
    uint64_t timer_freq_hz;
    uint64_t total_execution_ticks;
    uint64_t pure_algo_ticks;
    uint64_t total_cpu_cycles;
    uint64_t hash_ops_count;
    uint64_t ipc_calls_count;
    uint32_t peak_stack_usage;
} ta_perf_stats_t;

/* Stats collected by Host (OS Software Counters) */
typedef struct {
    uint64_t wall_time_us;
    uint64_t io_time_us;
    long context_switches;
    long peak_rss_kb;
} host_perf_stats_t;

/* --- UTILS --- */

static uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* Convert TA raw ticks to Microseconds */
static double ticks_to_us(uint64_t ticks, uint64_t freq) {
    if (freq == 0) return 0.0;
    return ((double)ticks * 1000000.0) / (double)freq;
}

/* Helper to print simplified stats */
static void print_report(const char *filename, size_t size, 
                        host_perf_stats_t *h, ta_perf_stats_t *t) {
    
    double ta_exec_us = ticks_to_us(t->total_execution_ticks, t->timer_freq_hz);
    double ta_algo_us = ticks_to_us(t->pure_algo_ticks, t->timer_freq_hz);
    
    printf("\n=== PERFORMANCE REPORT: %s ===\n", filename);
    printf("Size: %.2f MB | Method: %s\n", 
           (double)size / (1024*1024), 
           (size <= SINGLE_SHOT_LIMIT) ? "Single-Shot (Fast)" : "Chunked (Streaming)");

    printf("\n[HOST SIDE - OS Metrics]\n");
    printf("  Total Wall Time:   %lu us\n", h->wall_time_us);
    printf("  File I/O Time:     %lu us\n", h->io_time_us);
    printf("  Context Switches:  %ld\n", h->context_switches);
    printf("  Peak RSS Memory:   %ld KB\n", h->peak_rss_kb);

    printf("\n[TEE SIDE - Hardware Counters]\n");
    printf("  Frequency:         %lu Hz\n", t->timer_freq_hz);
    printf("  Total TEE Time:    %.2f us\n", ta_exec_us);
    printf("  Pure Algo Time:    %.2f us (SHA256 Only)\n", ta_algo_us);
    printf("  TEE Overhead:      %.2f us (Ctx Switch + Framework)\n", ta_exec_us - ta_algo_us);
    printf("  CPU Cycles:        %lu\n", t->total_cpu_cycles);
    printf("  Peak Stack Usage:  %u bytes\n", t->peak_stack_usage);
    printf("========================================\n");
}

/* --- TEE OPERATIONS --- */

static TEEC_Result get_ta_stats(TEEC_Session *sess, ta_perf_stats_t *stats) {
    TEEC_Operation op = {0};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = stats;
    op.params[0].tmpref.size = sizeof(ta_perf_stats_t);
    
    return TEEC_InvokeCommand(sess, CMD_GET_PERFORMANCE, &op, NULL);
}

static TEEC_Result run_benchmark_noop(TEEC_Session *sess) {
    TEEC_Operation op = {0};
    uint64_t start, end;
    const int ITERATIONS = 1000;
    
    printf("Running NOOP Benchmark (%d iterations)...\n", ITERATIONS);
    
    start = get_time_us();
    for(int i=0; i<ITERATIONS; i++) {
        TEEC_InvokeCommand(sess, CMD_BENCHMARK_NOOP, &op, NULL);
    }
    end = get_time_us();
    
    double total_ms = (end - start) / 1000.0;
    printf("  Total Time: %.2f ms\n", total_ms);
    printf("  Avg IPC Latency: %.2f us/call\n", (double)(end-start)/ITERATIONS);
    
    return TEEC_SUCCESS;
}

/* --- HASHING LOGIC --- */

static TEEC_Result hash_single_shot(TEEC_Session *sess, uint8_t *data, size_t len, uint8_t *hash) {
    TEEC_Operation op = {0};
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, 
                                    TEEC_MEMREF_TEMP_OUTPUT, 
                                    TEEC_VALUE_INOUT, TEEC_NONE);
    
    op.params[0].tmpref.buffer = data;
    op.params[0].tmpref.size = len;
    op.params[1].tmpref.buffer = hash;
    op.params[1].tmpref.size = 32; // SHA256
    
    return TEEC_InvokeCommand(sess, CMD_HASH_SINGLE_SHOT, &op, NULL);
}

static TEEC_Result hash_chunked(TEEC_Session *sess, uint8_t *data, size_t len, uint8_t *hash) {
    TEEC_Operation op = {0};
    TEEC_Result res;
    size_t offset = 0;
    size_t chunk_size = DEFAULT_CHUNK_SIZE;
    
    /* 1. Init */
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(sess, CMD_HASH_INIT, &op, NULL);
    if (res != TEEC_SUCCESS) return res;
    
    /* 2. Update Loop */
    while(offset < len) {
        size_t current_chunk = (len - offset > chunk_size) ? chunk_size : (len - offset);
        
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = data + offset;
        op.params[0].tmpref.size = current_chunk;
        
        res = TEEC_InvokeCommand(sess, CMD_HASH_UPDATE, &op, NULL);
        if (res != TEEC_SUCCESS) return res;
        
        offset += current_chunk;
    }
    
    /* 3. Final */
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = hash;
    op.params[0].tmpref.size = 32;
    
    return TEEC_InvokeCommand(sess, CMD_HASH_FINAL, &op, NULL);
}

/* Unified File Processor */
static void process_file_securely(TEEC_Session *sess, const char *filename) {
    FILE *f;
    uint8_t *buf = NULL;
    uint8_t hash[32];
    long file_size;
    struct rusage usage_start, usage_end;
    host_perf_stats_t h_stats = {0};
    ta_perf_stats_t t_stats = {0};
    uint64_t t_start, t_end, io_start, io_end;
    
    /* Reset TA counters for this run */
    TEEC_Operation op = {0};
    TEEC_InvokeCommand(sess, CMD_RESET_COUNTERS, &op, NULL);

    /* --- Host Measurement Start --- */
    getrusage(RUSAGE_SELF, &usage_start);
    t_start = get_time_us();
    
    /* 1. IO: Read File */
    io_start = get_time_us();
    f = fopen(filename, "rb");
    if (!f) { perror("File open error"); return; }
    
    fseek(f, 0, SEEK_END);
    file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    buf = malloc(file_size);
    if(!buf) { fclose(f); fprintf(stderr, "OOM\n"); return; }
    
    if(fread(buf, 1, file_size, f) != (size_t)file_size) {
        free(buf); fclose(f); fprintf(stderr, "Read error\n"); return;
    }
    fclose(f);
    io_end = get_time_us();
    h_stats.io_time_us = io_end - io_start;

    /* 2. Secure Hashing (Logic Merge) */
    TEEC_Result res;
    if (file_size <= SINGLE_SHOT_LIMIT) {
        res = hash_single_shot(sess, buf, file_size, hash);
    } else {
        res = hash_chunked(sess, buf, file_size, hash);
    }
    
    free(buf);

    /* --- Host Measurement End --- */
    t_end = get_time_us();
    getrusage(RUSAGE_SELF, &usage_end);
    
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TEE Operation Failed: 0x%x\n", res);
        return;
    }

    /* Calculate Host Stats */
    h_stats.wall_time_us = t_end - t_start;
    h_stats.context_switches = (usage_end.ru_nvcsw + usage_end.ru_nivcsw) - 
                              (usage_start.ru_nvcsw + usage_start.ru_nivcsw);
    h_stats.peak_rss_kb = usage_end.ru_maxrss;

    /* Get TA Stats */
    get_ta_stats(sess, &t_stats);
    
    /* Print Report */
    print_report(filename, file_size, &h_stats, &t_stats);
    
    /* Print Hash */
    printf("Hash: ");
    for(int i=0; i<32; i++) printf("%02x", hash[i]);
    printf("\n");
}

int main(int argc, char *argv[]) {
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Result res;
    TEEC_UUID uuid = TA_SECURE_HASH_UUID;
    uint32_t err_origin;

    if (argc < 2) {
        printf("Usage: %s <file1> [file2] ...\n", argv[0]);
        printf("       %s --benchmark-noop\n", argv[0]);
        return 1;
    }

    /* Initialize TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TEE Init Failed: 0x%x\n", res);
        return 1;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "TEE OpenSession Failed: 0x%x\n", res);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    /* Check for Benchmark Mode */
    if (strcmp(argv[1], "--benchmark-noop") == 0) {
        run_benchmark_noop(&sess);
    } 
    else {
        /* Process Files */
        for (int i = 1; i < argc; i++) {
            process_file_securely(&sess, argv[i]);
        }
    }

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}
