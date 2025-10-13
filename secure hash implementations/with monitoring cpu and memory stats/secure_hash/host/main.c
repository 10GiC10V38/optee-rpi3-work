#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include <tee_client_api.h>

/* UUID of the trusted application */
#define TA_SECURE_HASH_UUID \
    { 0xeb0ab446, 0xa63c, 0x4ad5, \
        { 0xaa, 0xda, 0xc6, 0x65, 0xde, 0x64, 0x52, 0x21} }

/* Command IDs for the TA */
#define CMD_HASH_FILE_SINGLE_SHOT   1  // Original single-shot hash command
#define CMD_GET_PERFORMANCE         2
#define CMD_RESET_COUNTERS          3
#define CMD_HASH_INIT               4  // New command to start a hash operation
#define CMD_HASH_UPDATE             5  // New command to update with a chunk
#define CMD_HASH_FINAL              6  // New command to finalize and get the hash
#define CMD_BENCHMARK_NOOP          7  // New command for baseline overhead

/* File size options (1-4 MB) */
#define SIZE_1MB    (1 * 1024 * 1024)
#define SIZE_2MB    (2 * 1024 * 1024)
#define SIZE_3MB    (3 * 1024 * 1024)
#define SIZE_4MB    (4 * 1024 * 1024)

/* Chunk sizes options for streaming */
#define CHUNK_SIZE_1MB    (1 * 1024 * 1024)
#define CHUNK_SIZE_2MB    (2 * 1024 * 1024)
#define CHUNK_SIZE_3MB    (3 * 1024 * 1024)
#define CHUNK_SIZE_4MB    (4 * 1024 * 1024)

/* Maximum total file size (1GB) */
#define MAX_TOTAL_FILE_SIZE         (1024 * 1024 * 1024)

/* Performance monitoring structure */
typedef struct {
    uint64_t context_switches;
    uint64_t voluntary_context_switches;
    uint64_t Involuntary_context_switches;
    uint64_t ipc_calls;
    uint64_t io_time_us;
    uint64_t cpu_time_us;
    uint64_t memory_peak_kb;
    uint64_t tee_stack_usage;
    uint64_t secure_storage_access;
    uint64_t rpc_count;
    uint64_t hash_operations;
    /* NEW FIELDS */
    uint64_t tee_time_start;
    uint64_t tee_time_end;
    uint64_t ree_time_start;
    uint64_t ree_time_end;
    uint64_t hash_compute_time;
    uint64_t wait_time_total;
    uint64_t io_read_time_us;
    uint64_t total_tee_execution_time;
} performance_stats_t;

/* Monitoring context structure */
typedef struct {
    FILE *log_file;
    volatile int monitoring_active;
    pthread_t monitor_thread;
    uint64_t start_time_us;
    pid_t process_pid;
} monitor_context_t;

/* Global monitoring context */
static monitor_context_t g_monitor_ctx = {0};

/* Forward declarations */
static void* monitor_thread_func(void *arg);
static int start_monitoring(const char *output_filename);
static void stop_monitoring(void);

/* Utility function to get current time in microseconds */
static uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}


/**************************************************************************/
/********************** NEW MONITORING LOGIC STARTS HERE **********************/
/**************************************************************************/

/* System CPU stats structure */
typedef struct {
    unsigned long long user;
    unsigned long long nice;
    unsigned long long system;
    unsigned long long idle;
    unsigned long long iowait;
    unsigned long long irq;
    unsigned long long softirq;
    unsigned long long steal;
} cpu_stats_t;

/* Read system-wide CPU statistics */
static int read_cpu_stats(cpu_stats_t *stats) {
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return -1;

    char line[256];
    if (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                   &stats->user, &stats->nice, &stats->system, &stats->idle,
                   &stats->iowait, &stats->irq, &stats->softirq, &stats->steal) >= 4) {
            fclose(fp);
            return 0;
        }
    }
    fclose(fp);
    return -1;
}

/* Calculate system CPU utilization percentage */
static float calculate_cpu_utilization(cpu_stats_t *prev, cpu_stats_t *curr) {
    unsigned long long prev_idle = prev->idle + prev->iowait;
    unsigned long long curr_idle = curr->idle + curr->iowait;

    unsigned long long prev_total = prev->user + prev->nice + prev->system +
                                    prev->idle + prev->iowait + prev->irq +
                                    prev->softirq + prev->steal;
    unsigned long long curr_total = curr->user + curr->nice + curr->system +
                                    curr->idle + curr->iowait + curr->irq +
                                    curr->softirq + curr->steal;

    unsigned long long total_diff = curr_total - prev_total;
    unsigned long long idle_diff = curr_idle - prev_idle;

    if (total_diff == 0) return 0.0;

    return ((float)(total_diff - idle_diff) / total_diff) * 100.0;
}

/* Get process CPU usage as percentage of total system CPU */
static float get_process_cpu_percent(void) {
    static unsigned long long last_process_time = 0;
    static cpu_stats_t last_system_stats;
    static int first_call = 1;

    // Read process CPU time from /proc/self/stat
    FILE *fp = fopen("/proc/self/stat", "r");
    if (!fp) return 0.0;

    unsigned long long utime = 0, stime = 0;
    char buffer[2048];
    if (fgets(buffer, sizeof(buffer), fp)) {
        // Skip to field 14 (utime) and 15 (stime)
        char *token = buffer;
        for (int i = 0; i < 13; i++) {
            token = strchr(token, ' ');
            if (!token) break;
            token++;
        }
        if (token) {
            sscanf(token, "%llu %llu", &utime, &stime);
        }
    }
    fclose(fp);

    // Read system CPU stats
    cpu_stats_t curr_system_stats;
    if (read_cpu_stats(&curr_system_stats) != 0) return 0.0;

    unsigned long long process_time = utime + stime;

    if (first_call) {
        first_call = 0;
        last_process_time = process_time;
        last_system_stats = curr_system_stats;
        return 0.0;
    }

    // Calculate deltas
    unsigned long long process_delta = process_time - last_process_time;

    unsigned long long system_delta =
        (curr_system_stats.user - last_system_stats.user) +
        (curr_system_stats.nice - last_system_stats.nice) +
        (curr_system_stats.system - last_system_stats.system) +
        (curr_system_stats.idle - last_system_stats.idle) +
        (curr_system_stats.iowait - last_system_stats.iowait) +
        (curr_system_stats.irq - last_system_stats.irq) +
        (curr_system_stats.softirq - last_system_stats.softirq) +
        (curr_system_stats.steal - last_system_stats.steal);

    last_process_time = process_time;
    last_system_stats = curr_system_stats;

    if (system_delta == 0) return 0.0;

    return ((float)process_delta / system_delta) * 100.0;
}

/* Get detailed system memory information */
static void get_detailed_memory_info(long *total_kb, long *free_kb, long *available_kb,
                                     long *buffers_kb, long *cached_kb, long *used_kb) {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return;

    char line[256];
    *total_kb = *free_kb = *available_kb = *buffers_kb = *cached_kb = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            sscanf(line + 9, "%ld", total_kb);
        } else if (strncmp(line, "MemFree:", 8) == 0) {
            sscanf(line + 8, "%ld", free_kb);
        } else if (strncmp(line, "MemAvailable:", 13) == 0) {
            sscanf(line + 13, "%ld", available_kb);
        } else if (strncmp(line, "Buffers:", 8) == 0) {
            sscanf(line + 8, "%ld", buffers_kb);
        } else if (strncmp(line, "Cached:", 7) == 0) {
            sscanf(line + 7, "%ld", cached_kb);
        }
    }
    fclose(fp);

    *used_kb = *total_kb - *free_kb - *buffers_kb - *cached_kb;
}

/* Get process memory info from /proc/self/status */
static void get_memory_info(long *vm_rss_kb, long *vm_size_kb) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return;

    char line[256];
    *vm_rss_kb = 0;
    *vm_size_kb = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%ld", vm_rss_kb);
        } else if (strncmp(line, "VmSize:", 7) == 0) {
            sscanf(line + 7, "%ld", vm_size_kb);
        }
    }
    fclose(fp);
}

/* ENHANCED monitoring thread with system-level metrics */
static void* monitor_thread_func(void *arg) {
    monitor_context_t *ctx = (monitor_context_t*)arg;

    /* Write enhanced CSV header */
    fprintf(ctx->log_file, "Timestamp_us,Elapsed_ms,"
            "System_CPU_Percent,Process_CPU_Percent,"
            "Process_RSS_KB,Process_VmSize_KB,"
            "System_Total_KB,System_Used_KB,System_Free_KB,System_Available_KB,"
            "System_Buffers_KB,System_Cached_KB,"
            "System_Used_Percent,System_Available_Percent,"
            "CtxSwitches\n");
    fflush(ctx->log_file);

    cpu_stats_t prev_cpu_stats, curr_cpu_stats;
    read_cpu_stats(&prev_cpu_stats);

    struct rusage usage;
    while (ctx->monitoring_active) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        uint64_t timestamp_us = tv.tv_sec * 1000000 + tv.tv_usec;
        uint64_t elapsed_ms = (timestamp_us - ctx->start_time_us) / 1000;

        /* System CPU utilization */
        read_cpu_stats(&curr_cpu_stats);
        float system_cpu_percent = calculate_cpu_utilization(&prev_cpu_stats, &curr_cpu_stats);
        prev_cpu_stats = curr_cpu_stats;

        /* Process CPU utilization (as % of total system) */
        float process_cpu_percent = get_process_cpu_percent();

        /* Process memory */
        long process_rss = 0, process_vmsize = 0;
        get_memory_info(&process_rss, &process_vmsize);

        /* System memory */
        long mem_total = 0, mem_free = 0, mem_available = 0;
        long mem_buffers = 0, mem_cached = 0, mem_used = 0;
        get_detailed_memory_info(&mem_total, &mem_free, &mem_available,
                                 &mem_buffers, &mem_cached, &mem_used);

        float mem_used_percent = mem_total > 0 ?
            ((float)mem_used / mem_total) * 100.0 : 0.0;
        float mem_avail_percent = mem_total > 0 ?
            ((float)mem_available / mem_total) * 100.0 : 0.0;

        /* Context switches */
        getrusage(RUSAGE_SELF, &usage);
        long ctx_switches = usage.ru_nvcsw + usage.ru_nivcsw;

        /* Write data */
        fprintf(ctx->log_file, "%lu,%lu,%.2f,%.2f,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%.2f,%.2f,%ld\n",
                timestamp_us, elapsed_ms,
                system_cpu_percent, process_cpu_percent,
                process_rss, process_vmsize,
                mem_total, mem_used, mem_free, mem_available,
                mem_buffers, mem_cached,
                mem_used_percent, mem_avail_percent,
                ctx_switches);
        fflush(ctx->log_file);

        usleep(100000); // 100ms sampling rate
    }

    return NULL;
}

/**************************************************************************/
/*********************** NEW MONITORING LOGIC ENDS HERE ***********************/
/**************************************************************************/


/* Start monitoring */
static int start_monitoring(const char *output_filename) {
    g_monitor_ctx.log_file = fopen(output_filename, "w");
    if (!g_monitor_ctx.log_file) {
        fprintf(stderr, "Failed to open monitoring log file: %s\n", output_filename);
        return -1;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    g_monitor_ctx.start_time_us = tv.tv_sec * 1000000 + tv.tv_usec;
    g_monitor_ctx.monitoring_active = 1;
    g_monitor_ctx.process_pid = getpid();

    if (pthread_create(&g_monitor_ctx.monitor_thread, NULL,
                       monitor_thread_func, &g_monitor_ctx) != 0) {
        fprintf(stderr, "Failed to create monitoring thread\n");
        fclose(g_monitor_ctx.log_file);
        return -1;
    }

    printf("Performance monitoring started -> %s\n", output_filename);
    return 0;
}

/* Stop monitoring */
static void stop_monitoring(void) {
    if (g_monitor_ctx.monitoring_active) {
        g_monitor_ctx.monitoring_active = 0;
        pthread_join(g_monitor_ctx.monitor_thread, NULL);
        fclose(g_monitor_ctx.log_file);
        printf("Performance monitoring stopped\n");
    }
}

static void print_usage(const char *program_name) {
    printf("Usage: %s [options] <file_to_hash> [file2] [file3] ...\n", program_name);
    printf("\nOptions:\n");
    printf("  -s <size>   Set single-shot size limit (1-4):\n");
    printf("              1 = 1MB, 2 = 2MB, 3 = 3MB, 4 = 4MB\n");
    printf("              Default: 4MB\n");
    printf("  -c <size>   Set chunk size for chunked method (1-4 MB)\n");
    printf("              Default: 1MB\n");
    printf("  -m          Enable real-time performance monitoring (generates CSV)\n");
    printf("  -h          Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -s 2 -c 3 /boot/config.txt  # Use 2MB single-shot limit, 3MB chunk size\n", program_name);
    printf("  %s -m /boot/config.txt         # Enable monitoring\n", program_name);
    printf("  %s /boot/config.txt            # Use default limits\n", program_name);
    printf("\nNote: Files larger than the single-shot limit will be processed in chunks\n");
}

static size_t parse_size_option(const char *size_str) {
    int size_option = atoi(size_str);

    switch (size_option) {
        case 1: return SIZE_1MB;
        case 2: return SIZE_2MB;
        case 3: return SIZE_3MB;
        case 4: return SIZE_4MB;
        default:
            fprintf(stderr, "Invalid size option: %s. Must be 1, 2, 3, or 4\n", size_str);
            return 0;
    }
}

static const char* get_size_string(size_t size) {
    switch (size) {
        case SIZE_1MB: return "1MB";
        case SIZE_2MB: return "2MB";
        case SIZE_3MB: return "3MB";
        case SIZE_4MB: return "4MB";
        default: return "Unknown";
    }
}

static TEEC_Result initialize_tee_context(TEEC_Context *ctx, TEEC_Session *sess) {
    TEEC_UUID svc_id = TA_SECURE_HASH_UUID;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;

    /* Initialize context */
    res = TEEC_InitializeContext(NULL, ctx);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "Failed to initialize TEE context: 0x%x\n", res);
        return res;
    }

    /* Clear operation struct */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    /* Open session */
    res = TEEC_OpenSession(ctx, sess, &svc_id, TEEC_LOGIN_PUBLIC,
                          NULL, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "Failed to open TEE session: 0x%x (origin: 0x%x)\n",
                res, err_origin);
        TEEC_FinalizeContext(ctx);
        return res;
    }

    return TEEC_SUCCESS;
}

static void cleanup_tee_context(TEEC_Context *ctx, TEEC_Session *sess) {
    TEEC_CloseSession(sess);
    TEEC_FinalizeContext(ctx);
}

static void get_system_stats_before(struct rusage *usage_before,
                                   uint64_t *time_before) {
    getrusage(RUSAGE_SELF, usage_before);
    *time_before = get_time_us();
}

static void get_system_stats_after(struct rusage *usage_before,
                                  uint64_t time_before,
                                  performance_stats_t *stats) {
    struct rusage usage_after;
    uint64_t time_after;

    getrusage(RUSAGE_SELF, &usage_after);
    time_after = get_time_us();

    /* Calculate context switches */
    stats->voluntary_context_switches = (usage_after.ru_nvcsw - usage_before->ru_nvcsw);
    stats->Involuntary_context_switches = (usage_after.ru_nivcsw - usage_before->ru_nivcsw);
    stats->context_switches = (usage_after.ru_nvcsw - usage_before->ru_nvcsw) +
                             (usage_after.ru_nivcsw - usage_before->ru_nivcsw);

    /* Calculate CPU time */
    uint64_t cpu_before = usage_before->ru_utime.tv_sec * 1000000 +
                         usage_before->ru_utime.tv_usec +
                         usage_before->ru_stime.tv_sec * 1000000 +
                         usage_before->ru_stime.tv_usec;

    uint64_t cpu_after = usage_after.ru_utime.tv_sec * 1000000 +
                        usage_after.ru_utime.tv_usec +
                        usage_after.ru_stime.tv_sec * 1000000 +
                        usage_after.ru_stime.tv_usec;

    stats->cpu_time_us = cpu_after - cpu_before;
    stats->io_time_us = time_after - time_before;

    /* Memory usage */
    stats->memory_peak_kb = usage_after.ru_maxrss;
}

/* Original single-shot hash function for small files */
static TEEC_Result hash_file_single_shot(TEEC_Session *sess, const char *filename,
                                         uint8_t *hash_output, size_t *hash_len,
                                         performance_stats_t *perf_stats) {
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    FILE *file;
    uint8_t *file_buffer = NULL;
    size_t file_size;
    struct rusage usage_before;
    uint64_t time_before;
    uint64_t io_start_time, io_end_time;

    printf("Using single-shot hashing for small file\n");

    /* Start I/O timing */
    io_start_time = get_time_us();

    /* Open and read file */
    file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file %s: %s\n", filename, strerror(errno));
        return TEEC_ERROR_ITEM_NOT_FOUND;
    }

    /* Get file size */
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    /* Allocate buffer and read file */
    file_buffer = malloc(file_size);
    if (!file_buffer) {
        fprintf(stderr, "Failed to allocate buffer for file\n");
        fclose(file);
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    if (fread(file_buffer, 1, file_size, file) != file_size) {
        fprintf(stderr, "Failed to read file content\n");
        free(file_buffer);
        fclose(file);
        return TEEC_ERROR_GENERIC;
    }
    fclose(file);

    io_end_time = get_time_us();
    perf_stats->io_read_time_us = io_end_time - io_start_time;

    /* Get system stats before TEE operation */
    get_system_stats_before(&usage_before, &time_before);

    /* Prepare TEE operation */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_VALUE_INOUT,
                                     TEEC_NONE);

    /* Input buffer */
    op.params[0].tmpref.buffer = file_buffer;
    op.params[0].tmpref.size = file_size;

    /* Output hash buffer */
    op.params[1].tmpref.buffer = hash_output;
    op.params[1].tmpref.size = *hash_len;

    /* File size parameter */
    op.params[2].value.a = file_size;
    op.params[2].value.b = 0; /* Will be set by TA with hash length */

    /* Invoke the command */
    res = TEEC_InvokeCommand(sess, CMD_HASH_FILE_SINGLE_SHOT, &op, &err_origin);

    /* Get system stats after TEE operation */
    get_system_stats_after(&usage_before, time_before, perf_stats);

    if (res == TEEC_SUCCESS) {
        *hash_len = op.params[1].tmpref.size;
        printf("Single-shot hash computed successfully (%zu bytes)\n", *hash_len);

        /* Print hash in hex format */
        printf("Hash: ");
        for (size_t i = 0; i < *hash_len; i++) {
            printf("%02x", hash_output[i]);
        }
        printf("\n");
    } else {
        fprintf(stderr, "Failed to compute hash: 0x%x (origin: 0x%x)\n",
                res, err_origin);
    }

    free(file_buffer);
    return res;
}

/* New chunked hash function for large files */
static TEEC_Result hash_file_chunked(TEEC_Session *sess, const char *filename,
                                     uint8_t *hash_output, size_t *hash_len,
                                     performance_stats_t *perf_stats,
                                     size_t chunksize) {
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    FILE *file;
    uint8_t *chunk_buffer = NULL;
    size_t file_size;
    size_t total_read = 0;
    struct rusage usage_before;
    uint64_t time_before;
    uint64_t io_start_time, io_end_time, total_io_time = 0;

    printf("Using chunked hashing for large file\n");

    /* Open file to get size */
    file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file %s: %s\n", filename, strerror(errno));
        return TEEC_ERROR_ITEM_NOT_FOUND;
    }

    /* Get file size */
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size > MAX_TOTAL_FILE_SIZE) {
        fprintf(stderr, "File too large: %zu bytes (max: %d)\n",
                file_size, MAX_TOTAL_FILE_SIZE);
        fclose(file);
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    printf("File size: %zu bytes, will process in chunks of %zu bytes\n",
           file_size, chunksize);

    /* Allocate chunk buffer */
    chunk_buffer = malloc(chunksize);
    if (!chunk_buffer) {
        fprintf(stderr, "Failed to allocate chunk buffer\n");
        fclose(file);
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

    /* Get system stats before TEE operations */
    get_system_stats_before(&usage_before, &time_before);

    /* Step 1: Initialize hash operation */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(sess, CMD_HASH_INIT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "Failed to initialize hash: 0x%x (origin: 0x%x)\n",
                res, err_origin);
        free(chunk_buffer);
        fclose(file);
        return res;
    }

    /* Step 2: Process file in chunks */
    size_t chunks_processed = 0;
    while (total_read < file_size) {
        size_t to_read = (file_size - total_read > chunksize) ?
                         chunksize : (file_size - total_read);

        /* Read chunk with I/O timing */
        io_start_time = get_time_us();
        size_t bytes_read = fread(chunk_buffer, 1, to_read, file);
        io_end_time = get_time_us();
        total_io_time += (io_end_time - io_start_time);

        if (bytes_read != to_read) {
            fprintf(stderr, "Failed to read chunk: expected %zu, got %zu\n",
                    to_read, bytes_read);
            free(chunk_buffer);
            fclose(file);
            return TEEC_ERROR_GENERIC;
        }

        /* Update hash with this chunk */
        memset(&op, 0, sizeof(op));
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                         TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = chunk_buffer;
        op.params[0].tmpref.size = bytes_read;

        res = TEEC_InvokeCommand(sess, CMD_HASH_UPDATE, &op, &err_origin);
        if (res != TEEC_SUCCESS) {
            fprintf(stderr, "Failed to update hash: 0x%x (origin: 0x%x)\n",
                    res, err_origin);
            free(chunk_buffer);
            fclose(file);
            return res;
        }

        total_read += bytes_read;
        chunks_processed++;
    }

    fclose(file);
    perf_stats->io_read_time_us = total_io_time;

    /* Step 3: Finalize hash and get result */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = hash_output;
    op.params[0].tmpref.size = *hash_len;

    res = TEEC_InvokeCommand(sess, CMD_HASH_FINAL, &op, &err_origin);

    /* Get system stats after all TEE operations */
    get_system_stats_after(&usage_before, time_before, perf_stats);

    if (res == TEEC_SUCCESS) {
        *hash_len = op.params[0].tmpref.size;
        printf("Chunked hash computed successfully (%zu bytes) from %zu chunks\n",
               *hash_len, chunks_processed);

        /* Print hash in hex format */
        printf("Hash: ");
        for (size_t i = 0; i < *hash_len; i++) {
            printf("%02x", hash_output[i]);
        }
        printf("\n");
    } else {
        fprintf(stderr, "Failed to finalize hash: 0x%x (origin: 0x%x)\n",
                res, err_origin);
    }

    free(chunk_buffer);
    return res;
}

/* Main hash function that chooses between single-shot and chunked */
static TEEC_Result hash_file_secure(TEEC_Session *sess, const char *filename,
                                   uint8_t *hash_output, size_t *hash_len,
                                   performance_stats_t *perf_stats,
                                   size_t single_shot_limit,
                                   size_t chunksize) {
    struct stat file_stat;

    /* Get file information */
    if (stat(filename, &file_stat) != 0) {
        fprintf(stderr, "Failed to get file info for %s: %s\n",
                filename, strerror(errno));
        return TEEC_ERROR_ITEM_NOT_FOUND;
    }

    size_t file_size = file_stat.st_size;
    printf("File size: %zu bytes\n", file_size);

    /* Choose hashing method based on file size */
    if (file_size <= single_shot_limit) {
        return hash_file_single_shot(sess, filename, hash_output, hash_len, perf_stats);
    } else {
        return hash_file_chunked(sess, filename, hash_output, hash_len, perf_stats, chunksize);
    }
}

static TEEC_Result get_ta_performance_stats(TEEC_Session *sess,
                                           performance_stats_t *ta_stats) {
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE,
                                     TEEC_NONE);

    op.params[0].tmpref.buffer = ta_stats;
    op.params[0].tmpref.size = sizeof(performance_stats_t);

    res = TEEC_InvokeCommand(sess, CMD_GET_PERFORMANCE, &op, &err_origin);

    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "Failed to get TA performance stats: 0x%x\n", res);
    }

    return res;
}

static void print_performance_report(performance_stats_t *host_stats,
                                     performance_stats_t *ta_stats,
                                     const char *method,
                                     size_t file_size_bytes) {
    double baseline_ipc_latency_us = 6.6;

    printf("\n=== ENHANCED PERFORMANCE ANALYSIS REPORT (%s) ===\n", method);

    // --- Host Application Stats ---
    printf("\n--- Host Application Stats ---\n");
    printf("File Read I/O Time: %lu us\n", host_stats->io_read_time_us);
    printf("Total Time: %lu us\n", host_stats->io_time_us);
    printf("Memory Peak: %lu KB\n", host_stats->memory_peak_kb);
    printf("Context Switches: %lu (Voluntary: %lu, Involuntary: %lu)\n",
           host_stats->context_switches, host_stats->voluntary_context_switches, host_stats->Involuntary_context_switches);

    // --- Trusted Application Stats ---
    printf("\n--- Trusted Application Stats ---\n");
    printf("IPC Calls: %lu\n", ta_stats->ipc_calls);
    const double TOTAL_TA_STACK_SIZE = 16384.0;
    double stack_utilization_percent = ((double)ta_stats->tee_stack_usage / TOTAL_TA_STACK_SIZE) * 100.0;
    printf("Peak TEE Stack Usage: %lu bytes (%.2f%% of total allocated)\n",
           ta_stats->tee_stack_usage, stack_utilization_percent);
    printf("Pure Hash Compute Time: %lu us\n", ta_stats->hash_compute_time / 1000);
    printf("Total TEE Execution Time: %lu us\n", ta_stats->total_tee_execution_time);

    // --- Core Performance Metrics ---
    printf("\n--- Core Performance Metrics ---\n");

    double file_size_mib = (double)file_size_bytes / (1024.0 * 1024.0);
    uint64_t hash_compute_time_us = ta_stats->hash_compute_time / 1000;

    if (host_stats->io_time_us > 0) {
        double throughput_mips = file_size_mib / ((double)host_stats->io_time_us / 1000000.0);
        printf("Overall Throughput: %.2f MiB/s\n", throughput_mips);
    }
    if (hash_compute_time_us > 0) {
        double hash_throughput = file_size_mib / ((double)hash_compute_time_us / 1000000.0);
        printf("Hash Compute Throughput: %.2f MiB/s\n", hash_throughput);
    }
    printf("I/O vs Compute Time Ratio: %.2f:1\n",
           hash_compute_time_us > 0 ?
           (double)host_stats->io_read_time_us / hash_compute_time_us : 0.0);

    // --- In-Depth Overhead Analysis ---
    printf("\n--- In-Depth Overhead Analysis ---\n");

    uint64_t total_overhead_us = 0;
    if (host_stats->io_time_us > (hash_compute_time_us + host_stats->io_read_time_us)) {
        total_overhead_us = host_stats->io_time_us - hash_compute_time_us - host_stats->io_read_time_us;
    }

    uint64_t tee_time_delta_us = ta_stats->total_tee_execution_time;
    uint64_t host_side_time_us = host_stats->io_time_us > tee_time_delta_us ? host_stats->io_time_us - tee_time_delta_us : 0;
    uint64_t host_side_overhead_us = host_side_time_us > host_stats->io_read_time_us ? host_side_time_us - host_stats->io_read_time_us : 0;
    uint64_t tee_side_overhead_us = tee_time_delta_us > hash_compute_time_us ? tee_time_delta_us - hash_compute_time_us : 0;

    printf("Total System Overhead: %lu us (%.2f%% of Total Time)\n",
           total_overhead_us,
           host_stats->io_time_us > 0 ? (double)total_overhead_us / host_stats->io_time_us * 100.0 : 0.0);
    printf("  - Host-side Overhead: %lu us\n", host_side_overhead_us);
    printf("  - TEE-side Overhead: %lu us\n", tee_side_overhead_us);
    printf("Baseline Round-trip IPC Latency: %.2f us\n", baseline_ipc_latency_us);

    printf("\n=== END ENHANCED REPORT ===\n");
}

static void run_noop_benchmark(TEEC_Session *sess) {
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;
    uint64_t total_time_us = 0;
    const int iterations = 100;

    printf("\nRunning NOOP Benchmark...\n");
    printf("----------------------------------------\n");

    /* Warm-up call */
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    res = TEEC_InvokeCommand(sess, CMD_BENCHMARK_NOOP, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        fprintf(stderr, "Warm-up call failed: 0x%x\n", res);
        return;
    }
    printf("Warm-up call complete. Starting benchmark for %d iterations...\n", iterations);

    /* Measurement loop */
    for (int i = 0; i < iterations; i++) {
        uint64_t start_time = get_time_us();
        res = TEEC_InvokeCommand(sess, CMD_BENCHMARK_NOOP, &op, &err_origin);
        uint64_t end_time = get_time_us();
        total_time_us += (end_time - start_time);

        if (res != TEEC_SUCCESS) {
            fprintf(stderr, "NOOP Benchmark failed during loop: 0x%x\n", res);
            return;
        }
    }

    /* Results */
    double avg_time_us = (double)total_time_us / iterations;
    printf("\n--- NOOP Benchmark Results ---\n");
    printf("Total time for %d calls: %lu us\n", iterations, total_time_us);
    printf("Average round-trip IPC latency: %.2f us (%.4f ms)\n", avg_time_us, avg_time_us / 1000.0);
}

int main(int argc, char *argv[]) {
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Result res;
    uint8_t hash_output[64];
    size_t hash_len = sizeof(hash_output);
    performance_stats_t host_stats = {0};
    performance_stats_t ta_stats = {0};
    size_t single_shot_limit = SIZE_4MB;
    size_t chunk_size = CHUNK_SIZE_1MB;
    int file_start_index = 1;
    int enable_monitoring = 0;
    char monitor_filename[256] = {0};

    /* Check for benchmark flag */
    if (argc == 2 && strcmp(argv[1], "--benchmark-noop") == 0) {
        res = initialize_tee_context(&ctx, &sess);
        if (res != TEEC_SUCCESS) return 1;
        run_noop_benchmark(&sess);
        cleanup_tee_context(&ctx, &sess);
        return 0;
    }

    /* Parse command line options */
    int opt;
    while ((opt = getopt(argc, argv, "s:c:mh")) != -1) {
        switch (opt) {
            case 's': {
                size_t new_limit = parse_size_option(optarg);
                if (new_limit == 0) {
                    return 1;
                }
                single_shot_limit = new_limit;
                break;
            }
            case 'c': {
                int cs = atoi(optarg);
                switch (cs) {
                    case 1: chunk_size = CHUNK_SIZE_1MB; break;
                    case 2: chunk_size = CHUNK_SIZE_2MB; break;
                    case 3: chunk_size = CHUNK_SIZE_3MB; break;
                    case 4: chunk_size = CHUNK_SIZE_4MB; break;
                    default:
                        fprintf(stderr, "Invalid chunk size: %s. Must be 1, 2, 3, or 4\n", optarg);
                        return 1;
                }
                break;
            }
            case 'm':
                enable_monitoring = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    file_start_index = optind;

    if (file_start_index >= argc) {
        fprintf(stderr, "Error: No files specified\n\n");
        print_usage(argv[0]);
        return 1;
    }

    printf("Secure Hash Computation with Enhanced Performance Monitoring\n");
    printf("============================================================\n");
    printf("Single-shot limit: %s, Chunk size: %zu KB\n",
           get_size_string(single_shot_limit), chunk_size / 1024);

    /* Generate monitoring filename if enabled */
    if (enable_monitoring) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        snprintf(monitor_filename, sizeof(monitor_filename),
                 "optee_performance_%04d%02d%02d_%02d%02d%02d.csv",
                 t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                 t->tm_hour, t->tm_min, t->tm_sec);

        if (start_monitoring(monitor_filename) != 0) {
            fprintf(stderr, "Warning: Monitoring disabled due to initialization failure\n");
            enable_monitoring = 0;
        }
    }

    /* Initialize TEE context */
    res = initialize_tee_context(&ctx, &sess);
    if (res != TEEC_SUCCESS) {
        if (enable_monitoring) {
            stop_monitoring();
        }
        return 1;
    }

    /* Process each file */
    for (int i = file_start_index; i < argc; i++) {
        printf("\nProcessing file: %s\n", argv[i]);
        printf("----------------------------------------\n");

        /* Get file size for stats */
        struct stat file_stat;
        size_t file_size = 0;
        if (stat(argv[i], &file_stat) == 0) {
            file_size = file_stat.st_size;
        }

        /* Reset hash length and stats for each file */
        hash_len = sizeof(hash_output);
        memset(&host_stats, 0, sizeof(host_stats));
        memset(&ta_stats, 0, sizeof(ta_stats));

        /* Compute hash with appropriate method */
        res = hash_file_secure(&sess, argv[i], hash_output, &hash_len,
                              &host_stats, single_shot_limit, chunk_size);

        if (res != TEEC_SUCCESS) {
            fprintf(stderr, "Failed to hash file: %s\n", argv[i]);
            continue;
        }

        /* Get TA performance statistics */
        res = get_ta_performance_stats(&sess, &ta_stats);
        if (res == TEEC_SUCCESS) {
            const char *method = (file_size <= single_shot_limit) ?
                                 "Single-shot" : "Chunked";
            print_performance_report(&host_stats, &ta_stats, method, file_size);
        }
    }

    /* Cleanup */
    cleanup_tee_context(&ctx, &sess);

    if (enable_monitoring) {
        stop_monitoring();
        printf("\nPerformance monitoring data saved to: %s\n", monitor_filename);
    }

    printf("\nSecure hash computation completed.\n");
    return 0;
}
