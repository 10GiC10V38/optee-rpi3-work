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

#include <tee_client_api.h>

/* UUID of the trusted application */
#define TA_SECURE_HASH_UUID \
    { 0xeb0ab446, 0xa63c, 0x4ad5, \
        { 0xaa, 0xda, 0xc6, 0x65, 0xde, 0x64, 0x52, 0x21} }

/* Command IDs for the TA */
#define CMD_HASH_FILE           1
#define CMD_GET_PERFORMANCE     2
#define CMD_RESET_COUNTERS      3

/* Maximum file size to hash (100MB) */
#define MAX_FILE_SIZE           (100 * 1024 * 1024)

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
    /* NEW FIELDS - ADD THESE */
    uint64_t tee_time_start;
    uint64_t tee_time_end;
    uint64_t ree_time_start;
    uint64_t ree_time_end;
    uint64_t hash_compute_time;
    uint64_t wait_time_total;
    uint64_t io_read_time_us;
} performance_stats_t;

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

static uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
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

static TEEC_Result hash_file_secure(TEEC_Session *sess, const char *filename,
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

    /* --- START I/O TIMING --- */
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

    if (file_size > MAX_FILE_SIZE) {
        fprintf(stderr, "File too large: %zu bytes (max: %d)\n", 
                file_size, MAX_FILE_SIZE);
        fclose(file);
        return TEEC_ERROR_OUT_OF_MEMORY;
    }

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
    res = TEEC_InvokeCommand(sess, CMD_HASH_FILE, &op, &err_origin);

    /* Get system stats after TEE operation */
    get_system_stats_after(&usage_before, time_before, perf_stats);

    if (res == TEEC_SUCCESS) {
        *hash_len = op.params[1].tmpref.size;
        printf("Hash computed successfully (%zu bytes)\n", *hash_len);
        
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
                                   performance_stats_t *ta_stats) {
    printf("\n=== PERFORMANCE ANALYSIS REPORT ===\n");
    
    printf("\n--- Host Application Stats ---\n");
    printf("File Read I/O Time: %lu μs\n", host_stats->io_read_time_us);
    printf("Context Switches: %lu\n", host_stats->context_switches);
    printf("Voluntary Context Switches: %lu\n", host_stats->voluntary_context_switches);
    printf("InVoluntary Context Switches: %lu\n", host_stats->Involuntary_context_switches);
    printf("Total Time: %lu μs\n", host_stats->io_time_us);
    printf("CPU Time: %lu μs (%.2f%%)\n", 
           host_stats->cpu_time_us,
           (double)host_stats->cpu_time_us / host_stats->io_time_us * 100.0);
    printf("Memory Peak: %lu KB\n", host_stats->memory_peak_kb);
    
    printf("\n--- Trusted Application Stats ---\n");
    printf("IPC Calls: %lu\n", ta_stats->ipc_calls);
    printf("RPC Count: %lu\n", ta_stats->rpc_count);
    printf("Secure Storage Access: %lu\n", ta_stats->secure_storage_access);
    printf("TEE Stack Usage: %lu bytes\n", ta_stats->tee_stack_usage);
    printf("Hash Operations: %lu\n", ta_stats->hash_operations);
    
    printf("\n--- Performance Metrics ---\n");
    printf("Average time per hash: %.2f μs\n", 
           ta_stats->hash_operations > 0 ? 
           (double)host_stats->io_time_us / ta_stats->hash_operations : 0.0);
    
    if (ta_stats->ipc_calls > 0) {
        printf("Average IPC latency: %.2f μs\n", 
               (double)host_stats->io_time_us / ta_stats->ipc_calls);
    }
    
    printf("CPU Utilization: %.2f%%\n",
           (double)host_stats->cpu_time_us / host_stats->io_time_us * 100.0);
    
    printf("\n=== END REPORT ===\n");
}

int main(int argc, char *argv[]) {
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Result res;
    uint8_t hash_output[64]; /* SHA-256/SHA-512 output */
    size_t hash_len = sizeof(hash_output);
    performance_stats_t host_stats = {0};
    performance_stats_t ta_stats = {0};

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file_to_hash> [file2] [file3] ...\n", argv[0]);
        fprintf(stderr, "Example: %s /boot/config.txt /boot/cmdline.txt\n", argv[0]);
        return 1;
    }

    printf("Secure Hash Computation with Performance Monitoring\n");
    printf("===================================================\n");

    /* Initialize TEE context */
    res = initialize_tee_context(&ctx, &sess);
    if (res != TEEC_SUCCESS) {
        return 1;
    }

    /* Process each file */
    for (int i = 1; i < argc; i++) {
        printf("\nProcessing file: %s\n", argv[i]);
        printf("----------------------------------------\n");
        
        /* Reset hash length for each file */
        hash_len = sizeof(hash_output);
        
        /* Compute hash with performance monitoring */
        res = hash_file_secure(&sess, argv[i], hash_output, &hash_len, &host_stats);
        
        if (res != TEEC_SUCCESS) {
            fprintf(stderr, "Failed to hash file: %s\n", argv[i]);
            continue;
        }

        /* Get TA performance statistics */
        res = get_ta_performance_stats(&sess, &ta_stats);
        if (res == TEEC_SUCCESS) {
            print_performance_report(&host_stats, &ta_stats);
        }
    }

    /* Cleanup */
    cleanup_tee_context(&ctx, &sess);
    
    printf("\nSecure hash computation completed.\n");
    return 0;
}
