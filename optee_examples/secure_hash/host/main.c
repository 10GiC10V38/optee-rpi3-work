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
#define CMD_HASH_FILE_SINGLE_SHOT   1  // Original single-shot hash command
#define CMD_GET_PERFORMANCE         2
#define CMD_RESET_COUNTERS          3
#define CMD_HASH_INIT               4  // New command to start a hash operation
#define CMD_HASH_UPDATE             5  // New command to update with a chunk
#define CMD_HASH_FINAL              6  // New command to finalize and get the hash

/* Maximum file size for single-shot hashing (4MB) */
#define MAX_SINGLE_SHOT_SIZE        (4 * 1024 * 1024)
/* Chunk size for streaming (1MB for better performance vs memory tradeoff) */
#define CHUNK_SIZE                  (1 * 1024 * 1024)
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
                                     performance_stats_t *perf_stats) {
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

    printf("File size: %zu bytes, will process in chunks of %d bytes\n", 
           file_size, CHUNK_SIZE);

    /* Allocate chunk buffer */
    chunk_buffer = malloc(CHUNK_SIZE);
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

    printf("Hash operation initialized\n");

    /* Step 2: Process file in chunks */
    size_t chunks_processed = 0;
    while (total_read < file_size) {
        size_t to_read = (file_size - total_read > CHUNK_SIZE) ? 
                         CHUNK_SIZE : (file_size - total_read);

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
        
        /* Print progress for large files */
        if (chunks_processed % 10 == 0 || total_read == file_size) {
            printf("Processed %zu/%zu bytes (%.1f%%) - %zu chunks\n", 
                   total_read, file_size, 
                   (double)total_read / file_size * 100.0, chunks_processed);
        }
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
                                   performance_stats_t *perf_stats) {
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
    if (file_size <= MAX_SINGLE_SHOT_SIZE) {
        return hash_file_single_shot(sess, filename, hash_output, hash_len, perf_stats);
    } else {
        return hash_file_chunked(sess, filename, hash_output, hash_len, perf_stats);
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
                                   const char *method) {
    printf("\n=== PERFORMANCE ANALYSIS REPORT (%s) ===\n", method);
    
    printf("\n--- Host Application Stats ---\n");
    printf("File Read I/O Time: %lu us\n", host_stats->io_read_time_us);
    printf("Context Switches: %lu\n", host_stats->context_switches);
    printf("Voluntary Context Switches: %lu\n", host_stats->voluntary_context_switches);
    printf("Involuntary Context Switches: %lu\n", host_stats->Involuntary_context_switches);
    printf("Total Time: %lu us\n", host_stats->io_time_us);
    printf("CPU Time: %lu us (%.2f%%)\n", 
           host_stats->cpu_time_us,
           host_stats->io_time_us > 0 ? 
           (double)host_stats->cpu_time_us / host_stats->io_time_us * 100.0 : 0.0);
    printf("Memory Peak: %lu KB\n", host_stats->memory_peak_kb);
    
    printf("\n--- Trusted Application Stats ---\n");
    printf("IPC Calls: %lu\n", ta_stats->ipc_calls);
    printf("RPC Count: %lu\n", ta_stats->rpc_count);
    printf("Secure Storage Access: %lu\n", ta_stats->secure_storage_access);
    printf("TEE Stack Usage: %lu bytes\n", ta_stats->tee_stack_usage);
    printf("Hash Operations: %lu\n", ta_stats->hash_operations);
    printf("Hash Compute Time: %lu us\n", ta_stats->hash_compute_time/1000);
    printf("TEE Time Delta: %lu us\n", 
           ta_stats->tee_time_end - ta_stats->tee_time_start);
    printf("REE Time Delta: %lu us\n", 
           ta_stats->ree_time_end - ta_stats->ree_time_start);
    
    printf("\n--- Performance Metrics ---\n");
    printf("Average time per hash operation: %.2f us\n", 
           ta_stats->hash_operations > 0 ? 
           (double)host_stats->io_time_us / ta_stats->hash_operations : 0.0);
    
    if (ta_stats->ipc_calls > 0) {
        printf("Average IPC latency: %.2f us\n", 
               (double)host_stats->io_time_us / ta_stats->ipc_calls);
    }
    
    printf("CPU Utilization: %.2f%%\n",
           host_stats->io_time_us > 0 ?
           (double)host_stats->cpu_time_us / host_stats->io_time_us * 100.0 : 0.0);
    
    printf("I/O vs Compute Time Ratio: %.2f:1\n",
           ta_stats->hash_compute_time > 0 ?
           (double)host_stats->io_read_time_us / (ta_stats->hash_compute_time/1000) : 0.0);
    
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
        fprintf(stderr, "Note: Files > %d bytes will be processed in chunks\n", 
                MAX_SINGLE_SHOT_SIZE);
        return 1;
    }

    printf("Secure Hash Computation with Performance Monitoring\n");
    printf("===================================================\n");
    printf("Single-shot limit: %d bytes, Chunk size: %d bytes\n", 
           MAX_SINGLE_SHOT_SIZE, CHUNK_SIZE);

    /* Initialize TEE context */
    res = initialize_tee_context(&ctx, &sess);
    if (res != TEEC_SUCCESS) {
        return 1;
    }

    /* Process each file */
    for (int i = 1; i < argc; i++) {
        printf("\nProcessing file: %s\n", argv[i]);
        printf("----------------------------------------\n");
        
        /* Reset hash length and stats for each file */
        hash_len = sizeof(hash_output);
        memset(&host_stats, 0, sizeof(host_stats));
        memset(&ta_stats, 0, sizeof(ta_stats));
        
        /* Compute hash with appropriate method */
        res = hash_file_secure(&sess, argv[i], hash_output, &hash_len, &host_stats);
        
        if (res != TEEC_SUCCESS) {
            fprintf(stderr, "Failed to hash file: %s\n", argv[i]);
            continue;
        }

        /* Get TA performance statistics */
        res = get_ta_performance_stats(&sess, &ta_stats);
        if (res == TEEC_SUCCESS) {
            struct stat file_stat;
            const char *method = "Unknown";
            if (stat(argv[i], &file_stat) == 0) {
                method = (file_stat.st_size <= MAX_SINGLE_SHOT_SIZE) ? 
                         "Single-shot" : "Chunked";
            }
            print_performance_report(&host_stats, &ta_stats, method);
        }
    }

    /* Cleanup */
    cleanup_tee_context(&ctx, &sess);
    
    printf("\nSecure hash computation completed.\n");
    return 0;
}
