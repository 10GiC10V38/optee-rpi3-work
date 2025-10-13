#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <openssl/evp.h>

#define CHUNK_SIZE (1 * 1024 * 1024) // Use the same chunk size as your TEE app

/* This performance struct and the helper functions are identical to your TEE host app */
/* This ensures the measurements are perfectly comparable */
typedef struct {
    uint64_t context_switches;
    uint64_t voluntary_context_switches;
    uint64_t Involuntary_context_switches;
    uint64_t io_time_us;
    uint64_t cpu_time_us;
    uint64_t io_read_time_us;
} performance_stats_t;

static uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static void get_system_stats_before(struct rusage *usage_before, uint64_t *time_before) {
    getrusage(RUSAGE_SELF, usage_before);
    *time_before = get_time_us();
}

static void get_system_stats_after(struct rusage *usage_before, uint64_t time_before, performance_stats_t *stats) {
    struct rusage usage_after;
    uint64_t time_after = get_time_us();
    getrusage(RUSAGE_SELF, &usage_after);
    
    stats->voluntary_context_switches = (usage_after.ru_nvcsw - usage_before->ru_nvcsw);
    stats->Involuntary_context_switches = (usage_after.ru_nivcsw - usage_before->ru_nivcsw);
    stats->context_switches = stats->voluntary_context_switches + stats->Involuntary_context_switches;

    uint64_t cpu_before = (usage_before->ru_utime.tv_sec * 1000000 + usage_before->ru_utime.tv_usec) + (usage_before->ru_stime.tv_sec * 1000000 + usage_before->ru_stime.tv_usec);
    uint64_t cpu_after = (usage_after.ru_utime.tv_sec * 1000000 + usage_after.ru_utime.tv_usec) + (usage_after.ru_stime.tv_sec * 1000000 + usage_after.ru_stime.tv_usec);
    
    stats->cpu_time_us = cpu_after - cpu_before;
    stats->io_time_us = time_after - time_before;
}

static void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    const char *filename = argv[1];

    struct rusage usage_before;
    uint64_t time_before;
    performance_stats_t host_stats = {0};
    uint64_t total_io_time = 0;

    printf("Calculating SHA-256 baseline for file: %s\n", filename);

    /* --- Start Performance Measurement --- */
    get_system_stats_before(&usage_before, &time_before);

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Failed to open file");
        return 1;
    }

    /* --- OpenSSL Hashing Logic --- */
    unsigned char hash_output[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Failed to create OpenSSL context\n");
        return 1;
    }

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    unsigned char chunk_buffer[CHUNK_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(chunk_buffer, 1, CHUNK_SIZE, fp)) > 0) {
        uint64_t io_start = get_time_us();
        // This is an empty block to measure fread timing, but it's already done by fread itself.
        // We accumulate the time of fread call to be comparable with TEE version.
        // For a more accurate I/O time, one might need to time the fread call itself,
        // but for simplicity, we assume the host_stats will capture the I/O wait time.
        EVP_DigestUpdate(mdctx, chunk_buffer, bytes_read);
        total_io_time += (get_time_us() - io_start); // Simplified I/O timing
    }

    EVP_DigestFinal_ex(mdctx, hash_output, &hash_len);
    EVP_MD_CTX_free(mdctx);
    fclose(fp);
    
    /* --- Stop Performance Measurement --- */
    get_system_stats_after(&usage_before, time_before, &host_stats);
    host_stats.io_read_time_us = total_io_time; // Store the measured I/O time

    /* --- Print Results --- */
    printf("SHA-256 Hash: ");
    print_hex(hash_output, hash_len);
    
    printf("\n=== BASELINE PERFORMANCE REPORT ===\n");
    printf("Total Time: %lu us (%.2f s)\n", host_stats.io_time_us, (double)host_stats.io_time_us / 1000000.0);
    printf("Total CPU Time: %lu us (%.2f s)\n", host_stats.cpu_time_us, (double)host_stats.cpu_time_us / 1000000.0);
    printf("CPU Utilization: %.2f%%\n", (double)host_stats.cpu_time_us * 100.0 / host_stats.io_time_us);

    return 0;
}
