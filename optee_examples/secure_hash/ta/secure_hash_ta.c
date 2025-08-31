#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

/* UUID for this TA - must match host application */
#define TA_SECURE_HASH_UUID \
    { 0xeb0ab446, 0xa63c, 0x4ad5, \
        { 0xaa, 0xda, 0xc6, 0x65, 0xde, 0x64, 0x52, 0x21} }

/* Command IDs */
#define CMD_HASH_FILE           1
#define CMD_GET_PERFORMANCE     2
#define CMD_RESET_COUNTERS      3

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
    /* NEW TIMING FIELDS */
    uint64_t tee_time_start;      /* TEE system time when started */
    uint64_t tee_time_end;        /* TEE system time when finished */
    uint64_t ree_time_start;      /* REE time when started */
    uint64_t ree_time_end;        /* REE time when finished */
    uint64_t hash_compute_time;   /* Time spent in actual hash computation */
    uint64_t wait_time_total;     /* Total wait time if any */
    uint64_t io_read_time_us;
} performance_stats_t;



static uint64_t get_precise_time_ns(void) {
    TEE_Time time;
    TEE_GetSystemTime(&time);
    return (uint64_t)time.seconds * 1000000000UL + 
           (uint64_t)time.millis * 1000000UL;
}

/* Global performance counters */
static performance_stats_t g_perf_stats = {0};
static uint32_t g_stack_base = 0;

/* Stack usage monitoring */
static void update_stack_usage(void) {
    uint32_t current_sp;
    
    /* Get current stack pointer (ARM-specific) */
    __asm__ volatile ("mov %0, sp" : "=r" (current_sp));
    
    if (g_stack_base == 0) {
        g_stack_base = current_sp;
    }
    
    uint32_t stack_used = g_stack_base - current_sp;
    if (stack_used > g_perf_stats.tee_stack_usage) {
        g_perf_stats.tee_stack_usage = stack_used;
    }
}

/* Secure storage access counter */
static void increment_storage_access(void) {
    g_perf_stats.secure_storage_access++;
}

/* RPC counter */
static void increment_rpc_count(void) {
    g_perf_stats.rpc_count++;
}

/* IPC counter */
static void increment_ipc_count(void) {
    g_perf_stats.ipc_calls++;
}

/* Hash operation counter */
static void increment_hash_operations(void) {
    g_perf_stats.hash_operations++;
}

/* Enhanced timing functions */
static uint64_t get_tee_time_us(void) {
    TEE_Time time;
    TEE_GetSystemTime(&time);
    return (uint64_t)time.seconds * 1000000UL + time.millis * 1000UL;
}

static uint64_t get_ree_time_us(void) {
    TEE_Time time;
    TEE_GetREETime(&time);  
    return (uint64_t)time.seconds * 1000000UL + time.millis * 1000UL;
}

/* Enhanced compute_secure_hash function with detailed timing */
static TEE_Result compute_secure_hash(uint32_t param_types,
                                     TEE_Param params[4]) {
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                              TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                              TEE_PARAM_TYPE_VALUE_INOUT,
                                              TEE_PARAM_TYPE_NONE);
    uint8_t *input_data;
    uint32_t input_size;
    uint8_t *hash_output;
    uint32_t hash_output_size;
    uint32_t digest_size = 32; /* SHA-256 */
    uint64_t hash_start_time, hash_end_time;

    /* Check parameters */
    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* ENHANCED TIMING: Record start times */
    g_perf_stats.tee_time_start = get_tee_time_us();
    g_perf_stats.ree_time_start = get_ree_time_us();

    /* Update performance counters */
    increment_ipc_count();
    update_stack_usage();

    /* Get input parameters */
    input_data = (uint8_t *)params[0].memref.buffer;
    input_size = params[0].memref.size;
    hash_output = (uint8_t *)params[1].memref.buffer;
    hash_output_size = params[1].memref.size;

    /* Validate input */
    if (!input_data || input_size == 0) {
        EMSG("Invalid input data");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (!hash_output || hash_output_size < digest_size) {
        EMSG("Invalid output buffer (need at least %u bytes)", digest_size);
        return TEE_ERROR_SHORT_BUFFER;
    }

    IMSG("Computing hash for %u bytes", input_size);

    /* Allocate digest operation */
    uint64_t alloc_start = get_precise_time_ns();
    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    uint64_t alloc_time = get_precise_time_ns() - alloc_start;
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate digest operation: 0x%x", res);
        return res;
    }

    /* ENHANCED TIMING: Record hash computation start */


    /* Perform hash computation */
    uint64_t update_start = get_precise_time_ns();
    TEE_DigestUpdate(op, input_data, input_size);
    uint64_t update_time = get_precise_time_ns() - update_start;

    uint64_t final_start = get_precise_time_ns();
    res = TEE_DigestDoFinal(op, NULL, 0, hash_output, &digest_size);
    uint64_t final_time = get_precise_time_ns() - final_start;
    
    if (res != TEE_SUCCESS) {
        EMSG("Failed to finalize digest: 0x%x", res);
        TEE_FreeOperation(op);
        return res;
    }

    /* ENHANCED TIMING: Record hash computation end */

    g_perf_stats.hash_compute_time = (alloc_time + update_time + final_time); // Convert to μs

    /* Optional: Add some wait time for testing (remove in production) */
    /* TEE_Wait(1000); // Wait 1ms for demonstration */
    /* g_perf_stats.wait_time_total += 1000; */

    /* ENHANCED TIMING: Record end times */
    g_perf_stats.tee_time_end = get_tee_time_us();
    g_perf_stats.ree_time_end = get_ree_time_us();

    /* Update output parameters */
    params[1].memref.size = digest_size;
    params[2].value.b = digest_size;

    /* Update performance counters */
    increment_hash_operations();
    update_stack_usage();

    /* Log hash for audit trail (secure storage access) */
    increment_storage_access();
    IMSG("Hash computed successfully: %u bytes -> %u bytes (took %lu μs)", 
         input_size, digest_size, g_perf_stats.hash_compute_time/1000);

    /* ENHANCED TIMING: Log detailed timing */
    IMSG("Timing details - Total TEE time: %lu μs, Hash compute: %lu μs, REE time delta: %lu μs",
         g_perf_stats.tee_time_end - g_perf_stats.tee_time_start,
         g_perf_stats.hash_compute_time/1000,
         g_perf_stats.ree_time_end - g_perf_stats.ree_time_start);

    TEE_FreeOperation(op);
    return TEE_SUCCESS;
}

/*
 * Get performance statistics
 */
static TEE_Result get_performance_stats(uint32_t param_types,
                                       TEE_Param params[4]) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                              TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE);
    
    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[0].memref.size < sizeof(performance_stats_t)) {
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Update final stack usage */
    update_stack_usage();
    increment_rpc_count(); /* This is an RPC call to get stats */

    /* Copy performance statistics */
    TEE_MemMove(params[0].memref.buffer, &g_perf_stats, 
                sizeof(performance_stats_t));
    params[0].memref.size = sizeof(performance_stats_t);

    IMSG("Performance stats retrieved - IPC: %lu, RPC: %lu, Hash ops: %lu",
         g_perf_stats.ipc_calls, g_perf_stats.rpc_count, 
         g_perf_stats.hash_operations);

    return TEE_SUCCESS;
}

/*
 * Reset performance counters
 */
static TEE_Result reset_performance_counters(uint32_t param_types,
                                           TEE_Param params[4]) {
    (void)param_types;
    (void)params;
    
    TEE_MemFill(&g_perf_stats, 0, sizeof(performance_stats_t));
    g_stack_base = 0;
    
    IMSG("Performance counters reset");
    return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is created
 */
TEE_Result TA_CreateEntryPoint(void) {
    DMSG("Secure Hash TA: Creating entry point");
    
    /* Initialize performance counters */
    TEE_MemFill(&g_perf_stats, 0, sizeof(performance_stats_t));
    
    return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed
 */
void TA_DestroyEntryPoint(void) {
    DMSG("Secure Hash TA: Destroying entry point");
}

/*
 * Called when a new session is opened to the TA
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                   TEE_Param params[4],
                                   void **sess_ctx) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE);

    DMSG("Secure Hash TA: Opening session");

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Session context not used */
    (void)sess_ctx;
    (void)params;

    /* Initialize stack base for this session */
    __asm__ volatile ("mov %0, sp" : "=r" (g_stack_base));
    
    IMSG("Secure Hash TA session opened successfully");
    return TEE_SUCCESS;
}

/*
 * Called when a session is closed
 */
void TA_CloseSessionEntryPoint(void *sess_ctx) {
    (void)sess_ctx;
    IMSG("Secure Hash TA session closed");
}

/*
 * Called when a TA is invoked
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                     uint32_t cmd_id,
                                     uint32_t param_types,
                                     TEE_Param params[4]) {
    (void)sess_ctx;
    
    /* Update stack usage on every command */
    update_stack_usage();

    switch (cmd_id) {
    case CMD_HASH_FILE:
        DMSG("Secure Hash TA: Computing hash");
        return compute_secure_hash(param_types, params);
        
    case CMD_GET_PERFORMANCE:
        DMSG("Secure Hash TA: Getting performance stats");
        return get_performance_stats(param_types, params);
        
    case CMD_RESET_COUNTERS:
        DMSG("Secure Hash TA: Resetting performance counters");
        return reset_performance_counters(param_types, params);
        
    default:
        EMSG("Command ID 0x%x is not supported", cmd_id);
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
