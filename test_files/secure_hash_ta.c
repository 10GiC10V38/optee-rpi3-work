#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

/* UUID for this TA - must match host application */
#define TA_SECURE_HASH_UUID \
    { 0xeb0ab446, 0xa63c, 0x4ad5, \
        { 0xaa, 0xda, 0xc6, 0x65, 0xde, 0x64, 0x52, 0x21} }

/* Command IDs */
#define CMD_HASH_FILE_SINGLE_SHOT   1 // Original single-shot hash command
#define CMD_GET_PERFORMANCE         2
#define CMD_RESET_COUNTERS          3
#define CMD_HASH_INIT               4 // New command to start a hash operation
#define CMD_HASH_UPDATE             5 // New command to update with a chunk
#define CMD_HASH_FINAL              6 // New command to finalize and get the hash
#define CMD_BENCHMARK_NOOP          7 // New command for baseline overhead

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
    uint64_t total_tee_execution_time; /* Total time spent in TEE */
} performance_stats_t;

/* Session Context for Streaming Hash */
typedef struct {
    TEE_OperationHandle hash_op_handle; // Handle for the hash operation
    bool is_op_active;                  // Flag to check if an operation is in progress
    uint32_t session_stack_base;        // Stack base for this session
    uint64_t session_start_time;        // Session start time
    uint64_t total_bytes_processed;     // Total bytes processed in this session
} ta_session_context;

/* Global performance counters */
static performance_stats_t g_perf_stats = {0};
static uint32_t g_stack_base = 0;
static uint32_t g_max_stack_usage = 0;



/* Reads the ARM Generic Timer's frequency register */
static inline uint64_t read_timer_frequency(void)
{
    uint64_t freq;
    /* Read CNTFRQ_EL0 */
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r" (freq));
    return freq;
}



/* Reads the ARM Generic Timer's physical count register */
static inline uint64_t read_timer_ticks(void)
{
    uint64_t val;
    /* Read CNTPCT_EL0 */
    __asm__ volatile("mrs %0, cntpct_el0" : "=r" (val));
    return val;
}

/* Helper to convert ticks to nanoseconds */
static uint64_t ticks_to_ns(uint64_t ticks)
{
    static uint64_t freq = 0;
    if (freq == 0) {
        freq = read_timer_frequency();
        if (freq == 0) {
            EMSG("Timer frequency is 0!");
            return 0;
        }
    }
    
    /* * Perform calculation in 128-bit to avoid overflow before division
     * (ticks * 1,000,000,000) / freq
     */
    unsigned __int128 ticks_128 = (unsigned __int128)ticks;
    unsigned __int128 ns_128 = (ticks_128 * 1000000000ULL) / freq;
    
    return (uint64_t)ns_128;
}



/* Enhanced utility functions */
static uint64_t get_precise_time_ns(void) {
    TEE_Time time;
    TEE_GetSystemTime(&time);
    return (uint64_t)time.seconds * 1000000000UL + 
           (uint64_t)time.millis * 1000000UL;
}

static void update_stack_usage(void) {
    uint32_t current_sp;
    __asm__ volatile ("mov %0, sp" : "=r" (current_sp));
    
    if (g_stack_base == 0) {
        g_stack_base = current_sp;
    }
    
    uint32_t stack_used = g_stack_base - current_sp;
    if (stack_used > g_perf_stats.tee_stack_usage) {
        g_perf_stats.tee_stack_usage = stack_used;
        g_max_stack_usage = stack_used;
    }
}

static void update_session_stack_usage(ta_session_context *ctx) {
    uint32_t current_sp;
    __asm__ volatile ("mov %0, sp" : "=r" (current_sp));
    
    if (ctx->session_stack_base == 0) {
        ctx->session_stack_base = current_sp;
    }
    
    uint32_t session_stack_used = ctx->session_stack_base - current_sp;
    if (session_stack_used > g_perf_stats.tee_stack_usage) {
        g_perf_stats.tee_stack_usage = session_stack_used;
    }
}

static void increment_storage_access(void) {
    g_perf_stats.secure_storage_access++;
}

static void increment_rpc_count(void) {
    g_perf_stats.rpc_count++;
}

static void increment_ipc_count(void) {
    g_perf_stats.ipc_calls++;
}

static void increment_hash_operations(void) {
    g_perf_stats.hash_operations++;
}

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

/* Enhanced memory usage tracking */
static void log_memory_checkpoint(const char* operation) {
    update_stack_usage();
 //   DMSG("Memory checkpoint [%s]: Stack usage = %lu bytes", 
 //        operation, g_perf_stats.tee_stack_usage);
}

/* for testing with basic functionality */
static TEE_Result benchmark_noop(void) {
   // g_perf_stats.ipc_calls++; // Still count it as an IPC call
    return TEE_SUCCESS;
}


/*
 * STREAMING HASH FUNCTIONS
 */

/* Function for CMD_HASH_INIT */
static TEE_Result hash_init(ta_session_context *ctx)
{
  //  log_memory_checkpoint("hash_init_start");
    
    if (ctx->is_op_active) {
        TEE_FreeOperation(ctx->hash_op_handle);
  //      DMSG("Freed previous operation handle");
    }

    TEE_Result res = TEE_AllocateOperation(&ctx->hash_op_handle,
                                         TEE_ALG_SHA256,
                                         TEE_MODE_DIGEST,
                                         0);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate digest operation: 0x%x", res);
        ctx->is_op_active = false;
        return res;
    }

    ctx->is_op_active = true;
    ctx->total_bytes_processed = 0;
    ctx->session_start_time = get_tee_time_us();
    
    increment_hash_operations(); // Count this as a hash-related op
    increment_ipc_count();
    update_session_stack_usage(ctx);
    
    // Record start times for streaming operation
    g_perf_stats.tee_time_start = get_tee_time_us();
    g_perf_stats.ree_time_start = get_ree_time_us();
    
 //   log_memory_checkpoint("hash_init_end");
 //   DMSG("Stream hash operation initialized. TEE start time: %lu us", 
 //        g_perf_stats.tee_time_start);
    return TEE_SUCCESS;
}

/* Function for CMD_HASH_UPDATE */
static TEE_Result hash_update(ta_session_context *ctx, uint32_t param_types,
                              TEE_Param params[4])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                              TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!ctx->is_op_active)
        return TEE_ERROR_BAD_STATE;

    uint8_t *data_chunk = (uint8_t *)params[0].memref.buffer;
    uint32_t chunk_size = params[0].memref.size;

    if (!data_chunk || chunk_size == 0) {
        EMSG("Invalid chunk data");
        return TEE_ERROR_BAD_PARAMETERS;
    }

  //  log_memory_checkpoint("hash_update_start");
    increment_ipc_count();
    update_session_stack_usage(ctx);
    
    uint64_t update_start = get_precise_time_ns();
    TEE_DigestUpdate(ctx->hash_op_handle, data_chunk, chunk_size);
    uint64_t update_time = get_precise_time_ns() - update_start;
    
    g_perf_stats.hash_compute_time += update_time;
    ctx->total_bytes_processed += chunk_size;
    
    log_memory_checkpoint("hash_update_end");
 //   DMSG("Updated stream hash with %u bytes. Total processed: %lu bytes. Update time: %lu ns", 
 //        chunk_size, ctx->total_bytes_processed, update_time);
    return TEE_SUCCESS;
}

/* Function for CMD_HASH_FINAL */
static TEE_Result hash_final(ta_session_context *ctx, uint32_t param_types,
                             TEE_Param params[4])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                              TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE,
                                              TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!ctx->is_op_active)
        return TEE_ERROR_BAD_STATE;

    uint8_t *hash_output = (uint8_t *)params[0].memref.buffer;
    uint32_t hash_output_size = params[0].memref.size;
    uint32_t digest_size = 32; /* For SHA-256 */

    if (hash_output_size < digest_size)
        return TEE_ERROR_SHORT_BUFFER;

 //   log_memory_checkpoint("hash_final_start");
    increment_ipc_count();
    update_session_stack_usage(ctx);
    
    uint64_t final_start = get_precise_time_ns();
    TEE_Result res = TEE_DigestDoFinal(ctx->hash_op_handle, NULL, 0,
                                       hash_output, &digest_size);
    uint64_t final_time = get_precise_time_ns() - final_start;
    
    g_perf_stats.hash_compute_time += final_time;

    // Record end times
    g_perf_stats.tee_time_end = get_tee_time_us();
    g_perf_stats.ree_time_end = get_ree_time_us();

    uint64_t total_session_time = g_perf_stats.tee_time_end - ctx->session_start_time;
    
    log_memory_checkpoint("hash_final_before_cleanup");

    // Clean up for the next operation
    TEE_FreeOperation(ctx->hash_op_handle);
    ctx->is_op_active = false;
    ctx->hash_op_handle = TEE_HANDLE_NULL;

    if (res == TEE_SUCCESS) {
        params[0].memref.size = digest_size;
        increment_storage_access(); // Log for audit trail
        
 //       log_memory_checkpoint("hash_final_end");
 //      IMSG("Streaming hash computed successfully.");
        
  /*      IMSG("Enhanced timing details:");
        IMSG("  Total TEE session time: %lu us", total_session_time);
        IMSG("  Hash finalization time: %lu ns", final_time);
        IMSG("  Total hash compute time: %lu us", g_perf_stats.hash_compute_time/1000);
        IMSG("  Total bytes processed: %lu", ctx->total_bytes_processed);
        IMSG("  Peak stack usage: %lu bytes", g_perf_stats.tee_stack_usage);
        IMSG("  REE time delta: %lu us", g_perf_stats.ree_time_end - g_perf_stats.ree_time_start);  */
    }

    return res;
}
/* Original single-shot hash function - enhanced with new high-precision timers */
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

    /* --- Timer variables --- */
    uint64_t total_start_ticks, total_end_ticks;
    uint64_t alloc_start_ticks, alloc_ticks;
    uint64_t update_start_ticks, update_ticks;
    uint64_t final_start_ticks, final_ticks;

    /* Check parameters */
    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Record start time using high-precision timer */
    total_start_ticks = read_timer_ticks();

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

    log_memory_checkpoint("before_allocation");

    /* Allocate digest operation */
    alloc_start_ticks = read_timer_ticks();
    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    alloc_ticks = read_timer_ticks() - alloc_start_ticks;
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate digest operation: 0x%x", res);
        return res;
    }

    /* Perform hash computation */
    update_start_ticks = read_timer_ticks();
    TEE_DigestUpdate(op, input_data, input_size);
    update_ticks = read_timer_ticks() - update_start_ticks;

    /* Finalize hash */
    final_start_ticks = read_timer_ticks();
    res = TEE_DigestDoFinal(op, NULL, 0, hash_output, &digest_size);
    final_ticks = read_timer_ticks() - final_start_ticks;
    
    if (res != TEE_SUCCESS) {
        EMSG("Failed to finalize digest: 0x%x", res);
        TEE_FreeOperation(op);
        return res;
    }

    /* Record end time */
    total_end_ticks = read_timer_ticks();

    /* --- Calculate and store performance stats in NANOSECONDS --- */
    
    /* 1. Calculate pure hash computation time */
    uint64_t total_hash_ticks = alloc_ticks + update_ticks + final_ticks;
    g_perf_stats.hash_compute_time = ticks_to_ns(total_hash_ticks); // Stored in ns

    /* 2. Calculate total time spent in this TA function call */
    uint64_t total_secure_ticks = total_end_ticks - total_start_ticks;
    uint64_t total_secure_time_ns = ticks_to_ns(total_secure_ticks);

    /* 3. Store total TEE execution time (optional, but good practice) */
    /* Note: Your TA_InvokeCommandEntryPoint already tracks this, but 
       this is the high-precision value for this *specific* command.
       You might want to add a new field to g_perf_stats for this.
       For now, I'll just use it to calculate overhead.
    */

    /* 4. Calculate overhead (in nanoseconds) */
    uint64_t overhead_time_ns = (total_secure_time_ns > g_perf_stats.hash_compute_time) ?
                                (total_secure_time_ns - g_perf_stats.hash_compute_time) : 0;
    


    /* Update output parameters */
    params[1].memref.size = digest_size;
    params[2].value.b = digest_size;

    /* Update performance counters */
    increment_hash_operations();
    update_stack_usage();
    increment_storage_access();

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

    /* Final stack usage update */
    update_stack_usage();
    increment_rpc_count(); /* This is an RPC call to get stats */

    /* Copy performance statistics */
    TEE_MemMove(params[0].memref.buffer, &g_perf_stats, 
                sizeof(performance_stats_t));
    params[0].memref.size = sizeof(performance_stats_t);

/*    IMSG("Performance stats retrieved:");
    IMSG("  IPC calls: %lu", g_perf_stats.ipc_calls);
    IMSG("  RPC count: %lu", g_perf_stats.rpc_count);
    IMSG("  Hash operations: %lu", g_perf_stats.hash_operations);
    IMSG("  Peak stack usage: %lu bytes", g_perf_stats.tee_stack_usage);
    IMSG("  Total hash compute time: %lu us", g_perf_stats.hash_compute_time/1000);  */

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
    g_max_stack_usage = 0;
    
 //   IMSG("Performance counters reset");
    return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is created
 */
TEE_Result TA_CreateEntryPoint(void) {
//  DMSG("Secure Hash TA: Creating entry point with enhanced monitoring");
    
    /* Initialize performance counters */
    TEE_MemFill(&g_perf_stats, 0, sizeof(performance_stats_t));
    g_max_stack_usage = 0;
    
    /* Initialize stack base */
    __asm__ volatile ("mov %0, sp" : "=r" (g_stack_base));
    
    IMSG("TA initialized with stack base at: 0x%x", g_stack_base);
    return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed
 */
void TA_DestroyEntryPoint(void) {
/*    DMSG("Secure Hash TA: Destroying entry point");
    IMSG("Final stats - Max stack usage: %u bytes, Total hash ops: %lu", 
         g_max_stack_usage, g_perf_stats.hash_operations); */
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

//    DMSG("Secure Hash TA: Opening session with enhanced tracking");

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Allocate session context */
    ta_session_context *ctx = TEE_Malloc(sizeof(ta_session_context), 0);
    if (!ctx)
        return TEE_ERROR_OUT_OF_MEMORY;

    ctx->hash_op_handle = TEE_HANDLE_NULL;
    ctx->is_op_active = false;
    ctx->session_stack_base = 0;
    ctx->session_start_time = get_tee_time_us();
    ctx->total_bytes_processed = 0;

    *sess_ctx = ctx;

    /* Initialize session stack base */
    __asm__ volatile ("mov %0, sp" : "=r" (ctx->session_stack_base));
    
//    IMSG("Secure Hash TA session opened successfully");
//    IMSG("Session context allocated at: %p", ctx);
//    IMSG("Session stack base: 0x%x", ctx->session_stack_base);
    return TEE_SUCCESS;
}

/*
 * Called when a session is closed
 */
void TA_CloseSessionEntryPoint(void *sess_ctx) {
    ta_session_context *ctx = (ta_session_context *)sess_ctx;

    if (ctx) {
        uint64_t session_duration = get_tee_time_us() - ctx->session_start_time;
        
  /*      IMSG("Session closing stats:");
        IMSG("  Session duration: %lu us", session_duration);
        IMSG("  Total bytes processed: %lu", ctx->total_bytes_processed);
        IMSG("  Operation active: %s", ctx->is_op_active ? "Yes" : "No"); */
        
        if (ctx->is_op_active) {
     //       DMSG("Cleaning up active hash operation");
            TEE_FreeOperation(ctx->hash_op_handle);
        }
        TEE_Free(ctx);
    }

 //   IMSG("Secure Hash TA session closed");
}

/*
 * Called when a TA is invoked
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                     uint32_t cmd_id,
                                     uint32_t param_types,
                                     TEE_Param params[4]) {
    ta_session_context *ctx = (ta_session_context *)sess_ctx;
    TEE_Result res; //
    
    uint64_t command_start_time = get_tee_time_us();

    /* Update stack usage on every command */
    if (ctx) {
        update_session_stack_usage(ctx);
    } else {
        update_stack_usage();
    }

    switch (cmd_id) {
    case CMD_HASH_INIT:
  //      DMSG("Secure Hash TA: Initializing streaming hash");
        res = hash_init(ctx); // 2. Assign the result to 'res'
        break; // 3. Use 'break' to exit the switch
        
    case CMD_HASH_UPDATE:
  //      DMSG("Secure Hash TA: Updating hash with chunk");
        res = hash_update(ctx, param_types, params);
        break;
        
    case CMD_HASH_FINAL:
 //       DMSG("Secure Hash TA: Finalizing hash");
        res = hash_final(ctx, param_types, params);
        break;
        
    case CMD_HASH_FILE_SINGLE_SHOT:
  //    DMSG("Secure Hash TA: Computing single-shot hash");
        res = compute_secure_hash(param_types, params);
        break;
        
    case CMD_GET_PERFORMANCE:
  //    DMSG("Secure Hash TA: Getting performance stats");
        res = get_performance_stats(param_types, params);
        break;
        
    case CMD_RESET_COUNTERS:
  //    DMSG("Secure Hash TA: Resetting performance counters");
        res = reset_performance_counters(param_types, params);
        break;
        
    case CMD_BENCHMARK_NOOP:
  //    DMSG("Calling basic functionality");
        res = benchmark_noop();
        break;
        
    default:
  //      EMSG("Command ID 0x%x is not supported", cmd_id);
        res = TEE_ERROR_NOT_SUPPORTED;
        break;
    }

    // 4. This code now runs for every command before exiting
    uint64_t command_end_time = get_tee_time_us();
    g_perf_stats.total_tee_execution_time += (command_end_time - command_start_time);
    
    return res; // 5. Return the stored result at the very end
}
