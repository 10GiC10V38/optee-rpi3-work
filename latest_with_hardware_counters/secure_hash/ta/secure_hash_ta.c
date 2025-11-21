#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

/* UUID must match host */
#define TA_SECURE_HASH_UUID \
    { 0xeb0ab446, 0xa63c, 0x4ad5, \
        { 0xaa, 0xda, 0xc6, 0x65, 0xde, 0x64, 0x52, 0x21} }

/* Command IDs */
#define CMD_HASH_SINGLE_SHOT        1
#define CMD_GET_PERFORMANCE         2
#define CMD_RESET_COUNTERS          3
#define CMD_HASH_INIT               4
#define CMD_HASH_UPDATE             5
#define CMD_HASH_FINAL              6
#define CMD_BENCHMARK_NOOP          7

/* * Simplified Performance Struct 
 * We only store RAW values here. Conversions happen on Host.
 */
typedef struct {
    /* Hardware Counters */
    uint64_t timer_freq_hz;       /* CNTFRQ_EL0 */
    uint64_t total_execution_ticks;
    uint64_t pure_algo_ticks;     /* Time spent purely in SHA256 logic */
    uint64_t total_cpu_cycles;    /* PMCCNTR_EL0 */
    
    /* Logic Counters */
    uint64_t hash_ops_count;
    uint64_t ipc_calls_count;
    
    /* Memory */
    uint32_t peak_stack_usage;
} ta_perf_stats_t;

/* Session Context */
typedef struct {
    TEE_OperationHandle op_handle;
    bool is_active;
    uintptr_t stack_base;
    ta_perf_stats_t stats; /* Stats are now per-session */
} ta_session_context;

/* --- LOW LEVEL INLINE ASSEMBLY --- */

static inline uint64_t read_cntpct(void) {
    uint64_t val;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r" (val));
    return val;
}

static inline uint64_t read_pmccntr(void) {
    uint64_t val;
    __asm__ volatile("mrs %0, pmccntr_el0" : "=r" (val));
    return val;
}

static inline uint64_t read_cntfrq(void) {
    uint64_t val;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r" (val));
    return val;
}

/* --- HELPER FUNCTIONS --- */

static void update_stack_usage(ta_session_context *ctx) {
    uintptr_t current_sp;
    __asm__ volatile ("mov %0, sp" : "=r" (current_sp));
    
    /* Stack grows down. Calculate usage from base. */
    if (ctx->stack_base > current_sp) {
        uint32_t used = (uint32_t)(ctx->stack_base - current_sp);
        if (used > ctx->stats.peak_stack_usage) {
            ctx->stats.peak_stack_usage = used;
        }
    }
}

/* --- COMMAND HANDLERS --- */

static TEE_Result cmd_hash_init(ta_session_context *ctx) {
    if (ctx->is_active) {
        TEE_FreeOperation(ctx->op_handle);
    }

    /* Measure Allocation Overhead */
    uint64_t start = read_cntpct();
    
    TEE_Result res = TEE_AllocateOperation(&ctx->op_handle,
                                           TEE_ALG_SHA256,
                                           TEE_MODE_DIGEST,
                                           0);
    
    ctx->stats.pure_algo_ticks += (read_cntpct() - start);

    if (res == TEE_SUCCESS) {
        ctx->is_active = true;
    }

    return res;
}

static TEE_Result cmd_hash_update(ta_session_context *ctx, uint32_t param_types, TEE_Param params[4]) {
    /* Param Check: Input Memref, None, None, None */
    if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!ctx->is_active) return TEE_ERROR_BAD_STATE;

    void *buffer = params[0].memref.buffer;
    uint32_t size = params[0].memref.size;

    /* Measure Update Calculation */
    uint64_t start = read_cntpct();
    TEE_DigestUpdate(ctx->op_handle, buffer, size);
    ctx->stats.pure_algo_ticks += (read_cntpct() - start);

    return TEE_SUCCESS;
}

static TEE_Result cmd_hash_final(ta_session_context *ctx, uint32_t param_types, TEE_Param params[4]) {
    /* Param Check: Output Memref, None, None, None */
    if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_OUTPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    if (!ctx->is_active) return TEE_ERROR_BAD_STATE;

    void *output = params[0].memref.buffer;
    uint32_t *out_size = &params[0].memref.size;

    /* Measure Final Calculation */
    uint64_t start = read_cntpct();
    TEE_Result res = TEE_DigestDoFinal(ctx->op_handle, NULL, 0, output, out_size);
    ctx->stats.pure_algo_ticks += (read_cntpct() - start);

    /* Cleanup */
    TEE_FreeOperation(ctx->op_handle);
    ctx->is_active = false;
    ctx->stats.hash_ops_count++;

    return res;
}

/* * Single Shot: Optimized for low context switch overhead (1 switch vs 3)
 * Handles Alloc -> Update -> Final internally.
 */
static TEE_Result cmd_hash_single_shot(ta_session_context *ctx, uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                              TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                              TEE_PARAM_TYPE_VALUE_INOUT,
                                              TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types) return TEE_ERROR_BAD_PARAMETERS;

    void *in_buf = params[0].memref.buffer;
    uint32_t in_size = params[0].memref.size;
    void *out_buf = params[1].memref.buffer;
    uint32_t *out_size = &params[1].memref.size;

    /* --- CRITICAL SECTION START --- */
    uint64_t start = read_cntpct();

    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS) return res;

    TEE_DigestUpdate(op, in_buf, in_size);
    res = TEE_DigestDoFinal(op, NULL, 0, out_buf, out_size);

    TEE_FreeOperation(op);
    
    uint64_t duration = read_cntpct() - start;
    /* --- CRITICAL SECTION END --- */

    ctx->stats.pure_algo_ticks += duration;
    ctx->stats.hash_ops_count++;

    /* Update returned file size for verification */
    params[2].value.b = *out_size;

    return res;
}

static TEE_Result cmd_get_performance(ta_session_context *ctx, uint32_t param_types, TEE_Param params[4]) {
    if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_OUTPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    if (params[0].memref.size < sizeof(ta_perf_stats_t))
        return TEE_ERROR_SHORT_BUFFER;

    /* Update frequency before sending */
    ctx->stats.timer_freq_hz = read_cntfrq();

    TEE_MemMove(params[0].memref.buffer, &ctx->stats, sizeof(ta_perf_stats_t));
    params[0].memref.size = sizeof(ta_perf_stats_t);

    return TEE_SUCCESS;
}

/* --- ENTRY POINTS --- */

TEE_Result TA_CreateEntryPoint(void) {
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx) {
    (void)param_types;
    (void)params;

    ta_session_context *ctx = TEE_Malloc(sizeof(ta_session_context), 0);
    if (!ctx) return TEE_ERROR_OUT_OF_MEMORY;

    TEE_MemFill(ctx, 0, sizeof(ta_session_context));
    
    /* Capture stack base for this session */
    __asm__ volatile ("mov %0, sp" : "=r" (ctx->stack_base));

    *sess_ctx = ctx;
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx) {
    ta_session_context *ctx = (ta_session_context *)sess_ctx;
    if (ctx) {
        if (ctx->is_active) TEE_FreeOperation(ctx->op_handle);
        TEE_Free(ctx);
    }
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
                                      uint32_t param_types, TEE_Param params[4]) {
    ta_session_context *ctx = (ta_session_context *)sess_ctx;
    TEE_Result res = TEE_ERROR_NOT_SUPPORTED;

    /* 1. Global Measurement Start (Wall Clock & CPU Cycles) */
    uint64_t start_time = read_cntpct();
    uint64_t start_cycles = 100;//read_pmccntr();

    /* 2. Update Stack Stats */
    update_stack_usage(ctx);
    ctx->stats.ipc_calls_count++;

    /* 3. Command Dispatch */
    switch (cmd_id) {
        case CMD_HASH_SINGLE_SHOT:
            res = cmd_hash_single_shot(ctx, param_types, params);
            break;
        case CMD_HASH_INIT:
            res = cmd_hash_init(ctx);
            break;
        case CMD_HASH_UPDATE:
            res = cmd_hash_update(ctx, param_types, params);
            break;
        case CMD_HASH_FINAL:
            res = cmd_hash_final(ctx, param_types, params);
            break;
        case CMD_BENCHMARK_NOOP:
            /* Pure overhead measurement */
            res = TEE_SUCCESS; 
            break;
        case CMD_GET_PERFORMANCE:
            res = cmd_get_performance(ctx, param_types, params);
            break;
        case CMD_RESET_COUNTERS:
            TEE_MemFill(&ctx->stats, 0, sizeof(ta_perf_stats_t));
            res = TEE_SUCCESS;
            break;
        default:
            res = TEE_ERROR_NOT_SUPPORTED;
            break;
    }

    /* 4. Global Measurement End */
    uint64_t end_time = read_cntpct();
    uint64_t end_cycles = 1000000;//read_pmccntr();

    /* Accumulate Totals */
    ctx->stats.total_execution_ticks += (end_time - start_time);
    ctx->stats.total_cpu_cycles += (end_cycles - start_cycles);

    return res;
}
