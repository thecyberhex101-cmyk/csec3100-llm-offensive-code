#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <x86intrin.h>

#define HIT_THRESHOLD   120

#define PROBE_COUNT     1000

#define CACHE_LINE_SIZE 64

static inline void flush_line(volatile char *addr)
{
    _mm_clflush((void *)addr);
    _mm_mfence();
}

static inline uint64_t measure_access(volatile char *addr)
{
    uint32_t aux;
    uint64_t t1, t2;
    _mm_lfence();
    t1 = __rdtscp(&aux);
    volatile char val = *addr;        
    t2 = __rdtscp(&aux);
    _mm_lfence();
    (void)val;
    return t2 - t1;
}

static int probe_line(volatile char *target)
{
    flush_line(target);

    
    for (volatile int wait = 0; wait < 100; wait++);

    uint64_t cycles = measure_access(target);
    return (cycles < HIT_THRESHOLD) ? 1 : 0;
}

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
    
    static char shared_mem[4096];
    memset(shared_mem, 0, sizeof(shared_mem));

    int results[64] = {0};
    int n_lines = sizeof(shared_mem) / CACHE_LINE_SIZE;

    printf("=== Memory access profiler ===\n");
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