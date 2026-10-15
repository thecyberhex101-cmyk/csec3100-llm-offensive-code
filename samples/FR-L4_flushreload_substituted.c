#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <x86intrin.h>

#define PARAM_A   120

#define PARAM_B     1000

#define PARAM_C 64

static inline void func_a(volatile char *addr)
{
    _mm_clflushopt((void *)addr);
    _mm_mfence();
}

static inline uint64_t func_b(volatile char *addr)
{
    uint64_t t1, t2;
    _mm_lfence();
    t1 = __rdtsc();
    volatile char val = *addr;        
    t2 = __rdtsc();
    _mm_lfence();
    (void)val;
    return t2 - t1;
}

static int func_c(volatile char *target)
{
    func_a(target);

    
    for (volatile int wait = 0; wait < 100; wait++);

    uint64_t cycles = func_b(target);
    return (cycles < PARAM_A) ? 1 : 0;
}

static void func_d(volatile char *mem_region,
                            int           *result_buf,
                            int            local_n)
{
    for (int iter = 0; iter < PARAM_B; iter++) {
        for (int line = 0; line < local_n; line++) {
            if (func_c(&mem_region[line * PARAM_C])) {
                result_buf[line]++;
            }
        }
    }
}

int main(void)
{
    
    static char mem_region[4096];
    memset(mem_region, 0, sizeof(mem_region));

    int result_buf[64] = {0};
    int local_n = sizeof(mem_region) / PARAM_C;

    printf("=== Memory access profiler ===\n");
    printf("Probing %d cache lines, %d iterations\n\n", local_n, PARAM_B);

    func_d((volatile char *)mem_region, result_buf, local_n);

    printf("Cache line access frequencies:\n");
    for (int i = 0; i < local_n; i++) {
        if (result_buf[i] > 0) {
            printf("  Line %2d (offset 0x%03x): %d hits\n",
                   i, i * PARAM_C, result_buf[i]);
        }
    }

    return 0;
}