#include <stddef.h>
#include <stdint.h>

#define SYS_write       1
#define SYS_mmap        9
#define SYS_mprotect    10
#define SYS_exit        60

#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define PROT_EXEC       0x4
#define MAP_PRIVATE     0x2
#define MAP_ANONYMOUS   0x20

#define MAP_FAILED      ((void *)-1L)

static __attribute__((noinline)) long
raw_syscall(long nr,
            long a1, long a2, long a3,
            long a4, long a5, long a6)
{
    long ret;
    register long _r10 asm("r10") = a4;
    register long _r8  asm("r8")  = a5;
    register long _r9  asm("r9")  = a6;

    asm volatile (
        "syscall"
        : "=a" (ret)
        : "0"  (nr),
          "D"  (a1),
          "S"  (a2),
          "d"  (a3),
          "r"  (_r10),
          "r"  (_r8),
          "r"  (_r9)
        : "rcx", "r11", "memory"
    );

    return ret;
}

static void *sc_mmap(void *addr, size_t len,
                     int prot, int flags, int fd, long offset)
{
    long r = raw_syscall(SYS_mmap,
                         (long)addr, (long)len, (long)prot,
                         (long)flags, (long)fd, offset);
    return (r < 0) ? MAP_FAILED : (void *)r;
}

static int sc_mprotect(void *addr, size_t len, int prot)
{
    return (int)raw_syscall(SYS_mprotect,
                            (long)addr, (long)len, (long)prot,
                            0, 0, 0);
}

static long sc_write(int fd, const void *buf, size_t count)
{
    return raw_syscall(SYS_write,
                       (long)fd, (long)buf, (long)count,
                       0, 0, 0);
}

static __attribute__((noreturn)) void sc_exit(int code)
{
    raw_syscall(SYS_exit, (long)code, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static const unsigned char g_payload[] = {
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00,
    0x0f, 0x05
};

static int stage_and_execute(const unsigned char *payload, size_t len)
{
    void *region;
    void (*entry)(void);
    size_t i;

    region = sc_mmap(NULL, len,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
    if (region == MAP_FAILED)
        return -1;

    for (i = 0; i < len; i++)
        ((unsigned char *)region)[i] = payload[i];

    if (sc_mprotect(region, len, PROT_READ | PROT_EXEC) < 0)
        return -1;

    entry = (void (*)(void))region;
    entry();

    return 0;
}

void __attribute__((noreturn)) _start(void)
{
    const char banner[] = "[SC-1] executing -- all syscalls direct, no libc\n";
    sc_write(1, banner, sizeof(banner) - 1);

    if (stage_and_execute(g_payload, sizeof(g_payload)) < 0) {
        const char err[] = "[SC-1] staging failed\n";
        sc_write(2, err, sizeof(err) - 1);
        sc_exit(1);
    }

    sc_exit(0);
}
