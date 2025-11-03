#ifndef FTRACE_HELPER_H
#define FTRACE_HELPER_H

#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#define MAX_HOOKS 128

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
extern struct kprobe kp;
#endif

#define HOOK(_name, _hook, _orig) { .name = (_name), .function = (_hook), .original = (_orig), }

#define USE_FENTRY_OFFSET 1
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

struct ftrace_hooks {
    int enabled;
    int hooks;
    struct ftrace_ops ops;
};

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    int slot;
};

// just doing linear scans as we have like 100 hooks at most, and the cpu
// probably likes it nore than anything fancy.
struct table_entry {
    unsigned long ip;
    void *function;
};

int  fh_resolve_hook_address(struct ftrace_hook *hook);
void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                              struct ftrace_ops *ops, struct pt_regs *regs);
int  fh_initialize(void);
void fh_shutdown(void);
int  fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);
int  fh_install_hooks(struct ftrace_hook *hooks, size_t count);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);

unsigned long *resolve_sym(const char *symname);

#endif
