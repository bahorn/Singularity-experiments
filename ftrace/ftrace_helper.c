#include <linux/module.h>
#include "ftrace_helper.h"

struct ftrace_hooks hookm = { .enabled = 0 };
struct table_entry table[MAX_HOOKS];

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
#endif

#ifdef KPROBE_LOOKUP
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_fn = NULL;
#endif

notrace unsigned long *resolve_sym(const char *symname)
{
    if (kallsyms_lookup_name_fn == NULL) {
#ifdef KPROBE_LOOKUP
        register_kprobe(&kp);
        kallsyms_lookup_name_fn = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
#else
        kallsyms_lookup_name_fn = &kallsyms_lookup_name;
#endif
    }
    return (unsigned long *)kallsyms_lookup_name_fn(symname);
}

notrace int fh_resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = (unsigned long)resolve_sym(hook->name);

    if (!hook->address) {
        pr_debug("ftrace_helper: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }
#if USE_FENTRY_OFFSET
    *((unsigned long *)hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long *)hook->original) = hook->address;
#endif
    return 0;
}

void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                             struct ftrace_ops *ops, struct pt_regs *regs)
{
    int i = 0;
    void *function = NULL;
    for (i = 0; i < MAX_HOOKS; i++) {
        if (table[i].ip == ip) {
            function = table[i].function;
            goto found;
        }
    }
    goto fail;
found:
#if USE_FENTRY_OFFSET
    regs->ip = (unsigned long)function;
#else
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)function;
#endif
fail:
}

notrace int fh_initialize(void)
{
    int err = 0;
    hookm.hooks = 0;
    hookm.ops.func  = (ftrace_func_t)fh_ftrace_thunk;
    hookm.ops.flags = FTRACE_OPS_FL_SAVE_REGS |
                      FTRACE_OPS_FL_RECURSION |
                      FTRACE_OPS_FL_IPMODIFY;
    ftrace_set_filter(&(hookm.ops), "kallsyms_lookup_name", strlen("kallsyms_lookup_name"), 1);
    err = register_ftrace_function(&(hookm.ops));
    if (err)
        pr_debug("ftrace_helper: register_ftrace_function() failed: %d\n", err);

    if (err == 0)
        hookm.enabled = 1;

    return err;
}

notrace void fh_shutdown(void)
{
    if (hookm.enabled != 1) return;
    if (hookm.hooks > 0) {
        pr_debug("still have %i hook(s) enabled\n", hookm.hooks);
    }
    // we should have no hooks registered with us anymore.
    unregister_ftrace_function(&(hookm.ops));
}

notrace int fh_install_hook(struct ftrace_hook *hook)
{
    int err = 0;
    if (hookm.enabled != 1)
        return -1;

    err = fh_resolve_hook_address(hook);
    if (err) return err;

    // find the first free slot
    hook->slot = -1;
    for (int i = 0; i < MAX_HOOKS; i++) {
        if (table[i].ip == hook->address)
            pr_debug("Multiple hooks on the same function!\n");
        if (table[i].ip == 0 && hook->slot == -1) {
            hook->slot = i;
            table[i].ip = hook->address;
            table[i].function = hook->function;
        }
    }

    if (hook->slot == -1)
        return -1;

    err = ftrace_set_filter_ip(&(hookm.ops), hook->address, 0, 0);
    if (err) {
        pr_debug("ftrace_helper: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    hookm.hooks++;

    return err;
}

notrace void fh_remove_hook(struct ftrace_hook *hook)
{
    if (hookm.enabled != 1) return;
    int err = ftrace_set_filter_ip(&(hookm.ops), hook->address, 1, 0);
    if (err) {
        pr_debug("ftrace_helper: ftrace_set_filter_ip() failed: %d\n", err);
        return;
    }

    if (hook->slot != -1)
        table[hook->slot].ip = 0;

    hookm.hooks--;
}

notrace int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;
    int err;
    for (i = 0; i < count; i++) {
        err = fh_install_hook(&hooks[i]);
        if (err) goto error;
    }
    return 0;
error:
    while (i--)
        fh_remove_hook(&hooks[i]);
    return err;
}

notrace void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++)
        fh_remove_hook(&hooks[i]);
}
