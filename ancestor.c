#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>

static struct proc_dir_entry *ancestor_entry;
static pid_t stored_pid = -1;
static DEFINE_MUTEX(pid_lock); // Mutex lock (use PID as lock number)

// Print ID and name
static void print_header(struct seq_file *m)
{
    seq_printf(m, "ID: 2023148089\n", MY_ID);
    seq_printf(m, "Name: Muhammad Afiq Aiman bin Affandi\n", MY_NAME);
    seq_printf(m, "----------------------------------------\n");
}

// Print ancestors PID and names
static int ancestor_show(struct seq_file *m, void *v)
{
    pid_t pid_local;
    struct task_struct *t;

    // Copy the PID under lock to avoid races with writer
    mutex_lock(&pid_lock);
    pid_local = stored_pid;
    mutex_unlock(&pid_lock);

    // Print ID and name
    print_header(m);

    // PID error
    if (pid_local <= 0) {
        return 0;
    }

    rcu_read_lock(); // Lock for read
    t = pid_task(find_vpid(pid_local), PIDTYPE_PID);
    if (!t) {
        rcu_read_unlock();
        return 0; /* nonexistent PID: print only header */
    }

    // Iterate real parents up to init
    for (;;) {
        seq_printf(m, "[%d] %s\n", t->pid, t->comm);
        if (t->pid == 1) // Break when found init
            break;
        t = rcu_dereference(t->real_parent);
    }
    rcu_read_unlock(); // Unlock read lock

    return 0;
}

// When proc is read
static int ancestor_open(struct inode *inode, struct file *file)
{
    return single_open(file, ancestor_show, NULL);
}

// When proc is written to, eg. using
// echo <PID> > /proc/ancestor
static ssize_t ancestor_write(struct file *file,
                  const char __user *ubuf,
                  size_t len, loff_t *ppos)
{
    char kbuf[32]; // Byte buffer
    long val;
    size_t n = min(len, sizeof(kbuf) - 1);

    if (copy_from_user(kbuf, ubuf, n))
        return -EFAULT;
    kbuf[n] = '\0';

    // Accept decimal PID with surrounding whitespace/newline */
    if (kstrtol(kbuf, 10, &val))
        return -EINVAL;
    if (val <= 0)
        return -EINVAL;

    // Lock when copying pid
    mutex_lock(&pid_lock);
    stored_pid = (pid_t)val;
    mutex_unlock(&pid_lock);

    // Report number of bytes consumed so that echo doesn't retry
    return len;
}

// Proc ops struct
static const struct proc_ops ancestor_ops = {
    .proc_open    = ancestor_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = ancestor_write,   // Make proc writable
};

// Initialize proc
static int __init ancestor_init(void)
{
    ancestor_entry = proc_create("ancestor", 0666, NULL, &ancestor_ops);
    if (!ancestor_entry)
        return -ENOMEM;

    pr_info("ancestor: /proc/ancestor created\n");
    return 0;
}

// Exit proc
static void __exit ancestor_exit(void)
{
    proc_remove(ancestor_entry);
    pr_info("ancestor: /proc/ancestor removed\n");
}

module_init(ancestor_init);
module_exit(ancestor_exit);

MODULE_LICENSE("GPL");
