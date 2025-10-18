#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/proc_fs.h> 
#include <linux/seq_file.h>

static int ancestor_show(struct seq_file *m, void *v) {
    seq_printf(m, "ID: 2023148089Xxx\n");
    seq_printf(m, "Name: Muhammad Afiq Aiman bin Affandi\n");
    seq_printf(m, "----------------------------------------\n");
    return 0;
}

static int ancestor_open(struct inode *inode, struct file *file) {
    return single_open(file, ancestor_show, NULL);
}

#define PROCFS_MAX_SIZE 1024
static char procfs_buffer[PROCFS_MAX_SIZE];  
static unsigned long procfs_buffer_size = 0;

static ssize_t ancestor_write(struct file *file, const char __user *buff,
                              size_t len, loff_t *off)  
{  
    procfs_buffer_size = len;
 
    if (procfs_buffer_size >= PROCFS_MAX_SIZE)  
        procfs_buffer_size = PROCFS_MAX_SIZE - 1;
 
    if (copy_from_user(procfs_buffer, buff, procfs_buffer_size))
        return -EFAULT;

    procfs_buffer[procfs_buffer_size] = '\0';  
    *off += procfs_buffer_size;
 
    pr_info("ancestor write %s\n", procfs_buffer);  
 
    return procfs_buffer_size;
}  

static const struct proc_ops ancestor_proc_ops = {
    .proc_open    = ancestor_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = ancestor_write,
};

static int __init ancestor_init(void) {
    proc_create("ancestor", 0666, NULL, &ancestor_proc_ops);
    pr_info("ancestor module loaded, /proc/ancestor created.\n");
    return 0;
}

static void __exit ancestor_exit(void) {
    remove_proc_entry("ancestor", NULL);
    pr_info("ancestor module unloaded, /proc/ancestor removed.\n");
}

module_init(ancestor_init);
module_exit(ancestor_exit);

MODULE_LICENSE("GPL");
