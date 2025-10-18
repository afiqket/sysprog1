#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/proc_fs.h> 
#include <linux/seq_file.h>


static int hello_show(struct seq_file *m, void *v) {
    seq_printf(m, "Hello, Kernel!\n");
    return 0;
}


static int hello_open(struct inode *inode, struct file *file) {
    return single_open(file, hello_show, NULL);
}


static const struct proc_ops hello_proc_ops = {
    .proc_open    = hello_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};


static int __init hello_init(void) {
    proc_create("hello", 0, NULL, &hello_proc_ops);
    pr_info("Hello module loaded, /proc/hello created.\n");
    return 0;
}


static void __exit hello_exit(void) {
    remove_proc_entry("hello", NULL);
    pr_info("Hello module unloaded, /proc/hello removed.\n");
}


module_init(hello_init);
module_exit(hello_exit);


MODULE_LICENSE("GPL");
