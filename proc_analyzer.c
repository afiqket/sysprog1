// File: proc_analyzer.c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/cpumask.h>


#define MY_ID   "2025123456"       /* <-- change to your ID */
#define MY_NAME "Hong, Gildong"    /* <-- change to your Name */


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("CFS runqueue analyzer for a PID and its descendants");


/* ---------- state ---------- */
static struct proc_dir_entry *proc_entry;
static DEFINE_MUTEX(pid_lock);
static pid_t stored_pid = -1;


/* ---------- record & per-CPU buckets ---------- */
struct proc_rec {
	pid_t           pid;
	char            comm[TASK_COMM_LEN];
	u64             vruntime;
};


struct cpu_bucket {
	struct proc_rec *arr;
	size_t           size;
	size_t           cap;
};


static int rec_cmp_by_vruntime(const void *a, const void *b)
{
	const struct proc_rec *ra = a, *rb = b;
	if (ra->vruntime < rb->vruntime) return -1;
	if (ra->vruntime > rb->vruntime) return  1;
	/* tie-breaker: pid */
	if (ra->pid < rb->pid) return -1;
	if (ra->pid > rb->pid) return  1;
	return 0;
}


static int bucket_push(struct cpu_bucket *b, const struct proc_rec *r)
{
	if (b->size == b->cap) {
		size_t newcap = b->cap ? b->cap * 2 : 16;
		void *p = krealloc(b->arr, newcap * sizeof(*b->arr), GFP_KERNEL);
		if (!p)
			return -ENOMEM;
		b->arr = p;
		b->cap = newcap;
	}
	b->arr[b->size++] = *r;
	return 0;
}


static void bucket_free(struct cpu_bucket *b)
{
	kfree(b->arr);
	b->arr = NULL;
	b->size = b->cap = 0;
}


/* ---------- helpers ---------- */


static inline bool is_cfs_policy(int policy)
{
	/* Tasks in these policies are managed by the fair (CFS) class */
	return policy == SCHED_NORMAL || policy == SCHED_BATCH || policy == SCHED_IDLE;
}


static void print_header(struct seq_file *m, pid_t pid_local)
{
	seq_printf(m, "ID: %s\n", MY_ID);
	seq_printf(m, "Name: %s\n", MY_NAME);
	seq_printf(m, "PID: %d\n", pid_local > 0 ? pid_local : -1);
	seq_puts(m, "----------------------------------------\n"); /* 40 '-' */
}


/* DFS over descendants (including root itself). We keep it iterative. */
struct stack_item { struct task_struct *t; struct list_head *next; };


static void walk_descendants(struct task_struct *root,
			     void (*visit)(struct task_struct *p, void *arg),
			     void *arg)
{
	/* Simple stack with dynamic growth if needed */
	size_t cap = 32, top = 0;
	struct stack_item *stk = kmalloc_array(cap, sizeof(*stk), GFP_KERNEL);
	struct task_struct *p;
	struct list_head *pos;


	if (!stk)
		return;


	/* seed with root */
	stk[top++] = (struct stack_item){ .t = root, .next = NULL };


	rcu_read_lock();


	while (top) {
		struct stack_item frame = stk[--top];


		p = frame.t;
		if (!p)
			continue;


		/* visit this task */
		visit(p, arg);


		/* iterate children under RCU */
		list_for_each_rcu(pos, &p->children) {
			struct task_struct *child =
				list_entry(pos, struct task_struct, sibling);
			if (top == cap) {
				size_t newcap = cap * 2;
				struct stack_item *tmp =
					krealloc(stk, newcap * sizeof(*stk), GFP_ATOMIC);
				if (!tmp) {
					/* out of memory; stop traversal gracefully */
					goto out_unlock;
				}
				stk = tmp;
				cap = newcap;
			}
			stk[top++] = (struct stack_item){ .t = child, .next = NULL };
		}
	}


out_unlock:
	rcu_read_unlock();
	kfree(stk);
}


/* Collector: if task is in CFS runqueue, put it into the right CPU bucket */
struct collect_ctx {
	struct cpu_bucket *buckets;
};


static void maybe_collect_task(struct task_struct *p, void *arg)
{
	struct collect_ctx *ctx = arg;
	struct proc_rec rec;
	int cpu;
	u64 vr;


	/* Snapshot fields safely for reporting */
	/* Check: CFS policy and currently enqueued on runqueue */
	if (!READ_ONCE(p->on_rq))
		return;
	if (!is_cfs_policy(READ_ONCE(p->policy)))
		return;


	/* task_cpu() is safe under RCU for a snapshot */
	cpu = task_cpu(p);
	if (cpu < 0 || cpu >= nr_cpu_ids || !cpu_online(cpu))
		return;


	/* Fill record */
	rec.pid = p->pid;
	/* READ_ONCE for vruntime to avoid tearing; it's a u64 */
	vr = READ_ONCE(p->se.vruntime);
	rec.vruntime = vr;
	/* Copy comm */
	memcpy(rec.comm, p->comm, TASK_COMM_LEN);


	/* Push into that CPU's bucket */
	bucket_push(&ctx->buckets[cpu], &rec);
}


/* ---------- /proc read path ---------- */
static int proc_analyzer_show(struct seq_file *m, void *v)
{
	pid_t pid_local;
	struct task_struct *root;
	int cpu;
	int ret = 0;
	struct cpu_bucket *buckets = NULL;
	int online_cnt = num_online_cpus();


	/* get stored pid */
	mutex_lock(&pid_lock);
	pid_local = stored_pid;
	mutex_unlock(&pid_lock);


	print_header(m, pid_local);


	if (pid_local <= 0)
		return 0;


	rcu_read_lock();
	root = pid_task(find_vpid(pid_local), PIDTYPE_PID);
	rcu_read_unlock();
	if (!root)
		return 0; /* PID disappeared: header only */


	/* Allocate per-CPU buckets (index by cpu number) */
	buckets = kcalloc(nr_cpu_ids, sizeof(*buckets), GFP_KERNEL);
	if (!buckets)
		return -ENOMEM;


	/* Collect */
	{
		struct collect_ctx ctx = { .buckets = buckets };
		walk_descendants(root, maybe_collect_task, &ctx);
	}


	/* Emit grouped by CPU in ascending CPU order */
	for_each_online_cpu(cpu) {
		/* Sort bucket by vruntime asc */
		if (buckets[cpu].size > 1)
			sort(buckets[cpu].arr, buckets[cpu].size,
			     sizeof(struct proc_rec), rec_cmp_by_vruntime, NULL);


		seq_printf(m, "[CPU #%d] Running processes: %zu\n",
			   cpu, buckets[cpu].size);


		for (size_t i = 0; i < buckets[cpu].size; i++) {
			struct proc_rec *r = &buckets[cpu].arr[i];
			seq_printf(m, "[%d] %s %llu\n",
				   r->pid, r->comm,
				   (unsigned long long)r->vruntime);
		}


		/* Print divider after each CPU section (like the example) */
		seq_puts(m, "----------------------------------------\n");
	}


	/* Free buckets */
	for_each_possible_cpu(cpu)
		bucket_free(&buckets[cpu]);
	kfree(buckets);


	return ret;
}


static int proc_analyzer_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_analyzer_show, NULL);
}


/* ---------- /proc write path: store PID ---------- */
static ssize_t proc_analyzer_write(struct file *file,
				   const char __user *ubuf,
				   size_t len, loff_t *ppos)
{
	char kbuf[32];
	long val;
	size_t n = min(len, sizeof(kbuf) - 1);


	if (copy_from_user(kbuf, ubuf, n))
		return -EFAULT;
	kbuf[n] = '\0';


	if (kstrtol(kbuf, 10, &val))
		return -EINVAL;
	if (val <= 0)
		return -EINVAL;


	mutex_lock(&pid_lock);
	stored_pid = (pid_t)val;
	mutex_unlock(&pid_lock);


	return len;
}


/* ---------- proc ops ---------- */
static const struct proc_ops proc_analyzer_ops = {
	.proc_open    = proc_analyzer_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = proc_analyzer_write,
};


/* ---------- module boilerplate ---------- */
static int __init proc_analyzer_init(void)
{
	/* 0644: root writable, others readable. Use 0666 if you want global write. */
	proc_entry = proc_create("proc_analyzer", 0666, NULL, &proc_analyzer_ops);
	if (!proc_entry)
		return -ENOMEM;


	pr_info("proc_analyzer: /proc/proc_analyzer created\n");
	return 0;
}


static void __exit proc_analyzer_exit(void)
{
	proc_remove(proc_entry);
	pr_info("proc_analyzer: /proc/proc_analyzer removed\n");
}


module_init(proc_analyzer_init);
module_exit(proc_analyzer_exit);





