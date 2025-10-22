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

static struct proc_dir_entry *proc_entry;
static DEFINE_MUTEX(pid_lock);
static pid_t stored_pid = -1;

// Process records & per-CPU buckets
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

// Compares two proc_rec items for sort()
static int rec_cmp_by_vruntime(const void *a, const void *b)
{
	const struct proc_rec *ra = a, *rb = b;
	if (ra->vruntime < rb->vruntime) return -1;
	if (ra->vruntime > rb->vruntime) return  1;

	// tie-breaker: pid
	if (ra->pid < rb->pid) return -1;
	if (ra->pid > rb->pid) return  1;
	return 0;
}

// Appends a record to a CPU bucket
// (grows the bucket's backing array with krealloc() (doubling capacity) when full)
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

// Releases a CPU bucket's dynamically allocated array
static void bucket_free(struct cpu_bucket *b)
{
	kfree(b->arr);
	b->arr = NULL;
	b->size = b->cap = 0;
}

// Returns true if the given scheduling policy belongs to the fair (CFS) class 
static inline bool is_cfs_policy(int policy) {
	return policy == SCHED_NORMAL || policy == SCHED_BATCH || policy == SCHED_IDLE;
}

// Print ID and name
static void print_header(struct seq_file *m, pid_t pid_local)
{
	seq_printf(m, "ID: 2023148089\n");
	seq_printf(m, "Name: Muhammad Afiq Aiman bin Affandi\n");
	seq_printf(m, "PID: %d\n", pid_local > 0 ? pid_local : -1);
	seq_printf(m, "----------------------------------------\n"); /* 40 '-' */
}

struct stack_item { struct task_struct *t; struct list_head *next; };

// Walks the root task and all descendants in depth-first order
static void walk_descendants(struct task_struct *root,
			     void (*visit)(struct task_struct *p, void *arg),
			     void *arg)
{
	// Use a manually managed stack that can grow if we encounter many descendants
	size_t cap = 32, top = 0;
	struct stack_item *stk = kmalloc_array(cap, sizeof(*stk), GFP_KERNEL);
	struct task_struct *p;
	struct list_head *pos;

	// If allocation fails, we simply skip the traversal
	if (!stk)
		return;

	// Seed the stack with the root task so we also visit it
	stk[top++] = (struct stack_item){ .t = root, .next = NULL };

	// Hold the RCU read lock while we walk task lists protected by RCU
	rcu_read_lock();

	while (top) {
		// Pop one frame from the stack to process it
		struct stack_item frame = stk[--top];

		p = frame.t;
		if (!p)
			continue;

		// Call the user-provided callback on the currently visited task
		visit(p, arg);

		// Iterate over children safely under RCU to discover more work
		list_for_each_rcu(pos, &p->children) {
			struct task_struct *child =
				list_entry(pos, struct task_struct, sibling);

			// Grow the stack if we have no free slots left.
			if (top == cap) {
				size_t newcap = cap * 2;
				struct stack_item *tmp =
					krealloc(stk, newcap * sizeof(*stk), GFP_ATOMIC);
				if (!tmp) {
					// On allocation failure, stop cleanly
					goto out_unlock;
				}
				stk = tmp;
				cap = newcap;
			}

			// Push the child so it will be visited in LIFO order (DFS)
			stk[top++] = (struct stack_item){ .t = child, .next = NULL };
		}
	}

out_unlock:
	// Release the RCU read-side critical section and free the stack memory
	rcu_read_unlock();
	kfree(stk);
}

// Context object that holds per-CPU buckets
struct collect_ctx {
	struct cpu_bucket *buckets;
};

// For a visited task, records it into the appropriate CPU bucket if it's on the CFS runqueue
static void maybe_collect_task(struct task_struct *p, void *arg)
{
	struct collect_ctx *ctx = arg;
	struct proc_rec rec;
	int cpu;
	u64 vr;

	// We only report tasks that are enqueued on the CFS runqueue right now
	if (!READ_ONCE(p->on_rq))
		return;
	if (!is_cfs_policy(READ_ONCE(p->policy)))
		return;

	// Grab the CPU as a snapshot under RCU; skip if the CPU is invalid or offline
	cpu = task_cpu(p);
	if (cpu < 0 || cpu >= nr_cpu_ids || !cpu_online(cpu))
		return;

	// Prepare a record with PID, name, and vruntime for sorting and printing
	// READ_ONCE avoids tearing when reading a 64-bit field
	// memcpy used to copy fixed-size task name safely
	rec.pid = p->pid;
	vr = READ_ONCE(p->se.vruntime); 
	rec.vruntime = vr;
	memcpy(rec.comm, p->comm, TASK_COMM_LEN); 

	// Append the record to the bucket of the CPU where the task currently resides
	bucket_push(&ctx->buckets[cpu], &rec);
}

// When /proc is read:
// gathers descendants, groups runnable CFS tasks by CPU, 
// sorts by vruntime, and prints them
static int proc_analyzer_show(struct seq_file *m, void *v)
{
	pid_t pid_local;
	struct task_struct *root;
	int cpu;
	int ret = 0;
	struct cpu_bucket *buckets = NULL;
	int online_cnt = num_online_cpus(); // Snapshot used for informational purposes.

	// Read the user-provided PID under a mutex to avoid races
	mutex_lock(&pid_lock);
	pid_local = stored_pid;
	mutex_unlock(&pid_lock);

	// Print module header and the currently selected root PID
	print_header(m, pid_local);

	// If no valid PID is stored
	if (pid_local <= 0)
		return 0;

	// Resolve the PID to a task_struct under RCU. If vanished, report nothing more.
	rcu_read_lock();
	root = pid_task(find_vpid(pid_local), PIDTYPE_PID);
	rcu_read_unlock();
	if (!root)
		return 0; // PID disappeared between write and read: nothing to traverse.

	// Allocate one bucket per possible CPU index so we can insert by cpu number directly
	buckets = kcalloc(nr_cpu_ids, sizeof(*buckets), GFP_KERNEL);
	if (!buckets)
		return -ENOMEM;

	// Walk the root and all its descendants, collecting runnable CFS tasks into CPU buckets
	{
		struct collect_ctx ctx = { .buckets = buckets };
		walk_descendants(root, maybe_collect_task, &ctx);
	}

	// For each online CPU, sort its records by vruntime (ascending) and print them as a section
	for_each_online_cpu(cpu) {
		// Sort ensures the smallest vruntime (ie. most entitled to run) appears first
		if (buckets[cpu].size > 1)
			sort(buckets[cpu].arr, buckets[cpu].size,
			     sizeof(struct proc_rec), rec_cmp_by_vruntime, NULL);

		// Print for each CPU
		seq_printf(m, "[CPU #%d] Running processes: %zu\n",
			   cpu, buckets[cpu].size);

		// Print for each record
		for (size_t i = 0; i < buckets[cpu].size; i++) {
			struct proc_rec *r = &buckets[cpu].arr[i];
			seq_printf(m, "[%d] %s %llu\n",
				   r->pid, r->comm,
				   (unsigned long long)r->vruntime);
		}

		// Add divider line after each CPU section
		seq_puts(m, "----------------------------------------\n");
	}

	// Release all dynamically allocated bucket storage before returning to userspace
	for_each_possible_cpu(cpu)
		bucket_free(&buckets[cpu]);
	kfree(buckets);

	return ret;
}


// When proc is read
static int proc_analyzer_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_analyzer_show, NULL);
}

// When proc is written to, eg. using
// echo <PID> > /proc/ancestor
static ssize_t proc_analyzer_write(struct file *file,
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
static const struct proc_ops proc_analyzer_ops = {
	.proc_open    = proc_analyzer_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = proc_analyzer_write,
};

// Initialize
static int __init proc_analyzer_init(void)
{
	// Permissions set to 0666 to make writable
	proc_entry = proc_create("proc_analyzer", 0666, NULL, &proc_analyzer_ops);
	if (!proc_entry)
		return -ENOMEM;

	pr_info("proc_analyzer: /proc/proc_analyzer created\n");
	return 0;
}

// Exit
static void __exit proc_analyzer_exit(void)
{
	proc_remove(proc_entry);
	pr_info("proc_analyzer: /proc/proc_analyzer removed\n");
}

module_init(proc_analyzer_init);
module_exit(proc_analyzer_exit);

MODULE_LICENSE("GPL");
