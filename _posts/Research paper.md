write introduction as to why we shifted from rb and ll implementation to maple trees. 

## The `task_struct`

Every process in the Linux kernel is represented by a single, massive structure called `task_struct`. It is defined in `<linux/sched.h>`, and is often called the **Process Descriptor**.

When we run a program, the kernel always allocates a `task_struct` for it. Everything the kernel needs to know about that particular process such as its memory, its files, its credentials, its CPU state, even its relationships to other processes lives in or is reachable from this one structure, task_struct. Lets check out the size of our task_struct on my 64 bit machine on kernel version 6.0.0 using the following command:
```gdb
pahole -C task_struct vmlinux
```
We get the following output:
```c
struct task_struct {
	struct thread_info         thread_info;          /*     0    24 */
	unsigned int               __state;              /*    24     4 */

	/* XXX 4 bytes hole, try to pack */

	void *                     stack;                /*    32     8 */
	refcount_t                 usage;                /*    40     4 */
	unsigned int               flags;                /*    44     4 */
	unsigned int               ptrace;               /*    48     4 */
	int                        on_cpu;               /*    52     4 */
	struct __call_single_node  wake_entry;           /*    56    16 */
	/* --- cacheline 1 boundary (64 bytes) was 8 bytes ago --- */
	unsigned int               wakee_flips;          /*    72     4 */

	/* XXX 4 bytes hole, try to pack */

	long unsigned int          wakee_flip_decay_ts;  /*    80     8 */
	struct task_struct *       last_wakee;           /*    88     8 */
	int                        recent_used_cpu;      /*    96     4 */
	int                        wake_cpu;             /*   100     4 */
	int                        on_rq;                /*   104     4 */
	int                        prio;                 /*   108     4 */
	int                        static_prio;          /*   112     4 */
	int                        normal_prio;          /*   116     4 */
	unsigned int               rt_priority;          /*   120     4 */

	/* XXX 4 bytes hole, try to pack */

	/* --- cacheline 2 boundary (128 bytes) --- */
	struct sched_entity        se __attribute__((__aligned__(64))); /*   128   256 */
	/* --- cacheline 6 boundary (384 bytes) --- */
	struct sched_rt_entity     rt;                   /*   384    48 */
	struct sched_dl_entity     dl __attribute__((__aligned__(8))); /*   432   224 */
	/* --- cacheline 10 boundary (640 bytes) was 16 bytes ago --- */
	const struct sched_class  * sched_class;         /*   656     8 */
	struct task_group *        sched_task_group;     /*   664     8 */

	/* XXX 32 bytes hole, try to pack */

	/* --- cacheline 11 boundary (704 bytes) --- */
	struct sched_statistics    stats __attribute__((__aligned__(64))); /*   704   256 */

	/* XXX last struct has 32 bytes of padding */

	/* --- cacheline 15 boundary (960 bytes) --- */
	unsigned int               btrace_seq;           /*   960     4 */
	unsigned int               policy;               /*   964     4 */
	int                        nr_cpus_allowed;      /*   968     4 */

	/* XXX 4 bytes hole, try to pack */

	const cpumask_t  *         cpus_ptr;             /*   976     8 */
	cpumask_t *                user_cpus_ptr;        /*   984     8 */
	cpumask_t                  cpus_mask;            /*   992     8 */
	void *                     migration_pending;    /*  1000     8 */
	short unsigned int         migration_disabled;   /*  1008     2 */
	short unsigned int         migration_flags;      /*  1010     2 */
	int                        rcu_read_lock_nesting; /*  1012     4 */
	union rcu_special          rcu_read_unlock_special; /*  1016     4 */

	/* XXX 4 bytes hole, try to pack */

	/* --- cacheline 16 boundary (1024 bytes) --- */
	struct list_head           rcu_node_entry;       /*  1024    16 */
	struct rcu_node *          rcu_blocked_node;     /*  1040     8 */
	long unsigned int          rcu_tasks_nvcsw;      /*  1048     8 */
	u8                         rcu_tasks_holdout;    /*  1056     1 */
	u8                         rcu_tasks_idx;        /*  1057     1 */

	/* XXX 2 bytes hole, try to pack */

	int                        rcu_tasks_idle_cpu;   /*  1060     4 */
	struct list_head           rcu_tasks_holdout_list; /*  1064    16 */
	struct sched_info          sched_info;           /*  1080    32 */
	/* --- cacheline 17 boundary (1088 bytes) was 24 bytes ago --- */
	struct list_head           tasks;                /*  1112    16 */
	struct plist_node          pushable_tasks;       /*  1128    40 */
	/* --- cacheline 18 boundary (1152 bytes) was 16 bytes ago --- */
	struct rb_node             pushable_dl_tasks __attribute__((__aligned__(8))); /*  1168    24 */
	struct mm_struct *         mm;                   /*  1192     8 */
	struct mm_struct *         active_mm;            /*  1200     8 */
	struct vmacache            vmacache;             /*  1208    40 */
	/* --- cacheline 19 boundary (1216 bytes) was 32 bytes ago --- */
	struct task_rss_stat       rss_stat;             /*  1248    20 */
	int                        exit_state;           /*  1268     4 */
	int                        exit_code;            /*  1272     4 */
	int                        exit_signal;          /*  1276     4 */
	/* --- cacheline 20 boundary (1280 bytes) --- */
	int                        pdeath_signal;        /*  1280     4 */

	/* XXX 4 bytes hole, try to pack */

	long unsigned int          jobctl;               /*  1288     8 */
	unsigned int               personality;          /*  1296     4 */
	unsigned int               sched_reset_on_fork:1; /*  1300: 0  4 */
	unsigned int               sched_contributes_to_load:1; /*  1300: 1  4 */
	unsigned int               sched_migrated:1;     /*  1300: 2  4 */

	/* XXX 29 bits hole, try to pack */

	/* Force alignment to the next boundary: */
	unsigned int               :0;

	unsigned int               sched_remote_wakeup:1; /*  1304: 0  4 */
	unsigned int               in_execve:1;          /*  1304: 1  4 */
	unsigned int               in_iowait:1;          /*  1304: 2  4 */
	unsigned int               restore_sigmask:1;    /*  1304: 3  4 */
	unsigned int               no_cgroup_migration:1; /*  1304: 4  4 */
	unsigned int               frozen:1;             /*  1304: 5  4 */
	unsigned int               use_memdelay:1;       /*  1304: 6  4 */
	unsigned int               in_eventfd_signal:1;  /*  1304: 7  4 */
	unsigned int               reported_split_lock:1; /*  1304: 8  4 */

	/* XXX 23 bits hole, try to pack */
	/* XXX 4 bytes hole, try to pack */

	long unsigned int          atomic_flags;         /*  1312     8 */
	struct restart_block       restart_block;        /*  1320    56 */
	/* --- cacheline 21 boundary (1344 bytes) was 32 bytes ago --- */
	pid_t                      pid;                  /*  1376     4 */
	pid_t                      tgid;                 /*  1380     4 */
	long unsigned int          stack_canary;         /*  1384     8 */
	struct task_struct *       real_parent;          /*  1392     8 */
	struct task_struct *       parent;               /*  1400     8 */
	/* --- cacheline 22 boundary (1408 bytes) --- */
	struct list_head           children;             /*  1408    16 */
	struct list_head           sibling;              /*  1424    16 */
	struct task_struct *       group_leader;         /*  1440     8 */
	struct list_head           ptraced;              /*  1448    16 */
	struct list_head           ptrace_entry;         /*  1464    16 */
	/* --- cacheline 23 boundary (1472 bytes) was 8 bytes ago --- */
	struct pid *               thread_pid;           /*  1480     8 */
	struct hlist_node          pid_links[4];         /*  1488    64 */
	/* --- cacheline 24 boundary (1536 bytes) was 16 bytes ago --- */
	struct list_head           thread_group;         /*  1552    16 */
	struct list_head           thread_node;          /*  1568    16 */
	struct completion *        vfork_done;           /*  1584     8 */
	int *                      set_child_tid;        /*  1592     8 */
	/* --- cacheline 25 boundary (1600 bytes) --- */
	int *                      clear_child_tid;      /*  1600     8 */
	void *                     worker_private;       /*  1608     8 */
	u64                        utime;                /*  1616     8 */
	u64                        stime;                /*  1624     8 */
	u64                        gtime;                /*  1632     8 */
	struct prev_cputime        prev_cputime;         /*  1640    24 */

	/* XXX last struct has 4 bytes of padding */

	/* --- cacheline 26 boundary (1664 bytes) --- */
	long unsigned int          nvcsw;                /*  1664     8 */
	long unsigned int          nivcsw;               /*  1672     8 */
	u64                        start_time;           /*  1680     8 */
	u64                        start_boottime;       /*  1688     8 */
	long unsigned int          min_flt;              /*  1696     8 */
	long unsigned int          maj_flt;              /*  1704     8 */
	struct posix_cputimers     posix_cputimers;      /*  1712    80 */
	/* --- cacheline 28 boundary (1792 bytes) --- */
	struct posix_cputimers_work posix_cputimers_work __attribute__((__aligned__(8))); /*  1792    24 */

	/* XXX last struct has 4 bytes of padding */

	const struct cred  *       ptracer_cred;         /*  1816     8 */
	const struct cred  *       real_cred;            /*  1824     8 */
	const struct cred  *       cred;                 /*  1832     8 */
	struct key *               cached_requested_key; /*  1840     8 */
	char                       comm[16];             /*  1848    16 */
	/* --- cacheline 29 boundary (1856 bytes) was 8 bytes ago --- */
	struct nameidata *         nameidata;            /*  1864     8 */
	struct sysv_sem            sysvsem;              /*  1872     8 */
	struct sysv_shm            sysvshm;              /*  1880    16 */
	struct fs_struct *         fs;                   /*  1896     8 */
	struct files_struct *      files;                /*  1904     8 */
	struct io_uring_task *     io_uring;             /*  1912     8 */
	/* --- cacheline 30 boundary (1920 bytes) --- */
	struct nsproxy *           nsproxy;              /*  1920     8 */
	struct signal_struct *     signal;               /*  1928     8 */
	struct sighand_struct *    sighand;              /*  1936     8 */
	sigset_t                   blocked;              /*  1944     8 */
	sigset_t                   real_blocked;         /*  1952     8 */
	sigset_t                   saved_sigmask;        /*  1960     8 */
	struct sigpending          pending;              /*  1968    24 */
	/* --- cacheline 31 boundary (1984 bytes) was 8 bytes ago --- */
	long unsigned int          sas_ss_sp;            /*  1992     8 */
	size_t                     sas_ss_size;          /*  2000     8 */
	unsigned int               sas_ss_flags;         /*  2008     4 */

	/* XXX 4 bytes hole, try to pack */

	struct callback_head *     task_works;           /*  2016     8 */
	struct audit_context *     audit_context;        /*  2024     8 */
	kuid_t                     loginuid;             /*  2032     4 */
	unsigned int               sessionid;            /*  2036     4 */
	struct seccomp             seccomp;              /*  2040    16 */
	/* --- cacheline 32 boundary (2048 bytes) was 8 bytes ago --- */
	struct syscall_user_dispatch syscall_dispatch;   /*  2056    32 */

	/* XXX last struct has 7 bytes of padding */

	u64                        parent_exec_id;       /*  2088     8 */
	u64                        self_exec_id;         /*  2096     8 */
	spinlock_t                 alloc_lock;           /*  2104     4 */
	raw_spinlock_t             pi_lock;              /*  2108     4 */
	/* --- cacheline 33 boundary (2112 bytes) --- */
	struct wake_q_node         wake_q;               /*  2112     8 */
	struct rb_root_cached      pi_waiters;           /*  2120    16 */
	struct task_struct *       pi_top_task;          /*  2136     8 */
	struct rt_mutex_waiter *   pi_blocked_on;        /*  2144     8 */
	void *                     journal_info;         /*  2152     8 */
	struct bio_list *          bio_list;             /*  2160     8 */
	struct blk_plug *          plug;                 /*  2168     8 */
	/* --- cacheline 34 boundary (2176 bytes) --- */
	struct reclaim_state *     reclaim_state;        /*  2176     8 */
	struct backing_dev_info *  backing_dev_info;     /*  2184     8 */
	struct io_context *        io_context;           /*  2192     8 */
	struct capture_control *   capture_control;      /*  2200     8 */
	long unsigned int          ptrace_message;       /*  2208     8 */
	kernel_siginfo_t *         last_siginfo;         /*  2216     8 */
	struct task_io_accounting  ioac;                 /*  2224    56 */
	/* --- cacheline 35 boundary (2240 bytes) was 40 bytes ago --- */
	u64                        acct_rss_mem1;        /*  2280     8 */
	u64                        acct_vm_mem1;         /*  2288     8 */
	u64                        acct_timexpd;         /*  2296     8 */
	/* --- cacheline 36 boundary (2304 bytes) --- */
	nodemask_t                 mems_allowed;         /*  2304     8 */
	seqcount_spinlock_t        mems_allowed_seq;     /*  2312     4 */
	int                        cpuset_mem_spread_rotor; /*  2316     4 */
	int                        cpuset_slab_spread_rotor; /*  2320     4 */

	/* XXX 4 bytes hole, try to pack */

	struct css_set *           cgroups;              /*  2328     8 */
	struct list_head           cg_list;              /*  2336    16 */
	struct robust_list_head *  robust_list;          /*  2352     8 */
	struct compat_robust_list_head * compat_robust_list; /*  2360     8 */
	/* --- cacheline 37 boundary (2368 bytes) --- */
	struct list_head           pi_state_list;        /*  2368    16 */
	struct futex_pi_state *    pi_state_cache;       /*  2384     8 */
	struct mutex               futex_exit_mutex;     /*  2392    32 */
	unsigned int               futex_state;          /*  2424     4 */

	/* XXX 4 bytes hole, try to pack */

	/* --- cacheline 38 boundary (2432 bytes) --- */
	struct perf_event_context * perf_event_ctxp[2];  /*  2432    16 */
	struct mutex               perf_event_mutex;     /*  2448    32 */
	struct list_head           perf_event_list;      /*  2480    16 */
	/* --- cacheline 39 boundary (2496 bytes) --- */
	long unsigned int          preempt_disable_ip;   /*  2496     8 */
	struct mempolicy *         mempolicy;            /*  2504     8 */
	short int                  il_prev;              /*  2512     2 */
	short int                  pref_node_fork;       /*  2514     2 */

	/* XXX 4 bytes hole, try to pack */

	struct rseq *              rseq;                 /*  2520     8 */
	u32                        rseq_sig;             /*  2528     4 */

	/* XXX 4 bytes hole, try to pack */

	long unsigned int          rseq_event_mask;      /*  2536     8 */
	struct tlbflush_unmap_batch tlb_ubc;             /*  2544    16 */

	/* XXX last struct has 6 bytes of padding */

	/* --- cacheline 40 boundary (2560 bytes) --- */
	union {
		refcount_t         rcu_users;            /*  2560     4 */
		struct callback_head rcu __attribute__((__aligned__(8))); /*  2560    16 */
	} __attribute__((__aligned__(8)));               /*  2560    16 */
	struct pipe_inode_info *   splice_pipe;          /*  2576     8 */
	struct page_frag           task_frag;            /*  2584    16 */
	struct task_delay_info *   delays;               /*  2600     8 */
	int                        nr_dirtied;           /*  2608     4 */
	int                        nr_dirtied_pause;     /*  2612     4 */
	long unsigned int          dirty_paused_when;    /*  2616     8 */
	/* --- cacheline 41 boundary (2624 bytes) --- */
	u64                        timer_slack_ns;       /*  2624     8 */
	u64                        default_timer_slack_ns; /*  2632     8 */
	long unsigned int          trace;                /*  2640     8 */
	long unsigned int          trace_recursion;      /*  2648     8 */
	struct request_queue *     throttle_queue;       /*  2656     8 */
	struct uprobe_task *       utask;                /*  2664     8 */
	struct kmap_ctrl           kmap_ctrl;            /*  2672     0 */
	int                        pagefault_disabled;   /*  2672     4 */

	/* XXX 4 bytes hole, try to pack */

	struct task_struct *       oom_reaper_list;      /*  2680     8 */
	/* --- cacheline 42 boundary (2688 bytes) --- */
	struct timer_list          oom_reaper_timer;     /*  2688    40 */

	/* XXX last struct has 4 bytes of padding */

	struct vm_struct *         stack_vm_area;        /*  2728     8 */
	refcount_t                 stack_refcount;       /*  2736     4 */

	/* XXX 4 bytes hole, try to pack */

	void *                     security;             /*  2744     8 */
	/* --- cacheline 43 boundary (2752 bytes) --- */
	void *                     mce_vaddr;            /*  2752     8 */
	__u64                      mce_kflags;           /*  2760     8 */
	u64                        mce_addr;             /*  2768     8 */
	__u64                      mce_ripv:1;           /*  2776: 0  8 */
	__u64                      mce_whole_page:1;     /*  2776: 1  8 */
	__u64                      __mce_reserved:62;    /*  2776: 2  8 */
	struct callback_head       mce_kill_me __attribute__((__aligned__(8))); /*  2784    16 */
	int                        mce_count;            /*  2800     4 */

	/* XXX 4 bytes hole, try to pack */

	struct llist_head          kretprobe_instances;  /*  2808     8 */
	/* --- cacheline 44 boundary (2816 bytes) --- */
	struct llist_head          rethooks;             /*  2816     8 */
	struct callback_head       l1d_flush_kill __attribute__((__aligned__(8))); /*  2824    16 */

	/* XXX 40 bytes hole, try to pack */

	/* --- cacheline 45 boundary (2880 bytes) --- */
	struct thread_struct       thread __attribute__((__aligned__(64))); /*  2880  4416 */

	/* size: 7296, cachelines: 114, members: 203 */
	/* sum members: 7146, holes: 18, sum holes: 134 */
	/* sum bitfield members: 76 bits, bit holes: 2, sum bit holes: 52 bits */
	/* paddings: 6, sum paddings: 57 */
	/* forced alignments: 9, forced holes: 3, sum forced holes: 76 */
} __attribute__((__aligned__(64)));
```
task_struct is massive, and we won't go in the details of each and every member, but lets take a look at one of the last lines:
```c
/* size: 7296, cachelines: 114, members: 203 */
```
This tells us that we have total 203 data members in our struct, and the size of task_struct is 7296 bytes which is around 7 kilobytes. We have 114 cachelines because we are on a 64 bit operating system, and 7296/64 will give us 114. Moving forward, the kernel maintains a **circular doubly-linked list** of all `task_struct`s present in the system, so it can iterate over every process at any time.

[insert imahe!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! diagram i mean]
[insert how we can get task_struct in gdb]

The `current` macro is used everywhere in kernel code. It efficiently retrieves the `task_struct` of the currently running process using the stack pointer or a dedicated register.

We know there are 203 members of the task_struct, so we will not go into their detail, but one member which we are particularly interested in is `mm_struct`.

`task_struct` points to it via two fields:

```c
struct mm_struct *mm;         // NULL for kernel threads
struct mm_struct *active_mm;  // borrowed mm when mm == NULL
```

Threads of the same process all point to the same `mm_struct`. When we call `clone()` with `CLONE_VM`, the new `task_struct` gets a pointer to the existing `mm_struct` and its reference count (`mm_users`) is incremented. This is what makes threads share an address space, since they start referring to the same `mm_struct` and `mm_struct` refers to memory. 

```c
struct mm_struct {
	struct {
		struct vm_area_struct * mmap;            /*     0     8 */
		struct rb_root     mm_rb;                /*     8     8 */
		u64                vmacache_seqnum;      /*    16     8 */
		long unsigned int  (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int); /*    24     8 */
		long unsigned int  mmap_base;            /*    32     8 */
		long unsigned int  mmap_legacy_base;     /*    40     8 */
		long unsigned int  mmap_compat_base;     /*    48     8 */
		long unsigned int  mmap_compat_legacy_base; /*    56     8 */
		/* --- cacheline 1 boundary (64 bytes) --- */
		long unsigned int  task_size;            /*    64     8 */
		long unsigned int  highest_vm_end;       /*    72     8 */
		pgd_t *            pgd;                  /*    80     8 */
		atomic_t           membarrier_state;     /*    88     4 */
		atomic_t           mm_users;             /*    92     4 */
		atomic_t           mm_count;             /*    96     4 */

		/* XXX 4 bytes hole, try to pack */

		atomic_long_t      pgtables_bytes;       /*   104     8 */
		int                map_count;            /*   112     4 */
		spinlock_t         page_table_lock;      /*   116     4 */
		struct rw_semaphore mmap_lock;           /*   120    40 */
		/* --- cacheline 2 boundary (128 bytes) was 32 bytes ago --- */
		struct list_head   mmlist;               /*   160    16 */
		long unsigned int  hiwater_rss;          /*   176     8 */
		long unsigned int  hiwater_vm;           /*   184     8 */
		/* --- cacheline 3 boundary (192 bytes) --- */
		long unsigned int  total_vm;             /*   192     8 */
		long unsigned int  locked_vm;            /*   200     8 */
		atomic64_t         pinned_vm;            /*   208     8 */
		long unsigned int  data_vm;              /*   216     8 */
		long unsigned int  exec_vm;              /*   224     8 */
		long unsigned int  stack_vm;             /*   232     8 */
		long unsigned int  def_flags;            /*   240     8 */
		seqcount_t         write_protect_seq;    /*   248     4 */
		spinlock_t         arg_lock;             /*   252     4 */
		/* --- cacheline 4 boundary (256 bytes) --- */
		long unsigned int  start_code;           /*   256     8 */
		long unsigned int  end_code;             /*   264     8 */
		long unsigned int  start_data;           /*   272     8 */
		long unsigned int  end_data;             /*   280     8 */
		long unsigned int  start_brk;            /*   288     8 */
		long unsigned int  brk;                  /*   296     8 */
		long unsigned int  start_stack;          /*   304     8 */
		long unsigned int  arg_start;            /*   312     8 */
		/* --- cacheline 5 boundary (320 bytes) --- */
		long unsigned int  arg_end;              /*   320     8 */
		long unsigned int  env_start;            /*   328     8 */
		long unsigned int  env_end;              /*   336     8 */
		long unsigned int  saved_auxv[48];       /*   344   384 */
		/* --- cacheline 11 boundary (704 bytes) was 24 bytes ago --- */
		struct mm_rss_stat rss_stat;             /*   728    32 */
		struct linux_binfmt * binfmt;            /*   760     8 */
		/* --- cacheline 12 boundary (768 bytes) --- */
		mm_context_t       context;              /*   768   128 */
		/* --- cacheline 14 boundary (896 bytes) --- */
		long unsigned int  flags;                /*   896     8 */
		spinlock_t         ioctx_lock;           /*   904     4 */

		/* XXX 4 bytes hole, try to pack */

		struct kioctx_table * ioctx_table;       /*   912     8 */
		struct user_namespace * user_ns;         /*   920     8 */
		struct file *      exe_file;             /*   928     8 */
		struct mmu_notifier_subscriptions * notifier_subscriptions; /*   936     8 */
		atomic_t           tlb_flush_pending;    /*   944     4 */
		atomic_t           tlb_flush_batched;    /*   948     4 */
		struct uprobes_state uprobes_state;      /*   952     8 */
		/* --- cacheline 15 boundary (960 bytes) --- */
		atomic_long_t      hugetlb_usage;        /*   960     8 */
		struct work_struct async_put_work;       /*   968    32 */
	};                                               /*     0  1000 */
	long unsigned int          cpu_bitmap[];         /*  1000     0 */

	/* size: 1000, cachelines: 16, members: 2 */
	/* last cacheline: 40 bytes */
};
```
Here we see that our `mm_struct` is of 1000 bytes which make 1 kilobyte, 16 cachelines because 1000/64 makes 16, and 2 members, because there is one huge struct embedded in `mm_struct` which contains all the key fields, and then we have our `cpu_bitmap[]`. 
Here we see that we have:
```c
struct rw_semaphore mmap_lock;
```
This is the most important synchronization primitive in `mm_struct`. Any operation that reads or modifies the VMA tree or linked list must hold this lock, either shared for lookups like page fault handling, or exclusive (write) for modifications like `mmap()`, `munmap()`, `mprotect()`. This is a frequent contention point in multithreaded processes. 
Then we have:
```c
int map_count;   // number of VMAs currently in this mm
```
This is bounded by `/proc/sys/vm/max_map_count` (default 65530). If a process hits this limit, `mmap()` fails. Processes with many threads, many shared libraries, or heavy use of `mprotect()` may approach this limit.

For our research, our sole focus for Linux kernel versions 6.1> is going to be on 
```c
struct vm_area_struct * mmap;            /*     0     8 */
struct rb_root     mm_rb;                /*     8     8 */
```
which are the main entry points to our VMAs.

We will now touch upon Virtual Memory Areas, famously known as VMAs.
## VMAs in the Linux Kernel

A VMA is a fundamental data structure in the Linux kernel that represents a contiguous region of a process's virtual address space. 
### The `vm_area_struct`

Each VMA is represented by the`vm_area_struct` structure which is of 192 bytes defined in `<linux/mm_types.h>`. 

```c
struct vm_area_struct {
	long unsigned int          vm_start;             /*     0     8 */
	long unsigned int          vm_end;               /*     8     8 */
	struct vm_area_struct *    vm_next;              /*    16     8 */
	struct vm_area_struct *    vm_prev;              /*    24     8 */
	struct rb_node  vm_rb __attribute__((__aligned__(8))); /*    32    24 */
	long unsigned int          rb_subtree_gap;       /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	struct mm_struct *         vm_mm;                /*    64     8 */
	pgprot_t                   vm_page_prot;         /*    72     8 */
	long unsigned int          vm_flags;             /*    80     8 */
	union {
		struct {
			struct rb_node rb __attribute__((__aligned__(8))); /*    88    24 */
			long unsigned int rb_subtree_last; /*   112     8 */
		} __attribute__((__aligned__(8))) shared __attribute__((__aligned__(8))); /*    88    32 */
		struct anon_vma_name * anon_name;        /*    88     8 */
	} __attribute__((__aligned__(8)));               /*    88    32 */
	struct list_head           anon_vma_chain;       /*   120    16 */
	/* --- cacheline 2 boundary (128 bytes) was 8 bytes ago --- */
	struct anon_vma *          anon_vma;             /*   136     8 */
	const struct vm_operations_struct  * vm_ops;     /*   144     8 */
	long unsigned int          vm_pgoff;             /*   152     8 */
	struct file *              vm_file;              /*   160     8 */
	void *                     vm_private_data;      /*   168     8 */
	atomic_long_t              swap_readahead_info;  /*   176     8 */
	struct mempolicy *         vm_policy;            /*   184     8 */
	/* --- cacheline 3 boundary (192 bytes) --- */
	struct vm_userfaultfd_ctx  vm_userfaultfd_ctx;   /*   192     0 */

	/* size: 192, cachelines: 3, members: 19 */
	/* forced alignments: 2 */
} __attribute__((__aligned__(8)));
};
```
```
 (one page)
```

Since we are going to be discussing VMA management, so we will go in the details of some fields of this struct. We have`vm_start` and `vm_end` at offsets 0 and 8
```c
long unsigned int vm_start;   /* 0   8 */
long unsigned int vm_end;     /* 8   8 */
```
They contain the start and end **virtual addresses** of the memory region to which our VMA belongs to. ADD GDB

**`vm_next` and `vm_prev`** at offsets 16 and 24
```c
struct vm_area_struct *vm_next;   /* 16  8 */
struct vm_area_struct *vm_prev;   /* 24  8 */
```
All VMAs of a process are kept in a ascending sorted linked list by address:

This is useful for sequential scanning. For example if we want to iterate over all mappings in `/proc/pid/maps`.

Then we have`vm_rb`which is at offset 32. Each vma needs to **exist as a node inside a Red-Black tree**, which we'll see soon. `vm_rb` is that node. it holds the left or right or parent pointers that connect this particular VMA to the rest of the tree:

```c
struct rb_node vm_rb __attribute__((__aligned__(8)));  /* 32  24 */
```

The same VMAs are **also** stored in a **red-black tree** (sorted by address) for fast lookup. 
vm_area_struct:                    
┌─────────────────────┐            
│ vm_start            │            
│ vm_end              │            
│ vm_next  ───────────┼──→ next vma (linked list)
│ vm_prev  ───────────┼──→ prev vma (linked list)
│ vm_rb               │            
│  ├─ rb_left  ───────┼──→ left child in tree
│  ├─ rb_right ───────┼──→ right child in tree
│  └─ parent   ───────┼──→ parent in tree
│ ...                 │            
└─────────────────────┘
MAKE THIS DIRAGAM
`vm_rb` is not the tree itself, it is just **this vma's hook** into our tree.

Then we have `rb_subtree_gap` at offset 56
```c
long unsigned int rb_subtree_gap;  /* 56  8 */
```
It stores the **largest free gap** below this node in the Red-Black tree. It is used by `mmap()` to quickly find a free address range without scanning everything. Everything discussed till now in `vm_area_struct` fits in the first cache line (bytes 0–63). The most performance critical fields for navigation are grouped here.

Then comes `vm_mm` at offset 64
```c
struct mm_struct *vm_mm;  /* 64  8 */
```

Pointer back to the **`mm_struct`** that owns this vma.

**`vm_flags`** at offset 80
```c
long unsigned int vm_flags;  /* 80  8 */
```
These are flags describing this VMA's properties:
```
VM_READ       region is readable
VM_WRITE      region is writable  
VM_EXEC       region is executable
VM_SHARED     shared mapping (vs private copy on write)
VM_GROWSDOWN  stack 
VM_LOCKED     pages locked in RAM (mlock)
```

This is what we see in `/proc/pid/maps` as `r-xp`, `rw-p` etc .GET FIAGRAMMM

**The union (shared / anon_name)** at offset 88
```c
union {
    struct {
        struct rb_node rb;           /* 88  24 */
        long unsigned int rb_subtree_last;  /* 112  8 */
    } shared;                        /* 88  32 */

    struct anon_vma_name *anon_name; /* 88   8 */
};                                   /* 88  32 */
```

- **`shared`** is used when the VMA is a **file backed mapping** (`mmap` of a file). The `rb node` links into the file's interval tree so the kernel can find all VMAs mapping a given file range.
- **`anon_name`** is used when the vma is an **anonymous mapping** (heap, stack, `mmap(MAP_ANONYMOUS)`). Optionally stores a name we set via `prctl(PR_SET_VMA)` and is visible in `/proc/pid/maps`.

They never coexist, so sharing memory here saves space.

So we now know that each VMA describes a region with the same, uniform properties, same permissions, same backing (file or anonymous), same flags etc. A process's full address space is the collection of all its VMAs. VMA regions in a process consist of:

- **Text segment** which is executable code (read + exec)
- **Data/BSS segment** which consists of initialized or uninitialized global variables
- **Heap** which is dynamically allocated memory
- **Stack** 
- **Memory-mapped files** such as `mmap()`ed files or shared libraries
- **Anonymous mappings** which is private memory not backed by a file
### How VMAs Are Organized

The kernel stores a process's VMAs in **two parallel data structures** for efficiency in kernel versions 6.1>:

| Structure              | Purpose                         |
| ---------------------- | ------------------------------- |
| **Doubly Linked list** | Simple iteration over all VMAs  |
| **Red-black tree**     | Fast O(log n) lookup by address |

Both are within `mm_struct`, which is the memory descriptor for a process (`task_struct->mm`).

A typical VMA lifecycle consists of the following steps: (make diagram)

```
mmap() / brk() / execve()
        │
        ▼
   do_mmap()  ──► allocates new vm_area_struct
        │
        ▼
   Inserted into mm_struct (list + rb-tree)
        │
        ▼
   Page fault occurs → kernel walks VMAs to find the right one
        │
        ▼
   munmap() / process exit → VMA removed and freed
```

We can see a process's VMAs from userspace:
```bash
# Human-readable map
cat /proc/<pid>/maps

# Detailed with extra info (inode, permissions, etc.)
cat /proc/<pid>/smaps
```

#### Entry points into VMAs

```c
struct vm_area_struct *mmap;       // head of the linked list (lowest VMA)
struct rb_root mm_rb;              // root of the red-black tree
```

These are the two fields that anchor everything we'll discuss below. Every VMA in the process is reachable from one or both of these.

```
task_struct (thread 1) ─────┐
task_struct (thread 2) ──────┤──► mm_struct
task_struct (thread 3) ─────┘        │
                                      ├── mmap ──► VMA → VMA → VMA → NULL   (linked list)
                                      ├── mm_rb ──► [rb tree root]           (rb tree)
                                      ├── pgd ──► [page tables]
                                      ├── brk, start_stack, mmap_base ...
                                      └── mmap_lock
```

Now we are done with the prerequisites, and lets now understand why we needed two data structures for managing our virtual memory areas in older kernels. 
### The Core Problem

We now know that a process's virtual address space is a collection of VMAs, with each covering a range of addresses. The kernel constantly needs to find which VMA contains a specific address queried by a process, or has to return all VMAs in an order when asked by fork() or munmap().
The problem is these two queries have **opposite requirements**.
### Why a Single Data Structure Can't Satisfy Both

A linked list alone couldn't be used because imagine if we needed an address `0x401234`, which was at the end of the linked list. It would take O(n) to reach our address. Imagine a linked list of 1000 VMAs, we would need to iterate over 999 VMAs to finally reach our VMA in the end of the linked list. Moreover, we have to deal with millions of page faults, dealing our page faults with a linked list would have created a complete havoc.

What if we assigned all these duties to a single red black tree alone? If we want to find the address  `0x401234` in a Red Black tree, it will take us maximum O(log n) time to reach our desired node which is pretty fast. But what if we need to iterate over all VMAs? We would have to do In-Order traversal of the tree, which does work, but is inefficient as it is cache unfriendly and each step jumps to an unpredictable memory location. 

So to cater these to queries, Linux kernel developers chose two structures.
### Why Each Structure Was Chosen

**The Red Black tree** was chosen for lookup because:
- VMAs are sorted by `vm_start` which is perfect for binary search
- Finding which VMA contains address X is just a binary search on ranges
- O(log n) even with thousands of VMAs
- Also stores `rb_subtree_gap`  the largest free gap below each node, making `mmap()` address selection fast

**The linked list** was chosen for iteration because:
- Sequential traversal is simply following `vm_next` pointers
- It is cache friendly since there is a predictable memory access pattern

### Summary of the Division of Labor

```
operation                        data structure used
─────────────────────────────────────────────────────
page fault → find vma by addr    rb tree   (O log n)
mmap → find free address gap     rb tree   (rb_subtree_gap)
fork → copy all vmas             linked list
/proc/pid/maps → list all vmas   linked list
munmap → iterate a range         linked list
mprotect → iterate a range       linked list
```

So these two structures complement each other. Each is doing a job the other cannot do efficiently.

We'll now look at exactly how both of these are used practically inside the kernel — the actual code paths that hit the rb tree during a page fault, and the ones that walk the linked list during a fork — and then we'll see why even this dual structure eventually wasn't enough, which is what motivated the transition to maple trees.
















## The Theory of RB Tree + Linked List Over VMAs

Now that we know what `mm_struct` holds, let us go deep on why the kernel uses two data structures and exactly how each one works.

---

### The Core Problem

The kernel needs to answer two fundamentally different questions about VMAs:

**Question 1 — "Give me the VMA that contains address X"** Asked during every page fault, every `mmap()`, every `munmap()`, every `mprotect()`. This is the hottest path in the entire VM subsystem. It needs to be O(log n).

**Question 2 — "Give me all VMAs in address order"** Asked during `fork()`, `exit()`, core dumps, `/proc/<pid>/maps`. This needs cheap sequential iteration — O(1) per step.

A single sorted linked list answers question 2 cheaply but question 1 in O(n). A pure RB tree answers question 1 in O(log n) but in-order traversal requires O(log n) per step (descending to find the successor each time). So the kernel keeps both, threading them through the same `vm_area_struct` nodes.

---

### The Linked List — Exactly How It Works

`mm_struct->mmap` points to the VMA with the lowest `vm_start`. Each VMA then has:

```c
struct vm_area_struct *vm_next;   // next higher address
struct vm_area_struct *vm_prev;   // next lower address
```

The invariant the kernel maintains at all times:

```
mmap->vm_start  <  mmap->vm_next->vm_start  <  mmap->vm_next->vm_next->vm_start  < ...
```

And importantly — **no two VMAs ever overlap**. Two VMAs cannot cover the same address. If you `mmap()` into an existing region, the kernel splits or removes existing VMAs first.

Iteration looks like this:

```c
struct vm_area_struct *vma;
for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
    // visit every VMA in address order
}
```

This is used in `exit_mmap()` to tear down every VMA on process exit, in `dup_mmap()` to copy VMAs on `fork()`, and in `walk_page_range()` to iterate VMAs for page table operations.

**Insertion into the linked list** is O(1) given you already know the predecessor — you just update `vm_next` and `vm_prev` pointers. The predecessor is found via the RB tree first (O(log n)), so the combined cost of inserting a new VMA into both structures is O(log n) dominated by the tree.

**The `vm_prev` pointer** was added in Linux 3.3. Before that the list was singly-linked, which made `munmap()` slightly awkward because you needed the predecessor. With `vm_prev`, any operation that already has a VMA pointer can walk backwards for free.

---

### The Red-Black Tree — Exactly How It Works

Every `vm_area_struct` embeds an `rb_node`:

```c
struct rb_node {
    unsigned long __rb_parent_color;  // parent pointer + color packed into one word
    struct rb_node *rb_right;
    struct rb_node *rb_left;
};
```

The color (red or black) is stored in the **lowest bit** of `__rb_parent_color` because pointers are always at least 4-byte aligned, making the bottom two bits always zero and thus free to steal. The parent pointer occupies the remaining bits. This is a common kernel space-saving trick.

The tree is keyed on `vm_start`. The invariants:

- Every node is either red or black
- The root is always black
- A red node's children are always black (no two consecutive reds)
- Every path from any node down to a NULL leaf passes through the same number of black nodes

These four rules together guarantee the tree height is at most `2 * log₂(n+1)`, giving true O(log n) worst-case for all operations.

---

### `find_vma()` — The Hot Path

This is called on every page fault. Here is the actual kernel logic:

```c
struct vm_area_struct *find_vma(struct mm_struct *mm, unsigned long addr)
{
    struct vm_area_struct *vma = NULL;
    struct rb_node *rb_node;

    rb_node = mm->mm_rb.rb_node;

    while (rb_node) {
        struct vm_area_struct *tmp;
        tmp = rb_entry(rb_node, struct vm_area_struct, vm_rb);

        if (tmp->vm_end > addr) {
            vma = tmp;
            if (tmp->vm_start <= addr)
                break;              // addr is inside this VMA — done
            rb_node = rb_node->rb_left;   // go left, might find earlier VMA
        } else {
            rb_node = rb_node->rb_right;  // addr is beyond this VMA, go right
        }
    }

    return vma;   // first VMA whose vm_end > addr, or NULL
}
```

Notice the return value: it is the **first VMA whose `vm_end > addr`**, not necessarily one that contains `addr`. The caller must check `addr >= vma->vm_start` to confirm containment. If there is no such VMA, `addr` is beyond all mappings → `SIGSEGV`.

This single function is one of the most frequently called functions in the entire kernel on workloads with many page faults.

---

### Inserting a New VMA — Both Structures Updated Together

When `mmap()` creates a new VMA, `__vma_link()` inserts it into both structures:

```c
static void __vma_link(struct mm_struct *mm,
                       struct vm_area_struct *vma,
                       struct vm_area_struct *prev,       // predecessor in LL
                       struct rb_node **rb_link,          // where to attach in tree
                       struct rb_node *rb_parent)         // parent node in tree
{
    __vma_link_list(mm, vma, prev);   // update vm_next / vm_prev
    __vma_link_rb(mm, vma, rb_link, rb_parent);  // rb_link_node + rb_insert_color
}
```

`rb_insert_color()` is where the rebalancing happens — it walks up the tree fixing color violations and performing rotations until all RB invariants hold. After it returns, both structures are consistent.

The predecessor `prev` and the RB insertion point `rb_link` are found together in a single downward pass through the RB tree before insertion, so no extra traversal is needed.

---

### Removing a VMA — `munmap()`

`munmap()` calls `remove_vma_list()` which calls `vma_rb_erase()` and then unlinks from the list:

```c
rb_erase(&vma->vm_rb, &mm->mm_rb);    // remove from rb tree + rebalance
__vma_unlink_list(mm, vma);            // update vm_next / vm_prev of neighbors
```

`rb_erase()` is the most complex operation — removing a node from an RB tree requires rebalancing which may involve rotations and color changes propagating up toward the root. The kernel's RB tree implementation handles all cases correctly in O(log n).

---

### VMA Merging — Keeping n Small

Every time a new VMA is inserted, the kernel calls `vma_merge()` to check whether it can be collapsed with adjacent VMAs. Two VMAs can merge if they are contiguous in address space and have identical flags, permissions, and backing (same file + same offset alignment, or both anonymous).

Merging matters because:

- Fewer VMAs means faster `find_vma()` (shallower tree)
- Fewer VMAs means less memory for `vm_area_struct` objects
- `map_count` stays well below `max_map_count`

The opposite happens with `mprotect()` — changing permissions on the middle of a VMA **splits** it into up to three pieces, each inserted into both structures independently.

---

### The `vmacache` — Avoiding the Tree Entirely

Because page faults are spatially local (a running program tends to touch the same few VMAs repeatedly), the kernel caches the last few VMAs looked up in a **per-thread cache** stored in `task_struct`:

```c
struct vmacache {
    u64 seqnum;           // invalidated when mm changes
    struct vm_area_struct *vmas[VMACACHE_SIZE];  // VMACACHE_SIZE = 4
};
```

`find_vma()` checks this cache first. On a hit it returns immediately without touching the RB tree at all. The cache is invalidated (via `seqnum`) whenever any VMA is added or removed from the `mm_struct`, ensuring stale entries are never returned.

In practice, the vmacache hit rate is very high for most workloads, meaning the RB tree is only consulted on cache misses.

---

### Why Not Just One Structure?

To make it concrete — imagine a process with 500 VMAs (not unusual for a large application with many shared libraries):

|Operation|Linked list only|RB tree only|Both|
|---|---|---|---|
|Page fault lookup|250 steps avg|9 steps (log₂500)|9 steps (tree)|
|fork() copy all VMAs|500 steps|~4500 steps (successor each time)|500 steps (list)|
|exit() free all VMAs|500 steps|~4500 steps|500 steps (list)|
|Insert new VMA|O(n) find position|O(log n)|O(log n)|

The linked list makes sequential operations fast. The RB tree makes address lookup fast. Together they cover every access pattern the VM subsystem needs. The cost is just the extra `vm_next`, `vm_prev`, and `vm_rb` fields in each `vm_area_struct`, which is a trivial memory overhead compared to the performance gain.
---

