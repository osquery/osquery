/* This is a generated file, see Makefile.am for its inputs. */
static const char x86_64_syscall_strings[] = "_sysctl\0accept\0accept4\0access\0acct\0add_key\0adjtimex\0afs_syscall\0alarm\0arch_prctl\0"
	"bind\0bpf\0brk\0capget\0capset\0chdir\0chmod\0chown\0chroot\0clock_adjtime\0"
	"clock_getres\0clock_gettime\0clock_nanosleep\0clock_settime\0clone\0close\0connect\0creat\0create_module\0delete_module\0"
	"dup\0dup2\0dup3\0epoll_create\0epoll_create1\0epoll_ctl\0epoll_ctl_old\0epoll_pwait\0epoll_wait\0epoll_wait_old\0"
	"eventfd\0eventfd2\0execve\0execveat\0exit\0exit_group\0faccessat\0fadvise64\0fallocate\0fanotify_init\0"
	"fanotify_mark\0fchdir\0fchmod\0fchmodat\0fchown\0fchownat\0fcntl\0fdatasync\0fgetxattr\0finit_module\0"
	"flistxattr\0flock\0fork\0fremovexattr\0fsetxattr\0fstat\0fstatfs\0fsync\0ftruncate\0futex\0"
	"futimesat\0get_kernel_syms\0get_mempolicy\0get_robust_list\0get_thread_area\0getcpu\0getcwd\0getdents\0getdents64\0getegid\0"
	"geteuid\0getgid\0getgroups\0getitimer\0getpeername\0getpgid\0getpgrp\0getpid\0getpmsg\0getppid\0"
	"getpriority\0getrandom\0getresgid\0getresuid\0getrlimit\0getrusage\0getsid\0getsockname\0getsockopt\0gettid\0"
	"gettimeofday\0getuid\0getxattr\0init_module\0inotify_add_watch\0inotify_init\0inotify_init1\0inotify_rm_watch\0io_cancel\0io_destroy\0"
	"io_getevents\0io_setup\0io_submit\0ioctl\0ioperm\0iopl\0ioprio_get\0ioprio_set\0kcmp\0kexec_file_load\0"
	"kexec_load\0keyctl\0kill\0lchown\0lgetxattr\0link\0linkat\0listen\0listxattr\0llistxattr\0"
	"lookup_dcookie\0lremovexattr\0lseek\0lsetxattr\0lstat\0madvise\0mbind\0memfd_create\0migrate_pages\0mincore\0"
	"mkdir\0mkdirat\0mknod\0mknodat\0mlock\0mlockall\0mmap\0modify_ldt\0mount\0move_pages\0"
	"mprotect\0mq_getsetattr\0mq_notify\0mq_open\0mq_timedreceive\0mq_timedsend\0mq_unlink\0mremap\0msgctl\0msgget\0"
	"msgrcv\0msgsnd\0msync\0munlock\0munlockall\0munmap\0name_to_handle_at\0nanosleep\0newfstatat\0nfsservctl\0"
	"open\0open_by_handle_at\0openat\0pause\0perf_event_open\0personality\0pipe\0pipe2\0pivot_root\0poll\0"
	"ppoll\0prctl\0pread\0preadv\0prlimit64\0process_vm_readv\0process_vm_writev\0pselect6\0ptrace\0putpmsg\0"
	"pwrite\0pwritev\0query_module\0quotactl\0read\0readahead\0readlink\0readlinkat\0readv\0reboot\0"
	"recvfrom\0recvmmsg\0recvmsg\0remap_file_pages\0removexattr\0rename\0renameat\0renameat2\0request_key\0restart_syscall\0"
	"rmdir\0rt_sigaction\0rt_sigpending\0rt_sigprocmask\0rt_sigqueueinfo\0rt_sigreturn\0rt_sigsuspend\0rt_sigtimedwait\0rt_tgsigqueueinfo\0sched_get_priority_max\0"
	"sched_get_priority_min\0sched_getaffinity\0sched_getattr\0sched_getparam\0sched_getscheduler\0sched_rr_get_interval\0sched_setaffinity\0sched_setattr\0sched_setparam\0sched_setscheduler\0"
	"sched_yield\0seccomp\0security\0select\0semctl\0semget\0semop\0semtimedop\0sendfile\0sendmmsg\0"
	"sendmsg\0sendto\0set_mempolicy\0set_robust_list\0set_thread_area\0set_tid_address\0setdomainname\0setfsgid\0setfsuid\0setgid\0"
	"setgroups\0sethostname\0setitimer\0setns\0setpgid\0setpriority\0setregid\0setresgid\0setresuid\0setreuid\0"
	"setrlimit\0setsid\0setsockopt\0settimeofday\0setuid\0setxattr\0shmat\0shmctl\0shmdt\0shmget\0"
	"shutdown\0sigaltstack\0signalfd\0signalfd4\0socket\0socketpair\0splice\0stat\0statfs\0swapoff\0"
	"swapon\0symlink\0symlinkat\0sync\0sync_file_range\0syncfs\0sysfs\0sysinfo\0syslog\0tee\0"
	"tgkill\0time\0timer_create\0timer_delete\0timer_getoverrun\0timer_gettime\0timer_settime\0timerfd\0timerfd_gettime\0timerfd_settime\0"
	"times\0tkill\0truncate\0tuxcall\0umask\0umount2\0uname\0unlink\0unlinkat\0unshare\0"
	"uselib\0ustat\0utime\0utimensat\0utimes\0vfork\0vhangup\0vmsplice\0vserver\0wait4\0"
	"waitid\0write\0writev";
static const unsigned x86_64_syscall_s2i_s[] = {
	0,8,15,23,30,35,43,52,64,70,
	81,86,90,94,101,108,114,120,126,133,
	147,160,174,190,204,210,216,224,230,244,
	258,262,267,272,285,299,309,323,335,346,
	361,369,378,385,394,399,410,420,430,440,
	454,468,475,482,491,498,507,513,523,533,
	546,557,563,568,581,591,597,605,611,621,
	627,637,653,667,683,699,706,713,722,733,
	741,749,756,766,776,788,796,804,811,819,
	827,839,849,859,869,879,889,896,908,919,
	926,939,946,955,967,985,998,1012,1029,1039,
	1050,1063,1072,1082,1088,1095,1100,1111,1122,1127,
	1143,1154,1161,1166,1173,1183,1188,1195,1202,1212,
	1223,1238,1251,1257,1267,1273,1281,1287,1300,1314,
	1322,1328,1336,1342,1350,1356,1365,1370,1381,1387,
	1398,1407,1421,1431,1439,1455,1468,1478,1485,1492,
	1499,1506,1513,1519,1527,1538,1545,1563,1573,1584,
	1595,1600,1618,1625,1631,1647,1659,1664,1670,1681,
	1686,1692,1698,1704,1711,1721,1738,1756,1765,1772,
	1780,1787,1795,1808,1817,1822,1832,1841,1852,1858,
	1865,1874,1883,1891,1908,1920,1927,1936,1946,1958,
	1974,1980,1993,2007,2022,2038,2051,2065,2081,2099,
	2122,2145,2163,2177,2192,2211,2233,2251,2265,2280,
	2299,2311,2319,2328,2335,2342,2349,2355,2366,2375,
	2384,2392,2399,2413,2429,2445,2461,2475,2484,2493,
	2500,2510,2522,2532,2538,2546,2558,2567,2577,2587,
	2596,2606,2613,2624,2637,2644,2653,2659,2666,2672,
	2679,2688,2700,2709,2719,2726,2737,2744,2749,2756,
	2764,2771,2779,2789,2794,2810,2817,2823,2831,2838,
	2842,2849,2854,2867,2880,2897,2911,2925,2933,2949,
	2965,2971,2977,2986,2994,3000,3008,3014,3021,3030,
	3038,3045,3051,3057,3067,3074,3080,3088,3097,3105,
	3111,3118,3124,
};
static const int x86_64_syscall_s2i_i[] = {
	156,43,288,21,163,248,159,183,37,158,
	49,321,12,125,126,80,90,92,161,305,
	229,228,230,227,56,3,42,85,174,176,
	32,33,292,213,291,233,214,281,232,215,
	284,290,59,322,60,231,269,221,285,300,
	301,81,91,268,93,260,72,75,193,313,
	196,73,57,199,190,5,138,74,77,202,
	261,177,239,274,211,309,79,78,217,108,
	107,104,115,36,52,121,111,39,181,110,
	140,318,120,118,97,98,124,51,55,186,
	96,102,191,175,254,253,294,255,210,207,
	208,206,209,16,173,172,252,251,312,320,
	246,250,62,94,192,86,265,50,194,195,
	212,198,8,189,6,28,237,319,256,27,
	83,258,133,259,149,151,9,154,165,279,
	10,245,244,240,243,242,241,25,71,68,
	70,69,26,150,152,11,303,35,262,180,
	2,304,257,34,298,135,22,293,155,7,
	271,157,17,295,302,310,311,270,101,182,
	18,296,178,179,0,187,89,267,19,169,
	45,299,47,216,197,82,264,316,249,219,
	84,13,127,14,129,15,130,128,297,146,
	147,204,315,143,145,148,203,314,142,144,
	24,317,185,23,66,64,65,220,40,307,
	46,44,238,273,205,218,171,123,122,106,
	116,170,38,308,109,141,114,119,117,113,
	160,112,54,164,105,188,30,31,67,29,
	48,131,282,289,41,53,275,4,137,168,
	167,88,266,162,277,306,139,99,103,276,
	234,201,222,226,225,224,223,283,287,286,
	100,200,76,184,95,166,63,87,263,272,
	134,136,132,280,235,58,153,278,236,61,
	247,1,20,
};
static int x86_64_syscall_s2i(const char *s, int *value) {
	size_t len, i;
	len = strlen(s);
	{ char copy[len + 1];
	for (i = 0; i < len; i++) {
		char c = s[i];
		copy[i] = GT_ISUPPER(c) ? c - 'A' + 'a' : c;
	}
	copy[i] = 0;
	return s2i__(x86_64_syscall_strings, x86_64_syscall_s2i_s, x86_64_syscall_s2i_i, 323, copy, value);
	}
}
static const unsigned x86_64_syscall_i2s_direct[] = {
	1817,3118,1595,210,2744,591,1267,1681,1251,1365,
	1398,1538,90,1980,2007,2038,1082,1698,1780,1852,
	3124,23,1659,2328,2299,1478,1513,1314,1273,2672,
	2653,2659,258,262,1625,1563,766,64,2522,804,
	2366,2719,216,8,2392,1865,2384,1883,2679,81,
	1195,896,776,2726,2613,908,204,563,3074,378,
	394,3105,1161,3008,2342,2349,2335,2666,1492,1506,
	1499,1485,507,557,605,513,2977,611,713,706,
	108,468,1920,1322,1974,224,1183,3014,2771,1832,
	114,475,120,491,1166,2994,926,869,879,2823,
	2965,1765,939,2831,749,2637,2493,741,733,2538,
	819,796,2606,2587,2558,756,2500,2577,859,2567,
	849,788,2484,2475,889,94,101,1993,2065,2022,
	2051,2688,3051,1336,3038,1647,3045,2749,597,2817,
	827,2546,2265,2177,2280,2192,2099,2122,2211,1350,
	1519,1356,1527,3080,1370,1670,0,1692,70,43,
	2596,126,2789,30,2624,1381,3000,2764,2756,1858,
	2510,2461,1095,1088,230,955,244,637,1795,1808,
	1584,811,1772,52,2986,2319,919,1822,2644,1257,
	581,946,1173,523,1202,1212,546,1908,1238,568,
	2971,2849,621,2233,2145,2429,1063,1039,1050,1072,
	1029,683,1223,272,309,346,1891,722,2445,1958,
	2355,420,2854,2911,2897,2880,2867,190,160,147,
	174,399,335,299,2842,3067,3097,1281,2399,653,
	1431,1468,1455,1439,1421,1407,1143,3111,35,1946,
	1154,1111,1100,985,967,1012,1300,1618,1328,1342,
	498,627,1573,3021,1927,1188,2779,1841,482,410,
	1756,1686,3030,2413,667,2737,2838,2794,3088,1387,
	3057,323,2700,2925,361,430,2949,2933,15,2709,
	369,285,267,1664,998,1704,1787,2081,1631,1874,
	440,454,1711,1545,1600,133,2810,2375,2532,699,
	1721,1738,1122,533,2251,2163,1936,2311,839,1287,
	1127,86,385,
};
static const char *x86_64_syscall_i2s(int v) {
	return i2s_direct__(x86_64_syscall_strings, x86_64_syscall_i2s_direct, 0, 322, v);
}
