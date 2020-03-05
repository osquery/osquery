/* This is a generated file, see Makefile.am for its inputs. */
static const char s390_syscall_strings[] = "_llseek\0_newselect\0_sysctl\0access\0acct\0add_key\0adjtimex\0afs_syscall\0alarm\0bdflush\0"
	"bpf\0brk\0capget\0capset\0chdir\0chmod\0chown\0chown32\0chroot\0clock_adjtime\0"
	"clock_getres\0clock_gettime\0clock_nanosleep\0clock_settime\0clone\0close\0creat\0create_module\0delete_module\0dup\0"
	"dup2\0dup3\0epoll_create\0epoll_create1\0epoll_ctl\0epoll_pwait\0epoll_wait\0eventfd\0eventfd2\0execve\0"
	"execveat\0exit\0exit_group\0faccessat\0fadvise64\0fadvise64_64\0fallocate\0fanotify_init\0fanotify_mark\0fchdir\0"
	"fchmod\0fchmodat\0fchown\0fchown32\0fchownat\0fcntl\0fcntl64\0fdatasync\0fgetxattr\0finit_module\0"
	"flistxattr\0flock\0fork\0fremovexattr\0fsetxattr\0fstat\0fstat64\0fstatat64\0fstatfs\0fstatfs64\0"
	"fsync\0ftruncate\0ftruncate64\0futex\0futimesat\0get_kernel_syms\0get_robust_list\0getcpu\0getcwd\0getdents\0"
	"getdents64\0getegid\0getegid32\0geteuid\0geteuid32\0getgid\0getgid32\0getgroups\0getgroups32\0getitimer\0"
	"getpgid\0getpgrp\0getpid\0getpmsg\0getppid\0getpriority\0getrandom\0getresgid\0getresgid32\0getresuid\0"
	"getresuid32\0getrlimit\0getrusage\0getsid\0gettid\0gettimeofday\0getuid\0getuid32\0getxattr\0idle\0"
	"init_module\0inotify_add_watch\0inotify_init\0inotify_init1\0inotify_rm_watch\0io_cancel\0io_destroy\0io_getevents\0io_setup\0io_submit\0"
	"ioctl\0ioperm\0ioprio_get\0ioprio_set\0ipc\0kcmp\0kexec_load\0keyctl\0kill\0lchown\0"
	"lchown32\0lgetxattr\0link\0linkat\0listxattr\0llistxattr\0lremovexattr\0lseek\0lsetxattr\0lstat\0"
	"lstat64\0madvise\0memfd_create\0mincore\0mkdir\0mkdirat\0mknod\0mknodat\0mlock\0mlockall\0"
	"mmap\0mmap2\0mount\0mprotect\0mq_getsetattr\0mq_notify\0mq_open\0mq_timedreceive\0mq_timedsend\0mq_unlink\0"
	"mremap\0msync\0munlock\0munlockall\0munmap\0name_to_handle_at\0nanosleep\0nfsservctl\0nice\0open\0"
	"open_by_handle_at\0openat\0pause\0perf_event_open\0personality\0pipe\0pipe2\0pivot_root\0poll\0ppoll\0"
	"prctl\0pread\0preadv\0prlimit64\0process_vm_readv\0process_vm_writev\0pselect6\0ptrace\0putpmsg\0pwrite\0"
	"pwritev\0query_module\0quotactl\0read\0readahead\0readdir\0readlink\0readlinkat\0readv\0reboot\0"
	"remap_file_pages\0removexattr\0rename\0renameat\0renameat2\0request_key\0rmdir\0rt_sigaction\0rt_sigpending\0rt_sigprocmask\0"
	"rt_sigqueueinfo\0rt_sigreturn\0rt_sigsuspend\0rt_sigtimedwait\0rt_tgsigqueueinfo\0s390_pci_mmio_read\0s390_pci_mmio_write\0s390_runtime_instr\0sched_get_priority_max\0sched_get_priority_min\0"
	"sched_getaffinity\0sched_getattr\0sched_getparam\0sched_getscheduler\0sched_rr_get_interval\0sched_setaffinity\0sched_setattr\0sched_setparam\0sched_setscheduler\0sched_yield\0"
	"seccomp\0sendfile\0sendfile64\0set_robust_list\0set_tid_address\0setdomainname\0setfsgid\0setfsgid32\0setfsuid\0setfsuid32\0"
	"setgid\0setgid32\0setgroups\0setgroups32\0sethostname\0setitimer\0setns\0setpgid\0setpriority\0setregid\0"
	"setregid32\0setresgid\0setresgid32\0setresuid\0setresuid32\0setreuid\0setreuid32\0setrlimit\0setsid\0settimeofday\0"
	"setuid\0setuid32\0setxattr\0sigaction\0sigaltstack\0signal\0signalfd\0signalfd4\0sigpending\0sigprocmask\0"
	"sigreturn\0sigsuspend\0socketcall\0splice\0stat\0stat64\0statfs\0statfs64\0stime\0swapoff\0"
	"swapon\0symlink\0symlinkat\0sync\0sync_file_range\0syncfs\0sysfs\0sysinfo\0syslog\0tee\0"
	"tgkill\0time\0timer_create\0timer_delete\0timer_getoverrun\0timer_gettime\0timer_settime\0timerfd\0timerfd_create\0timerfd_gettime\0"
	"timerfd_settime\0times\0tkill\0truncate\0truncate64\0ugetrlimit\0umask\0umount\0umount2\0uname\0"
	"unlink\0unlinkat\0unshare\0uselib\0ustat\0utime\0utimensat\0utimes\0vfork\0vhangup\0"
	"vmsplice\0wait4\0waitid\0write\0writev";
static const unsigned s390_syscall_s2i_s[] = {
	0,8,19,27,34,39,47,56,68,74,
	82,86,90,97,104,110,116,122,130,137,
	151,164,178,194,208,214,220,226,240,254,
	258,263,268,281,295,305,317,328,336,345,
	352,361,366,377,387,397,410,420,434,448,
	455,462,471,478,487,496,502,510,520,530,
	543,554,560,565,578,588,594,602,612,620,
	630,636,646,658,664,674,690,706,713,720,
	729,740,748,758,766,776,783,792,802,814,
	824,832,840,847,855,863,875,885,895,907,
	917,929,939,949,956,963,976,983,992,1001,
	1006,1018,1036,1049,1063,1080,1090,1101,1114,1123,
	1133,1139,1146,1157,1168,1172,1177,1188,1195,1200,
	1207,1216,1226,1231,1238,1248,1259,1272,1278,1288,
	1294,1302,1310,1323,1331,1337,1345,1351,1359,1365,
	1374,1379,1385,1391,1400,1414,1424,1432,1448,1461,
	1471,1478,1484,1492,1503,1510,1528,1538,1549,1554,
	1559,1577,1584,1590,1606,1618,1623,1629,1640,1645,
	1651,1657,1663,1670,1680,1697,1715,1724,1731,1739,
	1746,1754,1767,1776,1781,1791,1799,1808,1819,1825,
	1832,1849,1861,1868,1877,1887,1899,1905,1918,1932,
	1947,1963,1976,1990,2006,2024,2043,2063,2082,2105,
	2128,2146,2160,2175,2194,2216,2234,2248,2263,2282,
	2294,2302,2311,2322,2338,2354,2368,2377,2388,2397,
	2408,2415,2424,2434,2446,2458,2468,2474,2482,2494,
	2503,2514,2524,2536,2546,2558,2567,2578,2588,2595,
	2608,2615,2624,2633,2643,2655,2662,2671,2681,2692,
	2704,2714,2725,2736,2743,2748,2755,2762,2771,2777,
	2785,2792,2800,2810,2815,2831,2838,2844,2852,2859,
	2863,2870,2875,2888,2901,2918,2932,2946,2954,2969,
	2985,3001,3007,3013,3022,3033,3044,3050,3057,3065,
	3071,3078,3087,3095,3102,3108,3114,3124,3131,3137,
	3145,3154,3160,3167,3173,
};
static const int s390_syscall_s2i_i[] = {
	140,142,149,33,51,278,124,137,27,134,
	351,45,184,185,12,15,182,212,61,337,
	261,260,262,259,120,6,8,127,129,41,
	63,326,249,327,250,312,251,318,323,11,
	354,1,248,300,253,264,314,332,333,133,
	94,299,95,207,291,55,221,148,229,344,
	232,143,2,235,226,108,197,293,100,266,
	118,93,194,238,292,130,305,311,183,141,
	220,50,202,49,201,47,200,80,205,105,
	132,65,20,188,64,96,349,171,211,165,
	209,76,77,147,236,78,24,199,227,112,
	128,285,284,324,286,247,244,245,243,246,
	54,101,283,282,117,343,277,280,37,16,
	198,228,9,296,230,231,234,19,225,107,
	196,219,350,218,39,289,14,290,150,152,
	90,192,21,125,276,275,271,274,273,272,
	163,144,151,153,91,335,162,169,34,5,
	336,288,29,331,136,42,325,217,168,302,
	172,180,328,334,340,341,301,26,189,181,
	329,167,131,3,222,89,85,298,145,88,
	267,233,38,295,347,279,40,174,176,175,
	178,173,179,177,330,353,352,342,159,160,
	240,346,155,157,161,239,345,154,156,158,
	348,187,223,304,252,121,139,216,138,215,
	46,214,81,206,74,104,339,57,97,71,
	204,170,210,164,208,70,203,75,66,79,
	23,213,224,67,186,48,316,322,73,126,
	119,72,102,306,106,195,99,265,25,115,
	87,83,297,36,307,338,135,116,103,308,
	241,13,254,258,257,256,255,317,319,321,
	320,43,237,92,193,191,60,22,52,122,
	10,294,303,86,62,30,315,313,190,111,
	309,114,281,4,146,
};
static int s390_syscall_s2i(const char *s, int *value) {
	size_t len, i;
	len = strlen(s);
	{ char copy[len + 1];
	for (i = 0; i < len; i++) {
		char c = s[i];
		copy[i] = GT_ISUPPER(c) ? c - 'A' + 'a' : c;
	}
	copy[i] = 0;
	return s2i__(s390_syscall_strings, s390_syscall_s2i_s, s390_syscall_s2i_i, 325, copy, value);
	}
}
static const unsigned s390_syscall_i2s_direct[] = {
	361,560,1776,3167,1554,214,-1u,220,1226,3071,
	345,104,2870,1345,110,1200,-1u,-1u,1272,840,
	1385,3050,2608,976,2771,1724,68,-1u,1584,3108,
	-1u,-1u,27,1549,-1u,2810,1195,1861,1331,1899,
	254,1618,3001,-1u,86,2408,776,2655,758,740,
	34,3057,-1u,1133,496,-1u,2474,-1u,-1u,3044,
	130,3102,258,855,832,2588,2633,-1u,-1u,2558,
	2494,2714,2681,2446,2578,929,939,963,2595,792,
	2424,-1u,2792,-1u,1799,3095,2785,1825,1791,1374,
	1503,3013,636,455,471,863,2482,-1u,2755,612,
	1139,2725,2852,2458,814,2743,1288,588,-1u,-1u,
	3137,1001,-1u,3154,2777,2844,1168,630,2704,208,
	2354,3065,-1u,47,1391,2692,226,1006,240,674,
	1767,824,448,74,2838,1606,56,2388,2368,0,
	720,8,554,1478,1819,3173,949,510,19,1359,
	1484,1365,1492,2248,2160,2263,2175,2282,2082,2105,
	2194,1528,1471,2536,907,-1u,1754,1640,1538,2514,
	885,1651,1963,1905,1932,1918,1990,1947,1976,1657,
	1739,116,713,90,97,2643,2302,847,1731,3131,
	3033,1379,3022,646,2748,1294,594,1207,983,783,
	766,748,2567,2503,802,2434,478,2546,917,2524,
	895,122,2615,2415,2397,2377,1629,1323,1302,729,
	502,1781,2311,2624,1278,578,992,1216,520,1238,
	1248,543,1849,1259,565,956,3007,658,2216,2128,
	2863,-1u,1114,1090,1101,1123,1080,366,268,295,
	317,2338,387,2875,2932,2918,2901,2888,194,164,
	151,178,-1u,397,2762,620,1832,-1u,-1u,-1u,
	1424,1461,1448,1432,1414,1400,1177,39,1887,1188,
	3160,1157,1146,1036,1018,1063,-1u,1577,1337,1351,
	487,664,602,3078,1868,1231,2800,1808,462,377,
	1715,1645,3087,2322,690,2736,2815,2859,3145,-1u,
	706,305,3124,410,3114,2662,2946,328,2954,2985,
	2969,2671,336,1049,1623,263,281,1663,1746,2006,
	1590,420,434,1670,1510,1559,137,2831,2468,1680,
	1697,2063,1172,530,2234,2146,1877,2294,875,1310,
	82,2043,2024,352,
};
static const char *s390_syscall_i2s(int v) {
	return i2s_direct__(s390_syscall_strings, s390_syscall_i2s_direct, 1, 354, v);
}
