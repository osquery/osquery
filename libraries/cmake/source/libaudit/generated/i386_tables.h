/* This is a generated file, see Makefile.am for its inputs. */
static const char i386_syscall_strings[] = "_llseek\0_newselect\0_sysctl\0access\0acct\0add_key\0adjtimex\0afs_syscall\0alarm\0bdflush\0"
	"bpf\0break\0brk\0capget\0capset\0chdir\0chmod\0chown\0chown32\0chroot\0"
	"clock_adjtime\0clock_getres\0clock_gettime\0clock_nanosleep\0clock_settime\0clone\0close\0creat\0create_module\0delete_module\0"
	"dup\0dup2\0dup3\0epoll_create\0epoll_create1\0epoll_ctl\0epoll_pwait\0epoll_wait\0eventfd\0eventfd2\0"
	"execve\0execveat\0exit\0exit_group\0faccessat\0fadvise64\0fadvise64_64\0fallocate\0fanotify_init\0fanotify_mark\0"
	"fchdir\0fchmod\0fchmodat\0fchown\0fchown32\0fchownat\0fcntl\0fcntl64\0fdatasync\0fgetxattr\0"
	"finit_module\0flistxattr\0flock\0fork\0fremovexattr\0fsetxattr\0fstat\0fstat64\0fstatat64\0fstatfs\0"
	"fstatfs64\0fsync\0ftime\0ftruncate\0ftruncate64\0futex\0futimesat\0get_kernel_syms\0get_mempolicy\0get_robust_list\0"
	"get_thread_area\0getcpu\0getcwd\0getdents\0getdents64\0getegid\0getegid32\0geteuid\0geteuid32\0getgid\0"
	"getgid32\0getgroups\0getgroups32\0getitimer\0getpgid\0getpgrp\0getpid\0getpmsg\0getppid\0getpriority\0"
	"getrandom\0getresgid\0getresgid32\0getresuid\0getresuid32\0getrlimit\0getrusage\0getsid\0gettid\0gettimeofday\0"
	"getuid\0getuid32\0getxattr\0gtty\0idle\0init_module\0inotify_add_watch\0inotify_init\0inotify_init1\0inotify_rm_watch\0"
	"io_cancel\0io_destroy\0io_getevents\0io_setup\0io_submit\0ioctl\0ioperm\0iopl\0ioprio_get\0ioprio_set\0"
	"ipc\0kcmp\0keyctl\0kill\0lchown\0lchown32\0lgetxattr\0link\0linkat\0listxattr\0"
	"llistxattr\0lock\0lookup_dcookie\0lremovexattr\0lseek\0lsetxattr\0lstat\0lstat64\0madvise\0madvise1\0"
	"mbind\0memfd_create\0migrate_pages\0mincore\0mkdir\0mkdirat\0mknod\0mknodat\0mlock\0mlockall\0"
	"mmap\0mmap2\0modify_ldt\0mount\0move_pages\0mprotect\0mpx\0mq_getsetattr\0mq_notify\0mq_open\0"
	"mq_timedreceive\0mq_timedsend\0mq_unlink\0mremap\0msync\0munlock\0munlockall\0munmap\0name_to_handle_at\0nanosleep\0"
	"nfsservctl\0nice\0oldfstat\0oldlstat\0oldolduname\0oldstat\0olduname\0open\0open_by_handle_at\0openat\0"
	"pause\0perf_event_open\0personality\0pipe\0pipe2\0pivot_root\0poll\0ppoll\0prctl\0pread64\0"
	"preadv\0prlimit64\0process_vm_readv\0process_vm_writev\0prof\0profil\0pselect6\0ptrace\0putpmsg\0pwrite64\0"
	"pwritev\0query_module\0quotactl\0read\0readahead\0readdir\0readlink\0readlinkat\0readv\0reboot\0"
	"recvmmsg\0remap_file_pages\0removexattr\0rename\0renameat\0renameat2\0request_key\0restart_syscall\0rmdir\0rt_sigaction\0"
	"rt_sigpending\0rt_sigprocmask\0rt_sigqueueinfo\0rt_sigreturn\0rt_sigsuspend\0rt_sigtimedwait\0rt_tgsigqueueinfo\0sched_get_priority_max\0sched_get_priority_min\0sched_getaffinity\0"
	"sched_getattr\0sched_getparam\0sched_getscheduler\0sched_rr_get_interval\0sched_setaffinity\0sched_setattr\0sched_setparam\0sched_setscheduler\0sched_yield\0seccomp\0"
	"select\0sendfile\0sendfile64\0sendmmsg\0set_mempolicy\0set_robust_list\0set_thread_area\0set_tid_address\0setdomainname\0setfsgid\0"
	"setfsgid32\0setfsuid\0setfsuid32\0setgid\0setgid32\0setgroups\0setgroups32\0sethostname\0setitimer\0setns\0"
	"setpgid\0setpriority\0setregid\0setregid32\0setresgid\0setresgid32\0setresuid\0setresuid32\0setreuid\0setreuid32\0"
	"setrlimit\0setsid\0settimeofday\0setuid\0setuid32\0setxattr\0sgetmask\0sigaction\0sigaltstack\0signal\0"
	"signalfd\0signalfd4\0sigpending\0sigprocmask\0sigreturn\0sigsuspend\0socketcall\0splice\0ssetmask\0stat\0"
	"stat64\0statfs\0statfs64\0stime\0stty\0swapoff\0swapon\0symlink\0symlinkat\0sync\0"
	"sync_file_range\0syncfs\0sys_kexec_load\0sysfs\0sysinfo\0syslog\0tee\0tgkill\0time\0timer_create\0"
	"timer_delete\0timer_getoverrun\0timer_gettime\0timer_settime\0timerfd\0timerfd_gettime\0timerfd_settime\0times\0tkill\0truncate\0"
	"truncate64\0ugetrlimit\0ulimit\0umask\0umount\0umount2\0uname\0unlink\0unlinkat\0unshare\0"
	"uselib\0ustat\0utime\0utimensat\0utimes\0vfork\0vhangup\0vm86\0vm86old\0vmsplice\0"
	"vserver\0wait4\0waitid\0waitpid\0write\0writev";
static const unsigned i386_syscall_s2i_s[] = {
	0,8,19,27,34,39,47,56,68,74,
	82,86,92,96,103,110,116,122,128,136,
	143,157,170,184,200,214,220,226,232,246,
	260,264,269,274,287,301,311,323,334,342,
	351,358,367,372,383,393,403,416,426,440,
	454,461,468,477,484,493,502,508,516,526,
	536,549,560,566,571,584,594,600,608,618,
	626,636,642,648,658,670,676,686,702,716,
	732,748,755,762,771,782,790,800,808,818,
	825,834,844,856,866,874,882,889,897,905,
	917,927,937,949,959,971,981,991,998,1005,
	1018,1025,1034,1043,1048,1053,1065,1083,1096,1110,
	1127,1137,1148,1161,1170,1180,1186,1193,1198,1209,
	1220,1224,1229,1236,1241,1248,1257,1267,1272,1279,
	1289,1300,1305,1320,1333,1339,1349,1355,1363,1371,
	1380,1386,1399,1413,1421,1427,1435,1441,1449,1455,
	1464,1469,1475,1486,1492,1503,1512,1516,1530,1540,
	1548,1564,1577,1587,1594,1600,1608,1619,1626,1644,
	1654,1665,1670,1679,1688,1700,1708,1717,1722,1740,
	1747,1753,1769,1781,1786,1792,1803,1808,1814,1820,
	1828,1835,1845,1862,1880,1885,1892,1901,1908,1916,
	1925,1933,1946,1955,1960,1970,1978,1987,1998,2004,
	2011,2020,2037,2049,2056,2065,2075,2087,2103,2109,
	2122,2136,2151,2167,2180,2194,2210,2228,2251,2274,
	2292,2306,2321,2340,2362,2380,2394,2409,2428,2440,
	2448,2455,2464,2475,2484,2498,2514,2530,2546,2560,
	2569,2580,2589,2600,2607,2616,2626,2638,2650,2660,
	2666,2674,2686,2695,2706,2716,2728,2738,2750,2759,
	2770,2780,2787,2800,2807,2816,2825,2834,2844,2856,
	2863,2872,2882,2893,2905,2915,2926,2937,2944,2953,
	2958,2965,2972,2981,2987,2992,3000,3007,3015,3025,
	3030,3046,3053,3068,3074,3082,3089,3093,3100,3105,
	3118,3131,3148,3162,3176,3184,3200,3216,3222,3228,
	3237,3248,3259,3266,3272,3279,3287,3293,3300,3309,
	3317,3324,3330,3336,3346,3353,3359,3367,3372,3380,
	3389,3397,3403,3410,3418,3424,
};
static const int i386_syscall_s2i_i[] = {
	140,142,149,33,51,286,124,137,27,134,
	357,17,45,184,185,12,15,182,212,61,
	343,266,265,267,264,120,6,8,127,129,
	41,63,330,254,329,255,319,256,323,328,
	11,358,1,252,307,250,272,324,338,339,
	133,94,306,95,207,298,55,221,148,231,
	350,234,143,2,237,228,108,197,300,100,
	269,118,35,93,194,240,299,130,275,312,
	244,318,183,141,220,50,202,49,201,47,
	200,80,205,105,132,65,20,188,64,96,
	355,171,211,165,209,76,77,147,224,78,
	24,199,229,32,112,128,292,291,332,293,
	249,246,247,245,248,54,101,110,290,289,
	117,349,288,37,16,198,230,9,303,232,
	233,53,253,236,19,227,107,196,219,219,
	274,356,294,218,39,296,14,297,150,152,
	90,192,123,21,317,125,56,282,281,277,
	280,279,278,163,144,151,153,91,341,162,
	169,34,28,84,59,18,109,5,342,295,
	29,336,136,42,331,217,168,309,172,180,
	333,340,347,348,44,98,308,26,189,181,
	334,167,131,3,225,89,85,305,145,88,
	337,257,235,38,302,353,287,0,40,174,
	176,175,178,173,179,177,335,159,160,242,
	352,155,157,161,241,351,154,156,158,354,
	82,187,239,345,276,311,243,258,121,139,
	216,138,215,46,214,81,206,74,104,346,
	57,97,71,204,170,210,164,208,70,203,
	75,66,79,23,213,226,68,67,186,48,
	321,327,73,126,119,72,102,313,69,106,
	195,99,268,25,31,115,87,83,304,36,
	314,344,283,135,116,103,315,270,13,259,
	263,262,261,260,322,326,325,43,238,92,
	193,191,58,60,22,52,122,10,301,310,
	86,62,30,320,271,190,111,166,113,316,
	273,114,284,7,4,146,
};
static int i386_syscall_s2i(const char *s, int *value) {
	size_t len, i;
	len = strlen(s);
	{ char copy[len + 1];
	for (i = 0; i < len; i++) {
		char c = s[i];
		copy[i] = GT_ISUPPER(c) ? c - 'A' + 'a' : c;
	}
	copy[i] = 0;
	return s2i__(i386_syscall_strings, i386_syscall_s2i_s, i386_syscall_s2i_i, 356, copy, value);
	}
}
static const unsigned i386_syscall_i2s_direct[] = {
	2087,367,566,1955,3418,1717,220,3410,226,1267,
	3293,351,110,3100,1435,116,1241,86,1700,1333,
	882,1486,3272,2800,1018,2981,1901,68,1670,1747,
	3330,2987,1043,27,1665,642,3025,1236,2049,1421,
	2103,260,1781,3216,1880,92,2600,818,2856,800,
	782,34,3279,1300,1180,502,1512,2666,3259,1688,
	3266,136,3324,264,897,874,2780,2834,2825,2944,
	2750,2686,2915,2882,2638,2770,971,981,1005,2787,
	834,2616,2448,3007,1679,1978,3317,3000,2004,1970,
	1464,1619,3228,648,461,477,905,2674,1885,2965,
	618,1186,2926,3082,2650,856,2953,1349,594,1708,
	1193,3359,1048,3372,3397,2992,3074,1220,636,2905,
	214,2546,3287,1475,47,1503,2893,232,1053,246,
	686,1946,866,454,74,3068,1769,56,2580,2560,
	0,762,8,560,1594,1998,3424,991,516,19,
	1449,1600,1455,1608,2394,2306,2409,2321,2428,2228,
	2251,2340,1644,1587,2728,949,3367,1933,1803,1654,
	2706,927,1814,2167,2109,2136,2122,2194,2151,2180,
	1820,1916,122,755,96,103,2844,2455,889,1908,
	3353,3248,1469,3237,658,2958,1355,600,1248,1025,
	825,808,790,2759,2695,844,2626,484,2738,959,
	2716,937,128,2807,2607,2589,2569,1792,1413,1363,
	771,508,-1u,-1u,998,1960,2816,1339,584,1034,
	1257,526,1279,1289,549,2037,1320,571,3222,2464,
	670,2362,2274,2514,732,1161,1137,1148,1170,1127,
	393,-1u,372,1305,274,301,323,2020,2530,3105,
	3162,3148,3131,3118,200,170,157,184,2972,626,
	3093,3346,403,3389,1380,702,2484,1540,1577,1564,
	1548,1530,1516,3053,3403,-1u,39,2075,1229,1209,
	1198,1083,1065,1110,1399,1740,1427,1441,493,676,
	608,3300,2056,1272,3015,1987,468,383,1892,1808,
	3309,2498,716,2937,3030,3089,3380,1492,748,311,
	3336,2863,3176,334,416,3200,3184,2872,342,287,
	269,1786,1096,1828,1925,2210,1753,2011,426,440,
	1835,1626,1722,143,3046,2475,2660,1845,1862,1224,
	536,2380,2292,2065,2440,917,1386,82,358,
};
static const char *i386_syscall_i2s(int v) {
	return i2s_direct__(i386_syscall_strings, i386_syscall_i2s_direct, 0, 358, v);
}
