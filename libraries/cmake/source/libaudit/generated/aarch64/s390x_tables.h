/* This is a generated file, see Makefile.am for its inputs. */
static const char s390x_syscall_strings[] = "_sysctl\0access\0acct\0add_key\0adjtimex\0afs_syscall\0alarm\0bdflush\0bpf\0brk\0"
	"capget\0capset\0chdir\0chmod\0chown\0chroot\0clock_adjtime\0clock_getres\0clock_gettime\0clock_nanosleep\0"
	"clock_settime\0clone\0close\0creat\0create_module\0delete_module\0dup\0dup2\0dup3\0epoll_create\0"
	"epoll_create1\0epoll_ctl\0epoll_pwait\0epoll_wait\0eventfd\0eventfd2\0execve\0execveat\0exit\0exit_group\0"
	"faccessat\0fadvise64\0fallocate\0fanotify_init\0fanotify_mark\0fchdir\0fchmod\0fchmodat\0fchown\0fchownat\0"
	"fcntl\0fdatasync\0fgetxattr\0finit_module\0flistxattr\0flock\0fork\0fremovexattr\0fsetxattr\0fstat\0"
	"fstatfs\0fstatfs64\0fsync\0ftruncate\0futex\0futimesat\0get_kernel_syms\0get_robust_list\0getcpu\0getcwd\0"
	"getdents\0getegid\0geteuid\0getgid\0getgroups\0getitimer\0getpgid\0getpgrp\0getpid\0getpmsg\0"
	"getppid\0getpriority\0getrandom\0getresgid\0getresuid\0getrlimit\0getrusage\0getsid\0gettid\0gettimeofday\0"
	"getuid\0getxattr\0idle\0init_module\0inotify_add_watch\0inotify_init\0inotify_init1\0inotify_rm_watch\0io_cancel\0io_destroy\0"
	"io_getevents\0io_setup\0io_submit\0ioctl\0ioprio_get\0ioprio_set\0ipc\0kcmp\0kexec_load\0keyctl\0"
	"kill\0lchown\0lgetxattr\0link\0linkat\0listxattr\0llistxattr\0lremovexattr\0lseek\0lsetxattr\0"
	"lstat\0madvise\0memfd_create\0mincore\0mkdir\0mkdirat\0mknod\0mknodat\0mlock\0mlockall\0"
	"mmap\0mount\0mprotect\0mq_getsetattr\0mq_notify\0mq_open\0mq_timedreceive\0mq_timedsend\0mq_unlink\0mremap\0"
	"msync\0munlock\0munlockall\0munmap\0name_to_handle_at\0nanosleep\0newfstatat\0nfsservctl\0nice\0open\0"
	"open_by_handle_at\0openat\0pause\0perf_event_open\0personality\0pipe\0pipe2\0pivot_root\0poll\0ppoll\0"
	"prctl\0pread\0preadv\0prlimit64\0process_vm_readv\0process_vm_writev\0pselect6\0ptrace\0putpmsg\0pwrite\0"
	"pwritev\0query_module\0quotactl\0read\0readahead\0readdir\0readlink\0readlinkat\0readv\0reboot\0"
	"remap_file_pages\0removexattr\0rename\0renameat\0renameat2\0request_key\0rmdir\0rt_sigaction\0rt_sigpending\0rt_sigprocmask\0"
	"rt_sigqueueinfo\0rt_sigreturn\0rt_sigsuspend\0rt_sigtimedwait\0rt_tgsigqueueinfo\0s390_pci_mmio_read\0s390_pci_mmio_write\0s390_runtime_instr\0sched_get_priority_max\0sched_get_priority_min\0"
	"sched_getaffinity\0sched_getattr\0sched_getparam\0sched_getscheduler\0sched_rr_get_interval\0sched_setaffinity\0sched_setattr\0sched_setparam\0sched_setscheduler\0sched_yield\0"
	"seccomp\0select\0sendfile\0set_robust_list\0set_tid_address\0setdomainname\0setfsgid\0setfsuid\0setgid\0setgroups\0"
	"sethostname\0setitimer\0setns\0setpgid\0setpriority\0setregid\0setresgid\0setresuid\0setreuid\0setrlimit\0"
	"setsid\0settimeofday\0setuid\0setxattr\0sigaction\0sigaltstack\0signal\0signalfd\0signalfd4\0sigpending\0"
	"sigprocmask\0sigreturn\0sigsuspend\0socketcall\0splice\0stat\0statfs\0statfs64\0swapoff\0swapon\0"
	"symlink\0symlinkat\0sync\0sync_file_range\0syncfs\0sysfs\0sysinfo\0syslog\0tee\0tgkill\0"
	"timer_create\0timer_delete\0timer_getoverrun\0timer_gettime\0timer_settime\0timerfd\0timerfd_create\0timerfd_gettime\0timerfd_settime\0times\0"
	"tkill\0truncate\0umask\0umount\0umount2\0uname\0unlink\0unlinkat\0unshare\0uselib\0"
	"ustat\0utime\0utimensat\0utimes\0vfork\0vhangup\0vmsplice\0wait4\0waitid\0write\0"
	"writev";
static const unsigned s390x_syscall_s2i_s[] = {
	0,8,15,20,28,37,49,55,63,67,
	71,78,85,91,97,103,110,124,137,151,
	167,181,187,193,199,213,227,231,236,241,
	254,268,278,290,301,309,318,325,334,339,
	350,360,370,380,394,408,415,422,431,438,
	447,453,463,473,486,497,503,508,521,531,
	537,545,555,561,571,577,587,603,619,626,
	633,642,650,658,665,675,685,693,701,708,
	716,724,736,746,756,766,776,786,793,800,
	813,820,829,834,846,864,877,891,908,918,
	929,942,951,961,967,978,989,993,998,1009,
	1016,1021,1028,1038,1043,1050,1060,1071,1084,1090,
	1100,1106,1114,1127,1135,1141,1149,1155,1163,1169,
	1178,1183,1189,1198,1212,1222,1230,1246,1259,1269,
	1276,1282,1290,1301,1308,1326,1336,1347,1358,1363,
	1368,1386,1393,1399,1415,1427,1432,1438,1449,1454,
	1460,1466,1472,1479,1489,1506,1524,1533,1540,1548,
	1555,1563,1576,1585,1590,1600,1608,1617,1628,1634,
	1641,1658,1670,1677,1686,1696,1708,1714,1727,1741,
	1756,1772,1785,1799,1815,1833,1852,1872,1891,1914,
	1937,1955,1969,1984,2003,2025,2043,2057,2072,2091,
	2103,2111,2118,2127,2143,2159,2173,2182,2191,2198,
	2208,2220,2230,2236,2244,2256,2265,2275,2285,2294,
	2304,2311,2324,2331,2340,2350,2362,2369,2378,2388,
	2399,2411,2421,2432,2443,2450,2455,2462,2471,2479,
	2486,2494,2504,2509,2525,2532,2538,2546,2553,2557,
	2564,2577,2590,2607,2621,2635,2643,2658,2674,2690,
	2696,2702,2711,2717,2724,2732,2738,2745,2754,2762,
	2769,2775,2781,2791,2798,2804,2812,2821,2827,2834,
	2840,
};
static const int s390x_syscall_s2i_i[] = {
	149,33,51,278,124,137,27,134,351,45,
	184,185,12,15,212,61,337,261,260,262,
	259,120,6,8,127,129,41,63,326,249,
	327,250,312,251,318,323,11,354,1,248,
	300,253,314,332,333,133,94,299,207,291,
	55,148,229,344,232,143,2,235,226,108,
	100,266,118,93,238,292,130,305,311,183,
	141,202,201,200,205,105,132,65,20,188,
	64,96,349,211,209,191,77,147,236,78,
	199,227,112,128,285,284,324,286,247,244,
	245,243,246,54,283,282,117,343,277,280,
	37,198,228,9,296,230,231,234,19,225,
	107,219,350,218,39,289,14,290,150,152,
	90,21,125,276,275,271,274,273,272,163,
	144,151,153,91,335,162,293,169,34,5,
	336,288,29,331,136,42,325,217,168,302,
	172,180,328,334,340,341,301,26,189,181,
	329,167,131,3,222,89,85,298,145,88,
	267,233,38,295,347,279,40,174,176,175,
	178,173,179,177,330,353,352,342,159,160,
	240,346,155,157,161,239,345,154,156,158,
	348,142,187,304,252,121,216,215,214,206,
	74,104,339,57,97,204,210,208,203,75,
	66,79,213,224,67,186,48,316,322,73,
	126,119,72,102,306,106,99,265,115,87,
	83,297,36,307,338,135,116,103,308,241,
	254,258,257,256,255,317,319,321,320,43,
	237,92,60,22,52,122,10,294,303,86,
	62,30,315,313,190,111,309,114,281,4,
	146,
};
static int s390x_syscall_s2i(const char *s, int *value) {
	size_t len, i;
	len = strlen(s);
	{ char copy[len + 1];
	for (i = 0; i < len; i++) {
		char c = s[i];
		copy[i] = GT_ISUPPER(c) ? c - 'A' + 'a' : c;
	}
	copy[i] = 0;
	return s2i__(s390x_syscall_strings, s390x_syscall_s2i_s, s390x_syscall_s2i_i, 291, copy, value);
	}
}
static const unsigned s390x_syscall_i2s_direct[] = {
	334,503,1585,2834,1363,187,-1u,193,1038,2738,
	318,85,-1u,1149,91,-1u,-1u,-1u,1084,701,
	1183,2717,-1u,-1u,-1u,1533,49,-1u,1393,2775,
	-1u,-1u,8,1358,-1u,2504,1016,1670,1135,1708,
	227,1427,2690,-1u,67,-1u,-1u,2362,-1u,-1u,
	15,2724,-1u,961,447,-1u,2236,-1u,-1u,2711,
	103,2769,231,716,693,2304,2340,-1u,-1u,-1u,
	-1u,2421,2388,2208,2294,-1u,776,800,2311,-1u,
	-1u,-1u,2486,-1u,1608,2762,2479,1634,1600,1178,
	1301,2702,561,415,-1u,724,2244,-1u,2455,537,
	-1u,2432,2546,2220,675,2450,1100,531,-1u,-1u,
	2804,829,-1u,2821,2471,2538,989,555,2411,181,
	2159,2732,-1u,28,1189,2399,199,834,213,587,
	1576,685,408,55,2532,1415,37,-1u,-1u,-1u,
	633,2111,497,1276,1628,2840,786,453,0,1163,
	1282,1169,1290,2057,1969,2072,1984,2091,1891,1914,
	2003,1326,1269,-1u,-1u,-1u,1563,1449,1347,-1u,
	-1u,1460,1772,1714,1741,1727,1799,1756,1785,1466,
	1548,-1u,626,71,78,2350,2118,708,1540,2798,
	766,-1u,-1u,-1u,-1u,-1u,-1u,1021,813,658,
	650,642,2285,2256,665,2198,431,2275,756,2265,
	746,97,2324,2191,2182,2173,1438,1127,1106,-1u,
	-1u,1590,-1u,2331,1090,521,820,1028,463,1050,
	1060,486,1658,1071,508,793,2696,571,2025,1937,
	2557,-1u,942,918,929,951,908,339,241,268,
	290,2143,360,2564,2621,2607,2590,2577,167,137,
	124,151,-1u,-1u,2462,545,1641,-1u,-1u,-1u,
	1222,1259,1246,1230,1212,1198,998,20,1696,1009,
	2827,978,967,864,846,891,-1u,1386,1141,1155,
	438,577,1336,2745,1677,1043,2494,1617,422,350,
	1524,1454,2754,2127,603,2443,2509,2553,2812,-1u,
	619,278,2791,370,2781,2369,2635,301,2643,2674,
	2658,2378,309,877,1432,236,254,1472,1555,1815,
	1399,380,394,1479,1308,1368,110,2525,2230,1489,
	1506,1872,993,473,2043,1955,1686,2103,736,1114,
	63,1852,1833,325,
};
static const char *s390x_syscall_i2s(int v) {
	return i2s_direct__(s390x_syscall_strings, s390x_syscall_i2s_direct, 1, 354, v);
}
