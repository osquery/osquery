/* This is a generated file, see Makefile.am for its inputs. */
static const char aarch64_syscall_strings[] = "accept\0accept4\0acct\0add_key\0adjtimex\0bind\0bpf\0brk\0capget\0capset\0"
	"chdir\0chroot\0clock_adjtime\0clock_getres\0clock_gettime\0clock_nanosleep\0clock_settime\0clone\0close\0connect\0"
	"delete_module\0dup\0dup3\0epoll_create1\0epoll_ctl\0epoll_pwait\0eventfd2\0execve\0execveat\0exit\0"
	"exit_group\0faccessat\0fadvise64\0fallocate\0fanotify_init\0fanotify_mark\0fchdir\0fchmod\0fchmodat\0fchown\0"
	"fchownat\0fcntl\0fdatasync\0fgetxattr\0finit_module\0flistxattr\0flock\0fremovexattr\0fsetxattr\0fstatfs\0"
	"fsync\0ftruncate\0futex\0get_mempolicy\0get_robust_list\0getcpu\0getcwd\0getdents\0getegid\0geteuid\0"
	"getgid\0getgroups\0getitimer\0getpeername\0getpgid\0getpid\0getppid\0getpriority\0getrandom\0getresgid\0"
	"getresuid\0getrlimit\0getrusage\0getsid\0getsockname\0getsockopt\0gettid\0gettimeofday\0getuid\0getxattr\0"
	"init_module\0inotify_add_watch\0inotify_init1\0inotify_rm_watch\0io_cancel\0io_destroy\0io_getevents\0io_setup\0io_submit\0ioctl\0"
	"ioprio_get\0ioprio_set\0kcmp\0kexec_load\0keyctl\0kill\0lgetxattr\0linkat\0listen\0listxattr\0"
	"llistxattr\0lookup_dcookie\0lremovexattr\0lseek\0lsetxattr\0madvise\0mbind\0memfd_create\0migrate_pages\0mincore\0"
	"mkdirat\0mknodat\0mlock\0mlockall\0mmap\0mount\0move_pages\0mprotect\0mq_getsetattr\0mq_notify\0"
	"mq_open\0mq_timedreceive\0mq_timedsend\0mq_unlink\0mremap\0msgctl\0msgget\0msgrcv\0msgsnd\0msync\0"
	"munlock\0munlockall\0munmap\0name_to_handle_at\0nanosleep\0newfstat\0newfstatat\0nfsservctl\0open_by_handle_at\0openat\0"
	"perf_event_open\0personality\0pipe2\0pivot_root\0ppoll\0prctl\0pread\0preadv\0prlimit64\0process_vm_readv\0"
	"process_vm_writev\0pselect6\0ptrace\0pwrite\0pwritev\0quotactl\0read\0readahead\0readlinkat\0readv\0"
	"reboot\0recvfrom\0recvmmsg\0recvmsg\0remap_file_pages\0removexattr\0renameat\0renameat2\0request_key\0restart_syscall\0"
	"rt_sigaction\0rt_sigpending\0rt_sigprocmask\0rt_sigqueueinfo\0rt_sigreturn\0rt_sigsuspend\0rt_sigtimedwait\0rt_tgsigqueueinfo\0sched_get_priority_max\0sched_get_priority_min\0"
	"sched_getaffinity\0sched_getattr\0sched_getparam\0sched_getscheduler\0sched_rr_get_interval\0sched_setaffinity\0sched_setattr\0sched_setparam\0sched_setscheduler\0sched_yield\0"
	"seccomp\0semctl\0semget\0semop\0semtimedop\0sendfile\0sendmmsg\0sendmsg\0sendto\0set_mempolicy\0"
	"set_robust_list\0set_tid_address\0setdomainname\0setfsgid\0setfsuid\0setgid\0setgroups\0sethostname\0setitimer\0setns\0"
	"setpgid\0setpriority\0setregid\0setresgid\0setresuid\0setreuid\0setrlimit\0setsid\0setsockopt\0settimeofday\0"
	"setuid\0setxattr\0shmat\0shmctl\0shmdt\0shmget\0shutdown\0sigaltstack\0signalfd4\0socket\0"
	"socketpair\0splice\0statfs\0swapoff\0swapon\0symlinkat\0sync\0sync_file_range\0syncfs\0sysinfo\0"
	"syslog\0tee\0tgkill\0timer_create\0timer_delete\0timer_getoverrun\0timer_gettime\0timer_settime\0timerfd_create\0timerfd_gettime\0"
	"timerfd_settime\0times\0tkill\0truncate\0umask\0umount2\0uname\0unlinkat\0unshare\0utimensat\0"
	"vhangup\0vmsplice\0wait4\0waitid\0write\0writev";
static const unsigned aarch64_syscall_s2i_s[] = {
	0,7,15,20,28,37,42,46,50,57,
	64,70,77,91,104,118,134,148,154,160,
	168,182,186,191,205,215,227,236,243,252,
	257,268,278,288,298,312,326,333,340,349,
	356,365,371,381,391,404,415,421,434,444,
	452,458,468,474,488,504,511,518,527,535,
	543,550,560,570,582,590,597,605,617,627,
	637,647,657,667,674,686,697,704,717,724,
	733,745,763,777,794,804,815,828,837,847,
	853,864,875,880,891,898,903,913,920,927,
	937,948,963,976,982,992,1000,1006,1019,1033,
	1041,1049,1057,1063,1072,1077,1083,1094,1103,1117,
	1127,1135,1151,1164,1174,1181,1188,1195,1202,1209,
	1215,1223,1234,1241,1259,1269,1278,1289,1300,1318,
	1325,1341,1353,1359,1370,1376,1382,1388,1395,1405,
	1422,1440,1449,1456,1463,1471,1480,1485,1495,1506,
	1512,1519,1528,1537,1545,1562,1574,1583,1593,1605,
	1621,1634,1648,1663,1679,1692,1706,1722,1740,1763,
	1786,1804,1818,1833,1852,1874,1892,1906,1921,1940,
	1952,1960,1967,1974,1980,1991,2000,2009,2017,2024,
	2038,2054,2070,2084,2093,2102,2109,2119,2131,2141,
	2147,2155,2167,2176,2186,2196,2205,2215,2222,2233,
	2246,2253,2262,2268,2275,2281,2288,2297,2309,2319,
	2326,2337,2344,2351,2359,2366,2376,2381,2397,2404,
	2412,2419,2423,2430,2443,2456,2473,2487,2501,2516,
	2532,2548,2554,2560,2569,2575,2583,2589,2598,2606,
	2616,2624,2633,2639,2646,2652,
};
static const int aarch64_syscall_s2i_i[] = {
	202,242,89,217,171,200,280,214,90,91,
	49,51,266,114,113,115,112,220,57,203,
	106,23,24,20,21,22,19,221,281,93,
	94,48,223,47,262,263,50,52,53,55,
	54,25,83,10,273,13,32,16,7,44,
	82,46,98,236,100,168,17,61,177,175,
	176,158,102,205,155,172,173,141,278,150,
	148,163,165,156,204,209,178,169,174,8,
	105,27,26,28,3,1,4,0,2,29,
	31,30,272,104,219,129,9,37,201,11,
	12,18,15,62,6,233,235,279,238,232,
	34,33,228,230,222,40,239,226,185,184,
	180,183,182,181,216,187,186,188,189,227,
	229,231,215,264,101,80,79,42,265,56,
	241,92,59,41,73,167,67,69,261,270,
	271,72,117,68,70,60,63,213,78,65,
	142,207,243,212,234,14,38,276,218,128,
	134,136,135,138,139,133,137,240,125,126,
	123,275,121,120,127,122,274,118,119,124,
	277,191,190,193,192,71,269,211,206,237,
	99,96,162,152,151,144,159,161,103,268,
	154,140,143,149,147,145,164,157,208,170,
	146,5,196,195,197,194,210,132,74,198,
	199,76,43,225,224,36,81,84,267,179,
	116,77,131,107,111,109,108,110,85,87,
	86,153,130,45,166,39,160,35,97,88,
	58,75,260,95,64,66,
};
static int aarch64_syscall_s2i(const char *s, int *value) {
	size_t len, i;
	len = strlen(s);
	{ char copy[len + 1];
	for (i = 0; i < len; i++) {
		char c = s[i];
		copy[i] = GT_ISUPPER(c) ? c - 'A' + 'a' : c;
	}
	copy[i] = 0;
	return s2i__(aarch64_syscall_strings, aarch64_syscall_s2i_s, aarch64_syscall_s2i_i, 266, copy, value);
	}
}
static const unsigned aarch64_syscall_i2s_direct[] = {
	828,804,837,794,815,2253,982,434,724,903,
	381,927,937,404,1562,963,421,511,948,227,
	191,205,215,182,186,365,763,745,777,847,
	864,853,415,1049,1041,2589,2366,913,1574,2575,
	1077,1359,1289,2344,444,2560,458,288,268,64,
	326,70,333,340,356,349,1318,154,2616,1353,
	1471,518,976,1480,2646,1506,2652,1382,1456,1388,
	1463,1991,1440,1370,2309,2624,2337,2419,1495,1278,
	1269,2376,452,371,2381,2501,2532,2516,2606,15,
	50,57,1341,252,257,2639,2054,2598,468,2038,
	488,1259,560,2131,880,733,168,2430,2473,2456,
	2487,2443,134,104,91,118,2412,1449,1906,1921,
	1833,1818,1874,1786,1940,1740,1763,1852,1605,898,
	2554,2423,2297,1692,1621,1648,1634,1706,1663,1679,
	2155,605,1512,2167,2102,2196,2246,2186,637,2176,
	627,2093,2084,2548,2147,582,667,2215,550,2109,
	2583,2119,2070,647,2205,657,2569,1376,504,704,
	2233,28,590,597,717,535,543,527,697,2404,
	1127,1164,1151,1135,1117,1103,1188,1181,1195,1202,
	1967,1960,1980,1974,2281,2268,2262,2275,2319,2326,
	37,920,0,160,674,570,2017,1519,2222,686,
	2288,2009,1537,1485,46,1234,1174,20,1593,891,
	148,236,1072,278,2359,2351,1094,1209,1057,1215,
	1063,1223,1033,992,1545,1000,474,2024,1019,1083,
	1722,1325,7,1528,-1u,-1u,-1u,-1u,-1u,-1u,
	-1u,-1u,-1u,-1u,-1u,-1u,-1u,-1u,-1u,-1u,
	2633,1395,298,312,1241,1300,77,2397,2141,2000,
	1405,1422,875,391,1892,1804,1583,1952,617,1006,
	42,243,
};
static const char *aarch64_syscall_i2s(int v) {
	return i2s_direct__(aarch64_syscall_strings, aarch64_syscall_i2s_direct, 0, 281, v);
}
