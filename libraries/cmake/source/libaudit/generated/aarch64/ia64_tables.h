/* This is a generated file, see Makefile.am for its inputs. */
static const char ia64_syscall_strings[] = "_sysctl\0accept\0accept4\0access\0acct\0add_key\0adjtimex\0afs_syscall\0bdflush\0bind\0"
	"bpf\0brk\0capget\0capset\0chdir\0chmod\0chown\0chroot\0clock_adjtime\0clock_getres\0"
	"clock_gettime\0clock_nanosleep\0clock_settime\0clone\0clone2\0close\0connect\0creat\0delete_module\0dup\0"
	"dup2\0dup3\0epoll_create\0epoll_create1\0epoll_ctl\0epoll_pwait\0epoll_wait\0eventfd\0eventfd2\0execve\0"
	"execveat\0exit\0exit_group\0faccessat\0fadvise64\0fallocate\0fanotify_init\0fanotify_mark\0fchdir\0fchmod\0"
	"fchmodat\0fchown\0fchownat\0fcntl\0fdatasync\0fgetxattr\0finit_module\0flistxattr\0flock\0fremovexattr\0"
	"fsetxattr\0fstat\0fstatfs\0fstatfs64\0fsync\0ftruncate\0futex\0futimesat\0get_mempolicy\0get_robust_list\0"
	"getcpu\0getcwd\0getdents\0getdents64\0getegid\0geteuid\0getgid\0getgroups\0getitimer\0getpeername\0"
	"getpgid\0getpid\0getpmsg\0getppid\0getpriority\0getrandom\0getresgid\0getresuid\0getrlimit\0getrusage\0"
	"getsid\0getsockname\0getsockopt\0gettid\0gettimeofday\0getuid\0getunwind\0getxattr\0init_module\0inotify_add_watch\0"
	"inotify_init\0inotify_init1\0inotify_rm_watch\0io_cancel\0io_destroy\0io_getevents\0io_setup\0io_submit\0ioctl\0ioprio_get\0"
	"ioprio_set\0kexec_load\0keyctl\0kill\0lchown\0lgetxattr\0link\0linkat\0listen\0listxattr\0"
	"llistxattr\0lookup_dcookie\0lremovexattr\0lseek\0lsetxattr\0lstat\0madvise\0mbind\0memfd_create\0migrate_pages\0"
	"mincore\0mkdir\0mkdirat\0mknod\0mknodat\0mlock\0mlockall\0mmap\0mmap2\0mount\0"
	"mprotect\0mq_getsetattr\0mq_notify\0mq_open\0mq_timedreceive\0mq_timedsend\0mq_unlink\0mremap\0msgctl\0msgget\0"
	"msgrcv\0msgsnd\0msync\0munlock\0munlockall\0munmap\0name_to_handle_at\0nanosleep\0newfstatat\0nfsservctl\0"
	"ni_syscall\0open\0open_by_handle_at\0openat\0pciconfig_read\0pciconfig_write\0perfmonctl\0personality\0pipe\0pipe2\0"
	"pivot_root\0poll\0ppoll\0prctl\0pread64\0preadv\0prlimit64\0process_vm_readv\0process_vm_writev\0pselect\0"
	"ptrace\0putpmsg\0pwrite64\0pwritev\0quotactl\0read\0readahead\0readlink\0readlinkat\0readv\0"
	"reboot\0recv\0recvfrom\0recvmmsg\0recvmsg\0remap_file_pages\0removexattr\0rename\0renameat\0renameat2\0"
	"request_key\0restart_syscall\0rmdir\0rt_sigaction\0rt_sigpending\0rt_sigprocmask\0rt_sigqueueinfo\0rt_sigreturn\0rt_sigsuspend\0rt_sigtimedwait\0"
	"rt_tgsigqueueinfo\0sched_get_priority_max\0sched_get_priority_min\0sched_getaffinity\0sched_getattr\0sched_getparam\0sched_getscheduler\0sched_rr_get_interval\0sched_setaffinity\0sched_setattr\0"
	"sched_setparam\0sched_setscheduler\0sched_yield\0select\0semctl\0semget\0semop\0semtimedop\0send\0sendfile\0"
	"sendmmsg\0sendmsg\0sendto\0set_mempolicy\0set_robust_list\0set_tid_address\0set_zone_reclaim\0setdomainname\0setfsgid\0setfsuid\0"
	"setgid\0setgroups\0sethostname\0setitimer\0setns\0setpgid\0setpriority\0setregid\0setresgid\0setresuid\0"
	"setreuid\0setrlimit\0setsid\0setsockopt\0settimeofday\0setuid\0setxattr\0shmat\0shmctl\0shmdt\0"
	"shmget\0shutdown\0sigaltstack\0signalfd\0signalfd4\0socket\0socketpair\0splice\0stat\0statfs\0"
	"statfs64\0swapoff\0swapon\0symlink\0symlinkat\0sync\0sync_file_range\0syncfs\0sysfs\0sysinfo\0"
	"syslog\0tee\0tgkill\0timer_create\0timer_delete\0timer_getoverrun\0timer_gettime\0timer_settime\0timerfd\0timerfd_create\0"
	"timerfd_gettime\0timerfd_settime\0times\0tkill\0truncate\0tux\0umask\0umount\0uname\0unlink\0"
	"unlinkat\0unshare\0uselib\0ustat\0utimensat\0utimes\0vhangup\0vmsplice\0vserver\0wait4\0"
	"waitid\0write\0writev";
static const unsigned ia64_syscall_s2i_s[] = {
	0,8,15,23,30,35,43,52,64,72,
	77,81,85,92,99,105,111,117,124,138,
	151,165,181,195,201,208,214,222,228,242,
	246,251,256,269,283,293,305,316,324,333,
	340,349,354,365,375,385,395,409,423,430,
	437,446,453,462,468,478,488,501,512,518,
	531,541,547,555,565,571,581,587,597,611,
	627,634,641,650,661,669,677,684,694,704,
	716,724,731,739,747,759,769,779,789,799,
	809,816,828,839,846,859,866,876,885,897,
	915,928,942,959,969,980,993,1002,1012,1018,
	1029,1040,1051,1058,1063,1070,1080,1085,1092,1099,
	1109,1120,1135,1148,1154,1164,1170,1178,1184,1197,
	1211,1219,1225,1233,1239,1247,1253,1262,1267,1273,
	1279,1288,1302,1312,1320,1336,1349,1359,1366,1373,
	1380,1387,1394,1400,1408,1419,1426,1444,1454,1465,
	1476,1487,1492,1510,1517,1532,1548,1559,1571,1576,
	1582,1593,1598,1604,1610,1618,1625,1635,1652,1670,
	1678,1685,1693,1702,1710,1719,1724,1734,1743,1754,
	1760,1767,1772,1781,1790,1798,1815,1827,1834,1843,
	1853,1865,1881,1887,1900,1914,1929,1945,1958,1972,
	1988,2006,2029,2052,2070,2084,2099,2118,2140,2158,
	2172,2187,2206,2218,2225,2232,2239,2245,2256,2261,
	2270,2279,2287,2294,2308,2324,2340,2357,2371,2380,
	2389,2396,2406,2418,2428,2434,2442,2454,2463,2473,
	2483,2492,2502,2509,2520,2533,2540,2549,2555,2562,
	2568,2575,2584,2596,2605,2615,2622,2633,2640,2645,
	2652,2661,2669,2676,2684,2694,2699,2715,2722,2728,
	2736,2743,2747,2754,2767,2780,2797,2811,2825,2833,
	2848,2864,2880,2886,2892,2901,2905,2911,2918,2924,
	2931,2940,2948,2955,2961,2971,2978,2986,2995,3003,
	3009,3016,3022,
};
static const int ia64_syscall_s2i_i[] = {
	1150,1194,1334,1049,1064,1271,1131,1141,1138,1191,
	1341,1060,1185,1186,1034,1038,1039,1068,1328,1255,
	1254,1256,1253,1128,1213,1029,1192,1030,1134,1057,
	1070,1316,1243,1315,1244,1305,1245,1309,1314,1033,
	1342,1025,1236,1293,1234,1303,1323,1324,1035,1099,
	1292,1100,1284,1066,1052,1222,1335,1225,1145,1228,
	1219,1212,1104,1257,1051,1098,1230,1285,1260,1299,
	1304,1184,1144,1214,1063,1047,1062,1077,1119,1196,
	1079,1041,1188,1042,1101,1339,1075,1073,1085,1086,
	1082,1195,1204,1105,1087,1046,1215,1220,1133,1278,
	1277,1318,1279,1242,1239,1240,1238,1241,1065,1275,
	1274,1268,1273,1053,1124,1221,1031,1289,1193,1223,
	1224,1237,1227,1040,1218,1211,1209,1259,1340,1280,
	1208,1055,1282,1037,1283,1153,1154,1151,1172,1043,
	1155,1267,1266,1262,1265,1264,1263,1156,1112,1109,
	1111,1110,1157,1158,1159,1152,1326,1168,1286,1169,
	1024,1028,1327,1281,1173,1174,1175,1140,1058,1317,
	1207,1090,1295,1170,1148,1319,1325,1332,1333,1294,
	1048,1189,1149,1320,1137,1026,1216,1092,1291,1146,
	1096,1200,1201,1322,1206,1125,1226,1054,1288,1338,
	1272,1246,1056,1177,1178,1179,1180,1181,1182,1183,
	1321,1165,1166,1232,1337,1160,1162,1167,1231,1336,
	1161,1163,1164,1089,1108,1106,1107,1247,1198,1187,
	1331,1205,1199,1261,1298,1233,1276,1129,1143,1142,
	1061,1078,1083,1118,1330,1080,1102,1072,1076,1074,
	1071,1084,1081,1203,1088,1045,1217,1114,1116,1115,
	1113,1202,1176,1307,1313,1190,1197,1297,1210,1103,
	1258,1095,1094,1091,1290,1050,1300,1329,1139,1127,
	1117,1301,1235,1248,1252,1251,1250,1249,1308,1310,
	1312,1311,1059,1229,1097,1120,1067,1044,1130,1032,
	1287,1296,1093,1069,1306,1036,1123,1302,1269,1126,
	1270,1027,1147,
};
static int ia64_syscall_s2i(const char *s, int *value) {
	size_t len, i;
	len = strlen(s);
	{ char copy[len + 1];
	for (i = 0; i < len; i++) {
		char c = s[i];
		copy[i] = GT_ISUPPER(c) ? c - 'A' + 'a' : c;
	}
	copy[i] = 0;
	return s2i__(ia64_syscall_strings, ia64_syscall_s2i_s, ia64_syscall_s2i_i, 313, copy, value);
	}
}
static const unsigned ia64_syscall_i2s_direct[] = {
	1476,349,1719,3016,1487,208,222,1080,2924,333,
	99,423,2971,1233,105,111,1148,724,739,1273,
	2911,2533,859,669,1678,23,2694,565,468,1058,
	1827,1219,1881,242,1571,2880,81,2389,677,661,
	30,1012,462,2905,117,2955,246,2483,2454,779,
	2473,769,2463,684,2396,716,2434,2502,809,2406,
	2492,789,799,846,2520,2218,1593,2676,1734,2948,
	2669,2661,1760,2892,571,430,446,747,2442,2645,
	547,839,2232,2239,2225,1373,1387,1380,1366,2568,
	2549,2562,2555,2736,2418,694,2901,-1u,-1u,2978,
	1063,1798,3003,2728,195,2357,2918,43,-1u,885,
	228,-1u,-1u,1710,64,2722,1559,52,2380,2371,
	641,512,1754,3022,1610,1693,0,1262,1419,1247,
	1253,1279,1359,1394,1400,1408,2084,2172,2099,2187,
	2206,2006,2029,2118,1444,1465,1604,-1u,1267,1517,
	1532,1548,2584,1887,1900,1914,1929,1945,1958,1972,
	634,85,92,2261,731,1685,2615,72,214,1092,
	8,816,704,2622,2256,2287,1767,1772,2575,2509,
	828,2279,1790,1582,1211,1170,2640,1164,541,201,
	650,866,1724,2540,1154,531,876,1070,478,1099,
	1109,501,1815,1135,518,2886,581,2140,2052,2324,
	375,2747,354,1120,993,969,980,1002,959,256,
	283,305,1865,2245,2754,2811,2797,2780,2767,181,
	151,138,165,555,2652,1178,597,2294,1312,1349,
	1336,1320,1302,1288,1040,2995,3009,35,1853,1051,
	1029,1018,2340,915,897,942,1197,1510,1225,1239,
	453,587,1454,2931,1834,1085,2684,1743,437,365,
	1670,1598,2940,2633,2308,611,2699,2743,2986,385,
	627,293,2961,2596,2825,316,2833,2864,2848,2605,
	324,269,251,1576,928,1618,1702,1988,1781,395,
	409,1625,1426,1492,124,2715,2428,2270,1635,1652,
	15,488,2158,2070,1843,759,1184,77,340,
};
static const char *ia64_syscall_i2s(int v) {
	return i2s_direct__(ia64_syscall_strings, ia64_syscall_i2s_direct, 1024, 1342, v);
}
