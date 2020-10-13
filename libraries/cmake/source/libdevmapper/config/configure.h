/* include/configure.h.  Generated from configure.h.in by configure.  */
/* include/configure.h.in.  Generated from configure.in by autoheader.  */

/* Define to 1 to use libblkid detection of signatures when wiping. */
/* #undef BLKID_WIPING_SUPPORT */

/* The path to 'cache_check', if available. */
#define CACHE_CHECK_CMD "/usr/sbin/cache_check"

/* Define to 1 if the external 'cache_check' tool requires the
   --clear-needs-check-flag option */
/* #undef CACHE_CHECK_NEEDS_CHECK */

/* The path to 'cache_dump', if available. */
#define CACHE_DUMP_CMD "/usr/sbin/cache_dump"

/* Define to 1 to include built-in support for cache. */
#define CACHE_INTERNAL 1

/* The path to 'cache_repair', if available. */
#define CACHE_REPAIR_CMD "/usr/sbin/cache_repair"

/* The path to 'cache_restore', if available. */
#define CACHE_RESTORE_CMD "/usr/sbin/cache_restore"

/* Define to 1 if the `closedir' function returns void instead of `int'. */
/* #undef CLOSEDIR_VOID */

/* Define to 1 to include built-in support for clustered LVM locking. */
#define CLUSTER_LOCKING_INTERNAL 1

/* Path to clvmd binary. */
#define CLVMD_PATH "/usr/sbin/clvmd"

/* Path to clvmd pidfile. */
/* #undef CLVMD_PIDFILE */

/* Path to cmirrord pidfile. */
/* #undef CMIRRORD_PIDFILE */

/* Define to 0 to exclude libSaCkpt. */
/* #undef CMIRROR_HAS_CHECKPOINT */

/* Define to one of `_getb67', `GETB67', `getb67' for Cray-2 and Cray-YMP
   systems. This function is required for `alloca.c' support on those systems.
   */
/* #undef CRAY_STACKSEG_END */

/* Define to 1 if using `alloca.c'. */
/* #undef C_ALLOCA */

/* Name of default metadata archive subdirectory. */
#define DEFAULT_ARCHIVE_SUBDIR "archive"

/* Name of default metadata backup subdirectory. */
#define DEFAULT_BACKUP_SUBDIR "backup"

/* Name of default metadata cache subdirectory. */
#define DEFAULT_CACHE_SUBDIR "cache"

/* Default data alignment. */
#define DEFAULT_DATA_ALIGNMENT 1

/* Define default node creation behavior with dmsetup create */
#define DEFAULT_DM_ADD_NODE DM_ADD_NODE_ON_RESUME

/* Define default name mangling behaviour */
#define DEFAULT_DM_NAME_MANGLING DM_STRING_MANGLING_AUTO

/* Default DM run directory. */
#define DEFAULT_DM_RUN_DIR "/run"

/* Default system configuration directory. */
#define DEFAULT_ETC_DIR "/etc"

/* Fall back to LVM1 by default if device-mapper is missing from the kernel.
   */
#define DEFAULT_FALLBACK_TO_LVM1 0

/* Name of default locking directory. */
#define DEFAULT_LOCK_DIR "/run/lock/lvm"

/* Default segtype used for mirror volumes. */
#define DEFAULT_MIRROR_SEGTYPE "raid1"

/* Default directory to keep PID files in. */
#define DEFAULT_PID_DIR "/run"

/* Name of default configuration profile subdirectory. */
#define DEFAULT_PROFILE_SUBDIR "profile"

/* Default segtype used for raid10 volumes. */
#define DEFAULT_RAID10_SEGTYPE "raid10"

/* Default LVM run directory. */
#define DEFAULT_RUN_DIR "/run/lvm"

/* Define to 0 to reinstate the pre-2.02.54 handling of unit suffixes. */
/* #undef DEFAULT_SI_UNIT_CONSISTENCY */

/* Default segtype used for sparse volumes. */
#define DEFAULT_SPARSE_SEGTYPE "thin"

/* Path to LVM system directory. */
#define DEFAULT_SYS_DIR "/etc/lvm"

/* Use blkid wiping by default. */
#define DEFAULT_USE_BLKID_WIPING 0

/* Use lvmetad by default. */
#define DEFAULT_USE_LVMETAD 0

/* Use lvmlockd by default. */
#define DEFAULT_USE_LVMLOCKD 0

/* Use lvmpolld by default. */
#define DEFAULT_USE_LVMPOLLD 0

/* Define to 1 to enable LVM2 device-mapper interaction. */
#define DEVMAPPER_SUPPORT 1

/* Define to 1 to enable the device-mapper event daemon. */
/* #undef DMEVENTD */

/* Path to dmeventd binary. */
/* #undef DMEVENTD_PATH */

/* Path to dmeventd pidfile. */
/* #undef DMEVENTD_PIDFILE */

/* Define to 1 to enable the device-mapper filemap daemon. */
#define DMFILEMAPD $BUILD_DMFILEMAPD

/* Define to enable compat protocol */
/* #undef DM_COMPAT */

/* Define default group for device node */
#define DM_DEVICE_GID 0

/* Define default mode for device node */
#define DM_DEVICE_MODE 0600

/* Define default owner for device node */
#define DM_DEVICE_UID 0

/* Define to enable ioctls calls to kernel */
#define DM_IOCTLS 1

/* Library version */
#define DM_LIB_VERSION "1.02.142-git (2017-07-20)"

/* Path to fsadm binary. */
#define FSADM_PATH "/sbin/fsadm"

/* Define to 1 if you have the `alarm' function. */
#define HAVE_ALARM 1

/* Define to 1 if you have `alloca', as a function or macro. */
#define HAVE_ALLOCA 1

/* Define to 1 if you have <alloca.h> and it should be used (not on Ultrix).
   */
#define HAVE_ALLOCA_H 1

/* Define to 1 if you have the <arpa/inet.h> header file. */
/* #undef HAVE_ARPA_INET_H */

/* Define to 1 if you have the <asm/byteorder.h> header file. */
#define HAVE_ASM_BYTEORDER_H 1

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the `atexit' function. */
/* #undef HAVE_ATEXIT */

/* Define to 1 if canonicalize_file_name is available. */
#define HAVE_CANONICALIZE_FILE_NAME 1

/* Define to 1 if your system has a working `chown' function. */
#define HAVE_CHOWN 1

/* Define to 1 if you have the `clock_gettime' function. */
/* #undef HAVE_CLOCK_GETTIME */

/* Define to 1 if you have the <corosync/cmap.h> header file. */
/* #undef HAVE_COROSYNC_CMAP_H */

/* Define to 1 if you have the <corosync/confdb.h> header file. */
/* #undef HAVE_COROSYNC_CONFDB_H */

/* Define to 1 if you have the <ctype.h> header file. */
#define HAVE_CTYPE_H 1

/* Define to 1 if you have the declaration of `strerror_r', and to 0 if you
   don't. */
/* #undef HAVE_DECL_STRERROR_R */

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you don't have `vprintf' but do have `_doprnt.' */
/* #undef HAVE_DOPRNT */

/* Define to 1 if you have the `dup2' function. */
/* #undef HAVE_DUP2 */

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the <float.h> header file. */
#define HAVE_FLOAT_H 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `ftruncate' function. */
#define HAVE_FTRUNCATE 1

/* Define to 1 if you have the `gethostname' function. */
#define HAVE_GETHOSTNAME 1

/* Define to 1 if getline is available. */
#define HAVE_GETLINE 1

/* Define to 1 if you have the `getmntent' function. */
/* #undef HAVE_GETMNTENT */

/* Define to 1 if getopt_long is available. */
#define HAVE_GETOPTLONG 1

/* Define to 1 if you have the <getopt.h> header file. */
#define HAVE_GETOPT_H 1

/* Define to 1 if you have the `getpagesize' function. */
#define HAVE_GETPAGESIZE 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <langinfo.h> header file. */
#define HAVE_LANGINFO_H 1

/* Define to 1 if you have the <libcman.h> header file. */
/* #undef HAVE_LIBCMAN_H */

/* Define to 1 if dynamic libraries are available. */
#define HAVE_LIBDL 1

/* Define to 1 if you have the <libdlm.h> header file. */
/* #undef HAVE_LIBDLM_H */

/* Define to 1 if you have the <libgen.h> header file. */
#define HAVE_LIBGEN_H 1

/* Define to 1 if you have the <libintl.h> header file. */
/* #undef HAVE_LIBINTL_H */

/* Define to 1 if udev_device_get_is_initialized is available. */
/* #undef HAVE_LIBUDEV_UDEV_DEVICE_GET_IS_INITIALIZED */

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <linux/fiemap.h> header file. */
#define HAVE_LINUX_FIEMAP_H 1

/* Define to 1 if you have the <linux/fs.h> header file. */
#define HAVE_LINUX_FS_H 1

/* Define to 1 if you have the <linux/magic.h> header file. */
#define HAVE_LINUX_MAGIC_H 1

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define to 1 if you have the `localtime_r' function. */
#define HAVE_LOCALTIME_R 1

/* Define to 1 if `lstat' has the bug that it succeeds when given the
   zero-length file name argument. */
/* #undef HAVE_LSTAT_EMPTY_STRING_BUG */

/* Define to 1 if you have the <machine/endian.h> header file. */
/* #undef HAVE_MACHINE_ENDIAN_H */

/* Define to 1 if your system has a GNU libc compatible `malloc' function, and
   to 0 otherwise. */
#define HAVE_MALLOC 1

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the `memchr' function. */
#define HAVE_MEMCHR 1

/* Define to 1 if you have the `memmove' function. */
/* #undef HAVE_MEMMOVE */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the `mkdir' function. */
#define HAVE_MKDIR 1

/* Define to 1 if you have the `mkfifo' function. */
#define HAVE_MKFIFO 1

/* Define to 1 if you have a working `mmap' system call. */
#define HAVE_MMAP 1

/* Define to 1 if you have the <mntent.h> header file. */
/* #undef HAVE_MNTENT_H */

/* Define to 1 if you have the `munmap' function. */
#define HAVE_MUNMAP 1

/* Define to 1 if you have the <ndir.h> header file, and it defines `DIR'. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the <netdb.h> header file. */
/* #undef HAVE_NETDB_H */

/* Define to 1 if you have the <netinet/in.h> header file. */
/* #undef HAVE_NETINET_IN_H */

/* Define to 1 if you have the `nl_langinfo' function. */
#define HAVE_NL_LANGINFO 1

/* Define to 1 if you have the <paths.h> header file. */
#define HAVE_PATHS_H 1

/* Define to 1 if you have the <pthread.h> header file. */
/* #undef HAVE_PTHREAD_H */

/* Define to 1 if the system has the type `ptrdiff_t'. */
#define HAVE_PTRDIFF_T 1

/* Define to 1 if you have the <readline/history.h> header file. */
/* #undef HAVE_READLINE_HISTORY_H */

/* Define to 1 if you have the <readline/readline.h> header file. */
/* #undef HAVE_READLINE_READLINE_H */

/* Define to 1 if your system has a GNU libc compatible `realloc' function,
   and to 0 otherwise. */
#define HAVE_REALLOC 1

/* Define to 1 if you have the `realpath' function. */
#define HAVE_REALPATH 1

/* Define to 1 to include support for realtime clock. */
#define HAVE_REALTIME 1

/* Define to 1 if you have the `rl_completion_matches' function. */
/* #undef HAVE_RL_COMPLETION_MATCHES */

/* Define to 1 if you have the `rmdir' function. */
#define HAVE_RMDIR 1

/* Define to 1 if you have the <search.h> header file. */
/* #undef HAVE_SEARCH_H */

/* Define to 1 if you have the `select' function. */
/* #undef HAVE_SELECT */

/* Define to 1 to include support for selinux. */
/* #undef HAVE_SELINUX */

/* Define to 1 if you have the <selinux/label.h> header file. */
/* #undef HAVE_SELINUX_LABEL_H */

/* Define to 1 if you have the <selinux/selinux.h> header file. */
/* #undef HAVE_SELINUX_SELINUX_H */

/* Define to 1 if sepol_check_context is available. */
/* #undef HAVE_SEPOL */

/* Define to 1 if you have the `setenv' function. */
#define HAVE_SETENV 1

/* Define to 1 if you have the `setlocale' function. */
#define HAVE_SETLOCALE 1

/* Define to 1 if you have the <signal.h> header file. */
#define HAVE_SIGNAL_H 1

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET 1

/* Define to 1 if `stat' has the bug that it succeeds when given the
   zero-length file name argument. */
/* #undef HAVE_STAT_EMPTY_STRING_BUG */

/* Define if struct stat has a field st_ctim with timespec for ctime */
#define HAVE_STAT_ST_CTIM 1

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if stdbool.h conforms to C99. */
#define HAVE_STDBOOL_H 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio.h> header file. */
#define HAVE_STDIO_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strcasecmp' function. */
#define HAVE_STRCASECMP 1

/* Define to 1 if you have the `strchr' function. */
#define HAVE_STRCHR 1

/* Define to 1 if you have the `strcspn' function. */
#define HAVE_STRCSPN 1

/* Define to 1 if you have the `strdup' function. */
#define HAVE_STRDUP 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the `strerror_r' function. */
/* #undef HAVE_STRERROR_R */

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strncasecmp' function. */
#define HAVE_STRNCASECMP 1

/* Define to 1 if you have the `strndup' function. */
#define HAVE_STRNDUP 1

/* Define to 1 if you have the `strpbrk' function. */
/* #undef HAVE_STRPBRK */

/* Define to 1 if you have the `strrchr' function. */
#define HAVE_STRRCHR 1

/* Define to 1 if you have the `strspn' function. */
#define HAVE_STRSPN 1

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* Define to 1 if you have the `strtoul' function. */
#define HAVE_STRTOUL 1

/* Define to 1 if you have the `strtoull' function. */
/* #undef HAVE_STRTOULL */

/* Define to 1 if `st_blocks' is a member of `struct stat'. */
#define HAVE_STRUCT_STAT_ST_BLOCKS 1

/* Define to 1 if `st_rdev' is a member of `struct stat'. */
#define HAVE_STRUCT_STAT_ST_RDEV 1

/* Define to 1 if your `struct stat' has `st_blocks'. Deprecated, use
   `HAVE_STRUCT_STAT_ST_BLOCKS' instead. */
#define HAVE_ST_BLOCKS 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/dir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_DIR_H */

/* Define to 1 if you have the <sys/disk.h> header file. */
/* #undef HAVE_SYS_DISK_H */

/* Define to 1 if you have the <sys/file.h> header file. */
#define HAVE_SYS_FILE_H 1

/* Define to 1 if you have the <sys/inotify.h> header file. */
/* #undef HAVE_SYS_INOTIFY_H */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/ipc.h> header file. */
/* #undef HAVE_SYS_IPC_H */

/* Define to 1 if you have the <sys/mman.h> header file. */
#define HAVE_SYS_MMAN_H 1

/* Define to 1 if you have the <sys/mount.h> header file. */
/* #undef HAVE_SYS_MOUNT_H */

/* Define to 1 if you have the <sys/ndir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_NDIR_H */

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/resource.h> header file. */
#define HAVE_SYS_RESOURCE_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
/* #undef HAVE_SYS_SELECT_H */

/* Define to 1 if you have the <sys/sem.h> header file. */
/* #undef HAVE_SYS_SEM_H */

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/statvfs.h> header file. */
#define HAVE_SYS_STATVFS_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/timerfd.h> header file. */
#define HAVE_SYS_TIMERFD_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/uio.h> header file. */
/* #undef HAVE_SYS_UIO_H */

/* Define to 1 if you have the <sys/un.h> header file. */
#define HAVE_SYS_UN_H 1

/* Define to 1 if you have the <sys/utsname.h> header file. */
#define HAVE_SYS_UTSNAME_H 1

/* Define to 1 if you have the <sys/vfs.h> header file. */
#define HAVE_SYS_VFS_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <termios.h> header file. */
#define HAVE_TERMIOS_H 1

/* Define to 1 if you have the <time.h> header file. */
#define HAVE_TIME_H 1

/* Define to 1 if you have the `uname' function. */
#define HAVE_UNAME 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <utmpx.h> header file. */
/* #undef HAVE_UTMPX_H */

/* valgrind.h found */
/* #undef HAVE_VALGRIND */

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if you have the `vprintf' function. */
#define HAVE_VPRINTF 1

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK 1

/* Define to 1 if the system has the type `_Bool'. */
#define HAVE__BOOL 1

/* Define to 1 if the system has the `__builtin_clz' built-in function */
#define HAVE___BUILTIN_CLZ 1

/* Internalization package */
/* #undef INTL_PACKAGE */

/* Locale-dependent data */
/* #undef LOCALEDIR */

/* Define to 1 to include code that uses lvmlockd dlm option. */
/* #undef LOCKDDLM_SUPPORT */

/* Define to 1 to include code that uses lvmlockd sanlock option. */
/* #undef LOCKDSANLOCK_SUPPORT */

/* Define to 1 if `lstat' dereferences a symlink specified with a trailing
   slash. */
#define LSTAT_FOLLOWS_SLASHED_SYMLINK 1

/* Define to 1 if 'lvm' should fall back to using LVM1 binaries if
   device-mapper is missing from the kernel */
/* #undef LVM1_FALLBACK */

/* Define to 1 to include built-in support for LVM1 metadata. */
/* #undef LVM1_INTERNAL */

/* Path to lvmetad pidfile. */
/* #undef LVMETAD_PIDFILE */

/* Define to 1 to include code that uses lvmetad. */
/* #undef LVMETAD_SUPPORT */

/* Path to lvmlockd pidfile. */
/* #undef LVMLOCKD_PIDFILE */

/* Define to 1 to include code that uses lvmlockd. */
/* #undef LVMLOCKD_SUPPORT */

/* Path to lvmpolld pidfile. */
/* #undef LVMPOLLD_PIDFILE */

/* Define to 1 to include code that uses lvmpolld. */
/* #undef LVMPOLLD_SUPPORT */

/* configure command line used */
#define LVM_CONFIGURE_LINE "./configure --with-lvm1=none --disable-selinux --disable-readline --enable-static_link"

/* Path to lvm binary. */
#define LVM_PATH "/sbin/lvm"

/* Define to 1 if `major', `minor', and `makedev' are declared in <mkdev.h>.
   */
/* #undef MAJOR_IN_MKDEV */

/* Define to 1 if `major', `minor', and `makedev' are declared in
   <sysmacros.h>. */
/* #undef MAJOR_IN_SYSMACROS */

/* Define to 1 to include built-in support for mirrors. */
#define MIRRORED_INTERNAL 1

/* The path to 'modprobe', if available. */
#define MODPROBE_CMD "/sbin/modprobe"

/* Define to 1 to include code that uses dbus notification. */
/* #undef NOTIFYDBUS_SUPPORT */

/* Define to 1 to enable O_DIRECT support. */
#define O_DIRECT_SUPPORT 1

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING ""

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME ""

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* Define to 1 to include built-in support for GFS pool metadata. */
#define POOL_INTERNAL 1

/* Define to 1 to include built-in support for raid. */
#define RAID_INTERNAL 1

/* Define to 1 to include the LVM readline shell. */
/* #undef READLINE_SUPPORT */

/* Define to 1 to include built-in support for replicators. */
/* #undef REPLICATOR_INTERNAL */

/* Define as the return type of signal handlers (`int' or `void'). */
#define RETSIGTYPE void

/* Define to the type of arg 1 for `select'. */
/* #undef SELECT_TYPE_ARG1 */

/* Define to the type of args 2, 3 and 4 for `select'. */
/* #undef SELECT_TYPE_ARG234 */

/* Define to the type of arg 5 for `select'. */
/* #undef SELECT_TYPE_ARG5 */

/* Define to 1 to include built-in support for snapshots. */
#define SNAPSHOT_INTERNAL 1

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at runtime.
	STACK_DIRECTION > 0 => grows toward higher addresses
	STACK_DIRECTION < 0 => grows toward lower addresses
	STACK_DIRECTION = 0 => direction of growth unknown */
/* #undef STACK_DIRECTION */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if strerror_r returns char *. */
/* #undef STRERROR_R_CHAR_P */

/* Path to testsuite data */
#define TESTSUITE_DATA "/usr/share/lvm2-testsuite"

/* The path to 'thin_check', if available. */
#define THIN_CHECK_CMD "/usr/sbin/thin_check"

/* Define to 1 if the external 'thin_check' tool requires the
   --clear-needs-check-flag option */
/* #undef THIN_CHECK_NEEDS_CHECK */

/* The path to 'thin_dump', if available. */
#define THIN_DUMP_CMD "/usr/sbin/thin_dump"

/* Define to 1 to include built-in support for thin provisioning. */
#define THIN_INTERNAL 1

/* The path to 'thin_repair', if available. */
#define THIN_REPAIR_CMD "/usr/sbin/thin_repair"

/* The path to 'thin_restore', if available. */
#define THIN_RESTORE_CMD "/usr/sbin/thin_restore"

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Define to 1 if your <sys/time.h> declares `struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* Define to 1 to enable synchronisation with udev processing. */
/* #undef UDEV_SYNC_SUPPORT */

/* Enable a valgrind aware build of pool */
/* #undef VALGRIND_POOL */

/* Define for Solaris 2.5.1 so the uint32_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT32_T */

/* Define for Solaris 2.5.1 so the uint64_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT64_T */

/* Define for Solaris 2.5.1 so the uint8_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT8_T */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to the type of a signed integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
/* #undef int16_t */

/* Define to the type of a signed integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef int32_t */

/* Define to the type of a signed integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
/* #undef int64_t */

/* Define to the type of a signed integer type of width exactly 8 bits if such
   a type exists and the standard includes do not define it. */
/* #undef int8_t */

/* Define to rpl_malloc if the replacement function should be used. */
/* #undef malloc */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef mode_t */

/* Define to `long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define to rpl_realloc if the replacement function should be used. */
/* #undef realloc */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef ssize_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

/* Define to the type of an unsigned integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint16_t */

/* Define to the type of an unsigned integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint32_t */

/* Define to the type of an unsigned integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint64_t */

/* Define to the type of an unsigned integer type of width exactly 8 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint8_t */

/* Define as `fork' if `vfork' does not work. */
/* #undef vfork */
