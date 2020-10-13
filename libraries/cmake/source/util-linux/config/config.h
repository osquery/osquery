/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Enable agetty --reload feature */
#define AGETTY_RELOAD 1

/* Should chfn and chsh require the user to enter the password? */
#define CHFN_CHSH_PASSWORD 1

/* Path to hwclock adjtime file */
#define CONFIG_ADJTIME_PATH "/etc/adjtime"

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
#define ENABLE_NLS 1

/* search path for fs helpers */
#define FS_SEARCH_PATH "/sbin:/sbin/fs.d:/sbin/fs"

/* Define to 1 if you have the <asm/io.h> header file. */
/* #undef HAVE_ASM_IO_H */

/* Define to 1 if you have the <byteswap.h> header file. */
#define HAVE_BYTESWAP_H 1

/* Define to 1 if you have the Mac OS X function CFLocaleCopyCurrent in the
   CoreFoundation framework. */
/* #undef HAVE_CFLOCALECOPYCURRENT */

/* Define to 1 if you have the Mac OS X function CFPreferencesCopyAppValue in
   the CoreFoundation framework. */
/* #undef HAVE_CFPREFERENCESCOPYAPPVALUE */

/* Define to 1 if you have the `clock_gettime' function. */
/* #undef HAVE_CLOCK_GETTIME */

/* Define to 1 if the system has the type `cpu_set_t'. */
#define HAVE_CPU_SET_T 1

/* Define to 1 if you have the <crypt.h> header file. */
#define HAVE_CRYPT_H 1

/* Define if the GNU dcgettext() function is already present or preinstalled.
   */
#define HAVE_DCGETTEXT 1

/* Define to 1 if you have the declaration of `CPU_ALLOC', and to 0 if you
   don't. */
#define HAVE_DECL_CPU_ALLOC 1

/* Define to 1 if you have the declaration of `dirfd', and to 0 if you don't.
   */
/* #undef HAVE_DECL_DIRFD */

/* Define to 1 if you have the declaration of `_NL_TIME_WEEK_1STDAY', and to 0
   if you don't. */
#define HAVE_DECL__NL_TIME_WEEK_1STDAY 1

/* Define to 1 if you have the `dirfd' function. */
#define HAVE_DIRFD 1

/* Define to 1 if `dd_fd' is a member of `DIR'. */
/* #undef HAVE_DIR_DD_FD */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <endian.h> header file. */
#define HAVE_ENDIAN_H 1

/* Define to 1 if have **environ prototype */
#define HAVE_ENVIRON_DECL 1

/* Define to 1 if you have the `err' function. */
#define HAVE_ERR 1

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the `errx' function. */
#define HAVE_ERRX 1

/* Define to 1 if you have the <err.h> header file. */
#define HAVE_ERR_H 1

/* Have valid fallocate() function */
#define HAVE_FALLOCATE 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if fseeko (and presumably ftello) exists and is declared. */
#define HAVE_FSEEKO 1

/* Define to 1 if you have the `fstatat' function. */
#define HAVE_FSTATAT 1

/* Define to 1 if you have the `fsync' function. */
#define HAVE_FSYNC 1

/* Define to 1 if you have the `futimens' function. */
#define HAVE_FUTIMENS 1

/* Define to 1 if you have the `getdomainname' function. */
#define HAVE_GETDOMAINNAME 1

/* Define to 1 if you have the `getdtablesize' function. */
#define HAVE_GETDTABLESIZE 1

/* Define to 1 if you have the `getexecname' function. */
/* #undef HAVE_GETEXECNAME */

/* Define to 1 if you have the `getmntinfo' function. */
/* #undef HAVE_GETMNTINFO */

/* Define to 1 if you have the <getopt.h> header file. */
#define HAVE_GETOPT_H 1

/* Define to 1 if you have the `getrlimit' function. */
#define HAVE_GETRLIMIT 1

/* Define to 1 if you have the `getsgnam' function. */
#define HAVE_GETSGNAM 1

/* Define if the GNU gettext() function is already present or preinstalled. */
#define HAVE_GETTEXT 1

/* Define if you have the iconv() function and it works. */
/* #undef HAVE_ICONV */

/* Define to 1 if you have the `inotify_init' function. */
#define HAVE_INOTIFY_INIT 1

/* Define to 1 if you have the `inotify_init1' function. */
#define HAVE_INOTIFY_INIT1 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `ioperm' function. */
#define HAVE_IOPERM 1

/* Define to 1 if you have the `iopl' function. */
#define HAVE_IOPL 1

/* Define to 1 if you have the `jrand48' function. */
#define HAVE_JRAND48 1

/* Define to 1 if you have the <langinfo.h> header file. */
#define HAVE_LANGINFO_H 1

/* Define to 1 if you have the `lchown' function. */
#define HAVE_LCHOWN 1

/* Define to 1 if you have the `audit' library (-laudit). */
/* #undef HAVE_LIBAUDIT */

/* Define to 1 if you have the -lblkid. */
#define HAVE_LIBBLKID 1

/* Define to 1 if you have the `cap-ng' library (-lcap-ng). */
/* #undef HAVE_LIBCAP_NG */

/* Do we need -lcrypt? */
#define HAVE_LIBCRYPT 1

/* Define if libmount available. */
#define HAVE_LIBMOUNT 1

/* Define to 1 if you have the `ncurses' library (-lncurses). */
/* #undef HAVE_LIBNCURSES */

/* Define to 1 if you have the `ncursesw' library (-lncursesw). */
/* #undef HAVE_LIBNCURSESW */

/* Define to 1 if you have the `readline' library (-lreadline). */
/* #undef HAVE_LIBREADLINE */

/* Define if SELinux is available */
/* #undef HAVE_LIBSELINUX */

/* Define if libsystemd is available */
/* #undef HAVE_LIBSYSTEMD */

/* Define to 1 if you have the `termcap' library (-ltermcap). */
/* #undef HAVE_LIBTERMCAP */

/* Define if libtinfo available. */
/* #undef HAVE_LIBTINFO */

/* Define to 1 if you have the `udev' library (-ludev). */
/* #undef HAVE_LIBUDEV */

/* Define if libuser is available */
/* #undef HAVE_LIBUSER */

/* Define to 1 if you have the `utempter' library (-lutempter). */
/* #undef HAVE_LIBUTEMPTER */

/* Define to 1 if you have the `util' library (-lutil). */
#define HAVE_LIBUTIL 1

/* Define to 1 if you have the -luuid. */
#define HAVE_LIBUUID 1

/* Define to 1 if you have the <linux/blkpg.h> header file. */
#define HAVE_LINUX_BLKPG_H 1

/* Define to 1 if you have the <linux/cdrom.h> header file. */
#define HAVE_LINUX_CDROM_H 1

/* Define to 1 if you have the <linux/compiler.h> header file. */
/* #undef HAVE_LINUX_COMPILER_H */

/* Define to 1 if you have the <linux/falloc.h> header file. */
#define HAVE_LINUX_FALLOC_H 1

/* Define to 1 if you have the <linux/fd.h> header file. */
#define HAVE_LINUX_FD_H 1

/* Define to 1 if you have the <linux/gsmmux.h> header file. */
/* #undef HAVE_LINUX_GSMMUX_H */

/* Define to 1 if you have the <linux/major.h> header file. */
#define HAVE_LINUX_MAJOR_H 1

/* Define to 1 if you have the <linux/raw.h> header file. */
#define HAVE_LINUX_RAW_H 1

/* Define to 1 if you have the <linux/securebits.h> header file. */
#define HAVE_LINUX_SECUREBITS_H 1

/* Define to 1 if you have the <linux/tiocl.h> header file. */
#define HAVE_LINUX_TIOCL_H 1

/* Define to 1 if you have the <linux/version.h> header file. */
#define HAVE_LINUX_VERSION_H 1

/* Define to 1 if you have the <linux/watchdog.h> header file. */
#define HAVE_LINUX_WATCHDOG_H 1

/* Define to 1 if you have the `llseek' function. */
#define HAVE_LLSEEK 1

/* Define to 1 if have llseek prototype */
/* #undef HAVE_LLSEEK_PROTOTYPE */

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define to 1 if the system has the type `loff_t'. */
#define HAVE_LOFF_T 1

/* Define to 1 if you have the `lseek64' function. */
#define HAVE_LSEEK64 1

/* Define to 1 if have lseek64 prototype */
#define HAVE_LSEEK64_PROTOTYPE 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `mempcpy' function. */
#define HAVE_MEMPCPY 1

/* Define to 1 if you have the <mntent.h> header file. */
#define HAVE_MNTENT_H 1

/* Define to 1 if you have the `nanosleep' function. */
#define HAVE_NANOSLEEP 1

/* Define to 1 if you have the <ncursesw/ncurses.h> header file. */
/* #undef HAVE_NCURSESW_NCURSES_H */

/* Define to 1 if you have the <ncurses.h> header file. */
/* #undef HAVE_NCURSES_H */

/* Define to 1 if you have the <ncurses/ncurses.h> header file. */
/* #undef HAVE_NCURSES_NCURSES_H */

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the <net/if_dl.h> header file. */
/* #undef HAVE_NET_IF_DL_H */

/* Define to 1 if you have the <net/if.h> header file. */
#define HAVE_NET_IF_H 1

/* Define to 1 if you have the `ntp_gettime' function. */
#define HAVE_NTP_GETTIME 1

/* Define to 1 if you have the `openat' function. */
#define HAVE_OPENAT 1

/* Define to 1 if you have the `open_memstream' function. */
#define HAVE_OPEN_MEMSTREAM 1

/* Define to 1 if you have the <paths.h> header file. */
#define HAVE_PATHS_H 1

/* Define to 1 if you have the `personality' function. */
#define HAVE_PERSONALITY 1

/* Define to 1 if you have the `posix_fadvise' function. */
#define HAVE_POSIX_FADVISE 1

/* Define to 1 if you have the `prctl' function. */
#define HAVE_PRCTL 1

/* Define to 1 if you have the `prlimit' function. */
/* #undef HAVE_PRLIMIT */

/* Define if program_invocation_short_name is defined */
#define HAVE_PROGRAM_INVOCATION_SHORT_NAME 1

/* Define to 1 if you have the <pty.h> header file. */
#define HAVE_PTY_H 1

/* Define to 1 if you have the `qsort_r' function. */
#define HAVE_QSORT_R 1

/* Define if curses library has the resizeterm(). */
/* #undef HAVE_RESIZETERM */

/* Define to 1 if you have the `rpmatch' function. */
#define HAVE_RPMATCH 1

/* Define if struct sockaddr contains sa_len */
/* #undef HAVE_SA_LEN */

/* Define to 1 if you have the `scandirat' function. */
/* #undef HAVE_SCANDIRAT */

/* scanf %as modifier */
/* #undef HAVE_SCANF_AS_MODIFIER */

/* scanf %ms modifier */
#define HAVE_SCANF_MS_MODIFIER 1

/* Define to 1 if you have the `secure_getenv' function. */
/* #undef HAVE_SECURE_GETENV */

/* Define to 1 if you have the `security_get_initial_context' function. */
/* #undef HAVE_SECURITY_GET_INITIAL_CONTEXT */

/* Define to 1 if you have the <security/openpam.h> header file. */
/* #undef HAVE_SECURITY_OPENPAM_H */

/* Define to 1 if you have the <security/pam_appl.h> header file. */
/* #undef HAVE_SECURITY_PAM_APPL_H */

/* Define to 1 if you have the <security/pam_misc.h> header file. */
/* #undef HAVE_SECURITY_PAM_MISC_H */

/* Define to 1 if you have the `setns' function. */
/* #undef HAVE_SETNS */

/* Define to 1 if you have the `setresgid' function. */
#define HAVE_SETRESGID 1

/* Define to 1 if you have the `setresuid' function. */
#define HAVE_SETRESUID 1

/* Define to 1 if the system has the type `sighandler_t'. */
#define HAVE_SIGHANDLER_T 1

/* Define to 1 if you have the `sigqueue' function. */
#define HAVE_SIGQUEUE 1

/* Define to 1 if you have the <slang.h> header file. */
/* #undef HAVE_SLANG_H */

/* Define to 1 if you have the <slang/slang.h> header file. */
/* #undef HAVE_SLANG_SLANG_H */

/* Define to 1 if you have the <slang/slcurses.h> header file. */
/* #undef HAVE_SLANG_SLCURSES_H */

/* Define to 1 if you have the <slcurses.h> header file. */
/* #undef HAVE_SLCURSES_H */

/* Add SMACK support */
/* #undef HAVE_SMACK */

/* Define to 1 if you have the `srandom' function. */
#define HAVE_SRANDOM 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdio_ext.h> header file. */
#define HAVE_STDIO_EXT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strnchr' function. */
/* #undef HAVE_STRNCHR */

/* Define to 1 if you have the `strndup' function. */
#define HAVE_STRNDUP 1

/* Define to 1 if you have the `strnlen' function. */
#define HAVE_STRNLEN 1

/* Define to 1 if have strsignal function prototype */
#define HAVE_STRSIGNAL_DECL 1

/* Define to 1 if `st_mtim.tv_nsec' is a member of `struct stat'. */
#define HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC 1

/* Define to 1 if `c_line' is a member of `struct termios'. */
#define HAVE_STRUCT_TERMIOS_C_LINE 1

/* Define to 1 if you have the `sysconf' function. */
#define HAVE_SYSCONF 1

/* Define to 1 if you have the `sysinfo' function. */
#define HAVE_SYSINFO 1

/* Define to 1 if you have the <sys/disklabel.h> header file. */
/* #undef HAVE_SYS_DISKLABEL_H */

/* Define to 1 if you have the <sys/disk.h> header file. */
/* #undef HAVE_SYS_DISK_H */

/* Define to 1 if you have the <sys/endian.h> header file. */
/* #undef HAVE_SYS_ENDIAN_H */

/* Define to 1 if you have the <sys/file.h> header file. */
#define HAVE_SYS_FILE_H 1

/* Define to 1 if you have the <sys/ioccom.h> header file. */
/* #undef HAVE_SYS_IOCCOM_H */

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/io.h> header file. */
#define HAVE_SYS_IO_H 1

/* Define to 1 if you have the <sys/mkdev.h> header file. */
/* #undef HAVE_SYS_MKDEV_H */

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/prctl.h> header file. */
#define HAVE_SYS_PRCTL_H 1

/* Define to 1 if you have the <sys/queue.h> header file. */
#define HAVE_SYS_QUEUE_H 1

/* Define to 1 if you have the <sys/resource.h> header file. */
#define HAVE_SYS_RESOURCE_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/sockio.h> header file. */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/swap.h> header file. */
#define HAVE_SYS_SWAP_H 1

/* Define to 1 if you have the <sys/syscall.h> header file. */
#define HAVE_SYS_SYSCALL_H 1

/* Define to 1 if you have the <sys/timex.h> header file. */
#define HAVE_SYS_TIMEX_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/ttydefaults.h> header file. */
#define HAVE_SYS_TTYDEFAULTS_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
#define HAVE_SYS_UN_H 1

/* Define to 1 if you have the `timer_createx' function. */
/* #undef HAVE_TIMER_CREATEX */

/* Define to 1 if the target supports thread-local storage. */
#define HAVE_TLS 1

/* Does struct tm have a field tm_gmtoff? */
#define HAVE_TM_GMTOFF 1

/* Define to 1 if the system has the type `union semun'. */
/* #undef HAVE_UNION_SEMUN */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `unlinkat' function. */
#define HAVE_UNLINKAT 1

/* Define to 1 if you have the `unshare' function. */
#define HAVE_UNSHARE 1

/* Define to 1 if you have the `updwtmp' function. */
#define HAVE_UPDWTMP 1

/* Define if curses library has the use_default_colors(). */
/* #undef HAVE_USE_DEFAULT_COLORS */

/* Define to 1 if you have the `usleep' function. */
#define HAVE_USLEEP 1

/* Define to 1 if you have the `utimensat' function. */
#define HAVE_UTIMENSAT 1

/* Define to 1 if you want to use uuid daemon. */
#define HAVE_UUIDD 1

/* Define to 1 if you have the `warn' function. */
#define HAVE_WARN 1

/* Define to 1 if you have the `warnx' function. */
#define HAVE_WARNX 1

/* Do we have wide character support? */
#define HAVE_WIDECHAR 1

/* Define to 1 if you have the `__fpending' function. */
#define HAVE___FPENDING 1

/* Define if __progname is defined */
/* #undef HAVE___PROGNAME */

/* Define to 1 if you have the `__secure_getenv' function. */
#define HAVE___SECURE_GETENV 1

/* libblkid date string */
#define LIBBLKID_DATE "02-Nov-2015"

/* libblkid version string */
#define LIBBLKID_VERSION "2.27.0"

/* libfdisk version string */
#define LIBFDISK_VERSION "2.27.0"

/* libmount version string */
#define LIBMOUNT_VERSION "2.27.0"

/* libsmartcols version string */
#define LIBSMARTCOLS_VERSION "2.27.0"

/* Should login chown /dev/vcsN? */
/* #undef LOGIN_CHOWN_VCS */

/* Should login stat() the mailbox? */
/* #undef LOGIN_STAT_MAIL */

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Define to 1 if assertions should be disabled. */
/* #undef NDEBUG */

/* Should chsh allow only shells in /etc/shells? */
#define ONLY_LISTED_SHELLS 1

/* Name of package */
#define PACKAGE "util-linux"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "kzak@redhat.com"

/* Define to the full name of this package. */
#define PACKAGE_NAME "util-linux"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "util-linux 2.27.1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "util-linux"

/* Define to the home page for this package. */
#define PACKAGE_URL "http://www.kernel.org/pub/linux/utils/util-linux/"

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.27.1"

/* Should pg ring the bell on invalid keys? */
#define PG_BELL 1

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Is swapon() declared with two parameters? */
#define SWAPON_HAS_TWO_ARGS 1

/* Fallback syscall number for fallocate */
/* #undef SYS_fallocate */

/* Fallback syscall number for ioprio_get */
/* #undef SYS_ioprio_get */

/* Fallback syscall number for ioprio_set */
/* #undef SYS_ioprio_set */

/* Fallback syscall number for pivot_root */
/* #undef SYS_pivot_root */

/* Fallback syscall number for prlimit64 */
/* #undef SYS_prlimit64 */

/* Fallback syscall number for sched_getaffinity */
/* #undef SYS_sched_getaffinity */

/* Fallback syscall number for setns */
/* #undef SYS_setns */

/* Fallback syscall number for unshare */
/* #undef SYS_unshare */

/* Enables colorized output from utils by default */
#define USE_COLORS_BY_DEFAULT 1

/* Define to 1 if want to ignore mtab in all situations. */
/* #undef USE_LIBMOUNT_FORCE_MOUNTINFO */

/* Should sulogin use a emergency mount of /dev and /proc? */
/* #undef USE_SULOGIN_EMERGENCY_MOUNT */

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif


/* Should wall and write be installed setgid tty? */
#define USE_TTY_GROUP 1

/* Define to 1 to remove /bin and /sbin from PATH env.variable */
/* #undef USE_USRDIR_PATHS_ONLY */

/* Version number of package */
#define VERSION "2.27.1"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define to 1 to make fseeko visible on some hosts (e.g. glibc 2.2). */
/* #undef _LARGEFILE_SOURCE */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to empty if the keyword `volatile' does not work. Warning: valid
   code using `volatile' can become incorrect without. Disable with care. */
/* #undef volatile */
