/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Directory for AppArmor profiles (Linux) */
#define APPARMORDIR "no"

/* Build date and time */
#define BUILD_DATE "2019-07-31T21:20:43Z"

/* Cisco Discovery Protocol */
#define ENABLE_CDP /**/

/* Custom TLV support */
#define ENABLE_CUSTOM /**/

/* Dot1 extension (VLAN stuff) */
#define ENABLE_DOT1 /**/

/* Dot3 extension (PHY stuff) */
#define ENABLE_DOT3 /**/

/* systemtap/DTrace trace support */
/* #undef ENABLE_DTRACE */

/* Extreme Discovery Protocol */
#define ENABLE_EDP /**/

/* Foundry Discovery Protocol */
#define ENABLE_FDP /**/

/* use of pre-0.9.2 JSON/json-c format */
/* #undef ENABLE_JSON0 */

/* LLDP-MED extension */
#define ENABLE_LLDPMED /**/

/* compatibility with Linux kernel older than 2.6.39 */
/* #undef ENABLE_OLDIES */

/* Privilege separation */
#define ENABLE_PRIVSEP /**/

/* SynOptics Network Management Protocol */
#define ENABLE_SONMP /**/

/* Define if have both address and leak sanitizer */
/* #undef HAVE_ADDRESS_SANITIZER */

/* Define if __alignof__ operator is available */
#define HAVE_ALIGNOF 1

/* Define to 1 if you have the <arpa/nameser.h> header file. */
#define HAVE_ARPA_NAMESER_H 1

/* Define to 1 if you have the `asprintf' function. */
#define HAVE_ASPRINTF 1

/* Define to 1 if you have the `daemon' function. */
#define HAVE_DAEMON 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `getline' function. */
#define HAVE_GETLINE 1

/* Define to 1 if you have the <history.h> header file. */
/* #undef HAVE_HISTORY_H */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define if you have a readline compatible library */
/* #undef HAVE_LIBREADLINE */

/* Define to 1 if your system has a GNU libc compatible `malloc' function, and
   to 0 otherwise. */
#define HAVE_MALLOC 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the `netsnmp_enable_subagent' function. */
/* #undef HAVE_NETSNMP_ENABLE_SUBAGENT */

/* Define to 1 if `f_create_from_tstring_new' is a member of
   `netsnmp_tdomain'. */
/* #undef HAVE_NETSNMP_TDOMAIN_F_CREATE_FROM_TSTRING_NEW */

/* Define to 1 if you have the <net-snmp/agent/util_funcs.h> header file. */
/* #undef HAVE_NET_SNMP_AGENT_UTIL_FUNCS_H */

/* Define to 1 if you have the <readline.h> header file. */
/* #undef HAVE_READLINE_H */

/* Define if your readline library has \`add_history' */
/* #undef HAVE_READLINE_HISTORY */

/* Define to 1 if you have the <readline/history.h> header file. */
/* #undef HAVE_READLINE_HISTORY_H */

/* Define to 1 if you have the <readline/readline.h> header file. */
/* #undef HAVE_READLINE_READLINE_H */

/* Define to 1 if your system has a GNU libc compatible `realloc' function,
   and to 0 otherwise. */
#define HAVE_REALLOC 1

/* Define to 1 if you have the <resolv.h> header file. */
#define HAVE_RESOLV_H 1

/* Define to indicate that res_init() exists */
#define HAVE_RES_INIT 1

/* Define to 1 if you have the `setproctitle' function. */
/* #undef HAVE_SETPROCTITLE */

/* Define to 1 if you have the `setproctitle_init' function. */
/* #undef HAVE_SETPROCTITLE_INIT */

/* Define to 1 if you have the `setresgid' function. */
#define HAVE_SETRESGID 1

/* Define to 1 if you have the `setresuid' function. */
#define HAVE_SETRESUID 1

/* Define to 1 if you have the `snmp_select_info2' function. */
/* #undef HAVE_SNMP_SELECT_INFO2 */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the `strndup' function. */
#define HAVE_STRNDUP 1

/* Define to 1 if you have the `strnlen' function. */
#define HAVE_STRNLEN 1

/* Define to 1 if you have the `strtonum' function. */
/* #undef HAVE_STRTONUM */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if typeof works with your compiler. */
#define HAVE_TYPEOF 1

/* Define to 1 if the system has the type `uint32_t'. */
#define HAVE_UINT32_T 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if the system has the type `u_int32_t'. */
#define HAVE_U_INT32_T 1

/* Define to 1 if you have the <valgrind/valgrind.h> header file. */
/* #undef HAVE_VALGRIND_VALGRIND_H */

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if you have the `vsyslog' function. */
#define HAVE_VSYSLOG 1

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK 1

/* Define if libc defines __progname */
#define HAVE___PROGNAME 1

/* Host operating system is DragonFly BSD */
/* #undef HOST_OS_DRAGONFLY */

/* Host operating system is FreeBSD */
/* #undef HOST_OS_FREEBSD */

/* Host operating system is Linux */
#define HOST_OS_LINUX 1

/* Host operating system is NetBSD */
/* #undef HOST_OS_NETBSD */

/* Host operating system is OpenBSD */
/* #undef HOST_OS_OPENBSD */

/* Host operating system is OS X */
/* #undef HOST_OS_OSX */

/* Host operating system is Solaris */
/* #undef HOST_OS_SOLARIS */

/* Directory for launchd configuration file (OSX) */
#define LAUNCHDDAEMONSDIR "no"

/* Path to socket for communication with lldpd */
#define LLDPD_CTL_SOCKET "/usr/local/var/run/lldpd.socket"

/* Path to lldpd PID file */
#define LLDPD_PID_FILE "/usr/local/var/run/lldpd.pid"

/* C compiler command */
#define LLDP_CC "gcc  -fdiagnostics-show-option -fdiagnostics-color=auto -pipe -Wall -W -Wextra -Wformat -Wformat-security -Wfatal-errors -Wcast-align -Winline -Wpointer-arith -fno-omit-frame-pointer -Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -fstack-protector -fstack-protector-all -fstack-protector-strong  -D_FORTIFY_SOURCE=2 -D_GNU_SOURCE -g -O2 "

/* Linker compiler command */
#define LLDP_LD "/usr/bin/ld -Wl,-z,relro -Wl,-z,now   "

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Minimal kernel version required */
#define MIN_LINUX_KERNEL_VERSION "2.6.39"

/* Netlink maximum receive buffer size */
#define NETLINK_MAX_RECEIVE_BUFSIZE 1024*1024

/* Netlink initial receive buffer size */
#define NETLINK_RECEIVE_BUFSIZE 0

/* Netlink send buffer size */
#define NETLINK_SEND_BUFSIZE 0

/* Name of package */
#define PACKAGE "lldpd"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://github.com/vincentbernat/lldpd/issues"

/* Define to the full name of this package. */
#define PACKAGE_NAME "lldpd"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "lldpd 0.9.6-dirty"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "lldpd"

/* Define to the home page for this package. */
#define PACKAGE_URL "http://vincentbernat.github.io/lldpd/"

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.9.6-dirty"

/* Which directory to use to chroot lldpd */
#define PRIVSEP_CHROOT "/var/empty"

/* Which group to use for privilege separation */
#define PRIVSEP_GROUP "nogroup"

/* Which user to use for privilege separation */
#define PRIVSEP_USER "nobody"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Directory for systemd service files */
#define SYSTEMDSYSTEMUNITDIR "/usr/share"

/* Directory for sysusers files */
#define SYSUSERSDIR "/usr/share"

/* Define to indicate to enable JSON support through jansson */
/* #undef USE_JANSSON */

/* Define to indicate to enable JSON support */
/* #undef USE_JSON */

/* Define to indicate to enable JSON via json-c support */
/* #undef USE_JSONC */

/* Define to indicate to enable seccomp support */
/* #undef USE_SECCOMP */

/* Define to indicate to enable SNMP support */
/* #undef USE_SNMP */

/* Define to indicate to enable XML support */
/* #undef USE_XML */

/* Version number of package */
#define VERSION "0.9.6-dirty"

/* Define to rpl_malloc if the replacement function should be used. */
/* #undef malloc */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define to rpl_realloc if the replacement function should be used. */
/* #undef realloc */

/* Define to __typeof__ if your compiler spells it that way. */
/* #undef typeof */

/* Compatibility with Linux u_int16_t */
/* #undef u_int16_t */

/* Compatibility with Linux u_int32_t */
/* #undef u_int32_t */

/* Compatibility with Linux u_int64_t */
/* #undef u_int64_t */

/* Compatibility with Linux u_int8_t */
/* #undef u_int8_t */

/* Define as `fork' if `vfork' does not work. */
/* #undef vfork */
