/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if __attribute__((destructor)) is accepted */
/* #undef ATTRIBUTE_DESTRUCTOR */

/* Type cast for the gethostbyname() argument */
#define GETHOSTBYNAME_ARG_CAST (char *)

/* Define to 1 if you have the <arpa/inet.h> header file. */
/* #undef HAVE_ARPA_INET_H */

/* Define to 1 if you have the <arpa/nameser.h> header file. */
/* #undef HAVE_ARPA_NAMESER_H */

/* Whether struct sockaddr::__ss_family exists */
/* #undef HAVE_BROKEN_SS_FAMILY */

/* Define to 1 if you have the <ctype.h> header file. */
#define HAVE_CTYPE_H 1

/* Define to 1 if you have the <dirent.h> header file. */
/* #undef HAVE_DIRENT_H */

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #undef HAVE_DLFCN_H */

/* Have dlopen based dso */
/* #undef HAVE_DLOPEN */

/* Define to 1 if you have the <dl.h> header file. */
/* #undef HAVE_DL_H */

/* Define to 1 if you have the <errno.h> header file. */
/* #undef HAVE_ERRNO_H */

/* Define to 1 if you have the <fcntl.h> header file. */
/* #undef HAVE_FCNTL_H */

/* Define to 1 if you have the <float.h> header file. */
/* #undef HAVE_FLOAT_H */

/* Define to 1 if you have the `fprintf' function. */
/* #undef HAVE_FPRINTF */

/* Define to 1 if you have the `ftime' function. */
/* #undef HAVE_FTIME */

/* Define if getaddrinfo is there */
/* #undef HAVE_GETADDRINFO */

/* Define to 1 if you have the `gettimeofday' function. */
/* #undef HAVE_GETTIMEOFDAY */

/* Define to 1 if you have the <inttypes.h> header file. */
/* #undef HAVE_INTTYPES_H */

/* Define to 1 if you have the `isascii' function. */
/* #undef HAVE_ISASCII */

/* Define if isinf is there */
/* #undef HAVE_ISINF */

/* Define if isnan is there */
/* #undef HAVE_ISNAN */

/* Define if history library is there (-lhistory) */
/* #undef HAVE_LIBHISTORY */

/* Define if pthread library is there (-lpthread) */
/* #undef HAVE_LIBPTHREAD */

/* Define if readline library is there (-lreadline) */
/* #undef HAVE_LIBREADLINE */

/* Define to 1 if you have the <limits.h> header file. */
/* #undef HAVE_LIMITS_H */

/* Define to 1 if you have the `localtime' function. */
/* #undef HAVE_LOCALTIME */

/* Define to 1 if you have the <lzma.h> header file. */
/* #undef HAVE_LZMA_H */

/* Define to 1 if you have the <malloc.h> header file. */
/* #undef HAVE_MALLOC_H */

/* Define to 1 if you have the <math.h> header file. */
#define HAVE_MATH_H 1

/* Define to 1 if you have the <memory.h> header file. */
/* #undef HAVE_MEMORY_H */

/* Define to 1 if you have the `mmap' function. */
/* #undef HAVE_MMAP */

/* Define to 1 if you have the `munmap' function. */
/* #undef HAVE_MUNMAP */

/* mmap() is no good without munmap() */
#if defined(HAVE_MMAP) && !defined(HAVE_MUNMAP)
#  undef /**/ HAVE_MMAP
#endif

/* Define to 1 if you have the <ndir.h> header file, and it defines `DIR'. */
/* #undef HAVE_NDIR_H */

/* Define to 1 if you have the <netdb.h> header file. */
/* #undef HAVE_NETDB_H */

/* Define to 1 if you have the <netinet/in.h> header file. */
/* #undef HAVE_NETINET_IN_H */

/* Define to 1 if you have the <poll.h> header file. */
/* #undef HAVE_POLL_H */

/* Define to 1 if you have the `printf' function. */
/* #undef HAVE_PRINTF */

/* Define if <pthread.h> is there */
/* #undef HAVE_PTHREAD_H */

/* Define to 1 if you have the `putenv' function. */
/* #undef HAVE_PUTENV */

/* Define to 1 if you have the `rand' function. */
/* #undef HAVE_RAND */

/* Define to 1 if you have the `rand_r' function. */
/* #undef HAVE_RAND_R */

/* Define to 1 if you have the <resolv.h> header file. */
/* #undef HAVE_RESOLV_H */

/* Have shl_load based dso */
/* #undef HAVE_SHLLOAD */

/* Define to 1 if you have the `signal' function. */
/* #undef HAVE_SIGNAL */

/* Define to 1 if you have the <signal.h> header file. */
/* #undef HAVE_SIGNAL_H */

/* Define to 1 if you have the `snprintf' function. */
/* #undef HAVE_SNPRINTF */

/* Define to 1 if you have the `sprintf' function. */
/* #undef HAVE_SPRINTF */

/* Define to 1 if you have the `srand' function. */
/* #undef HAVE_SRAND */

/* Define to 1 if you have the `sscanf' function. */
/* #undef HAVE_SSCANF */

/* Define to 1 if you have the `stat' function. */
/* #undef HAVE_STAT */

/* Define to 1 if you have the <stdarg.h> header file. */
/* #undef HAVE_STDARG_H */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
/* #undef HAVE_STDLIB_H */

/* Define to 1 if you have the `strftime' function. */
/* #undef HAVE_STRFTIME */

/* Define to 1 if you have the <strings.h> header file. */
/* #undef HAVE_STRINGS_H */

/* Define to 1 if you have the <string.h> header file. */
/* #undef HAVE_STRING_H */

/* Define to 1 if you have the <sys/dir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_DIR_H */

/* Define to 1 if you have the <sys/mman.h> header file. */
/* #undef HAVE_SYS_MMAN_H */

/* Define to 1 if you have the <sys/ndir.h> header file, and it defines `DIR'.
   */
/* #undef HAVE_SYS_NDIR_H */

/* Define to 1 if you have the <sys/select.h> header file. */
/* #undef HAVE_SYS_SELECT_H */

/* Define to 1 if you have the <sys/socket.h> header file. */
/* #undef HAVE_SYS_SOCKET_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
/* #undef HAVE_SYS_STAT_H */

/* Define to 1 if you have the <sys/timeb.h> header file. */
/* #undef HAVE_SYS_TIMEB_H */

/* Define to 1 if you have the <sys/time.h> header file. */
/* #undef HAVE_SYS_TIME_H */

/* Define to 1 if you have the <sys/types.h> header file. */
/* #undef HAVE_SYS_TYPES_H */

/* Define to 1 if you have the `time' function. */
/* #undef HAVE_TIME */

/* Define to 1 if you have the <time.h> header file. */
/* #undef HAVE_TIME_H */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Whether va_copy() is available */
#define HAVE_VA_COPY 1

/* Define to 1 if you have the `vfprintf' function. */
/* #undef HAVE_VFPRINTF */

/* Define to 1 if you have the `vsnprintf' function. */
/* #undef HAVE_VSNPRINTF */

/* Define to 1 if you have the `vsprintf' function. */
/* #undef HAVE_VSPRINTF */

/* Define to 1 if you have the <zlib.h> header file. */
/* #undef HAVE_ZLIB_H */

/* Whether __va_copy() is available */
/* #undef HAVE___VA_COPY */

/* Define as const if the declaration of iconv() needs const. */
#define ICONV_CONST const

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "libxml2"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "xml@gnome.org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libxml2"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libxml2 2.9.10"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libxml2"

/* Define to the home page for this package. */
#define PACKAGE_URL "http://www.xmlsoft.org/"

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.9.10"

/* Type cast for the send() function 2nd arg */
#define SEND_ARG2_CAST (char *)

/* Define to 1 if you have the ANSI C header files. */
/* #undef STDC_HEADERS */

/* Support for IPv6 */
/* #undef SUPPORT_IP6 */

/* Define if va_list is an array type */
#define VA_LIST_IS_ARRAY 1

/* Version number of package */
#define VERSION "2.9.10"

/* Determine what socket length (socklen_t) data type is */
#define XML_SOCKLEN_T int

/* Define for Solaris 2.5.1 so the uint32_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT32_T */

/* ss_family is not defined here, use __ss_family instead */
/* #undef ss_family */

/* Define to the type of an unsigned integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint32_t */
