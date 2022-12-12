/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if __attribute__((destructor)) is accepted */
#define ATTRIBUTE_DESTRUCTOR __attribute__((destructor))

/* Type cast for the gethostbyname() argument */
#define GETHOSTBYNAME_ARG_CAST /**/

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the <arpa/nameser.h> header file. */
#define HAVE_ARPA_NAMESER_H 1

/* Whether struct sockaddr::__ss_family exists */
/* #undef HAVE_BROKEN_SS_FAMILY */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Have dlopen based dso */
#define HAVE_DLOPEN 1

/* Define to 1 if you have the <dl.h> header file. */
/* #undef HAVE_DL_H */

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `ftime' function. */
#define HAVE_FTIME 1

/* Define if getaddrinfo is there */
#define HAVE_GETADDRINFO 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `isascii' function. */
#define HAVE_ISASCII 1

/* Define if history library is there (-lhistory) */
/* #undef HAVE_LIBHISTORY */

/* Define if readline library is there (-lreadline) */
#define HAVE_LIBREADLINE 1

/* Define to 1 if you have the `mmap' function. */
#define HAVE_MMAP 1

/* Define to 1 if you have the `munmap' function. */
#define HAVE_MUNMAP 1

/* mmap() is no good without munmap() */
#if defined(HAVE_MMAP) && !defined(HAVE_MUNMAP)
#  undef /**/ HAVE_MMAP
#endif

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have the <poll.h> header file. */
#define HAVE_POLL_H 1

/* Define if <pthread.h> is there */
#define HAVE_PTHREAD_H 1

/* Define to 1 if you have the `putenv' function. */
#define HAVE_PUTENV 1

/* Define to 1 if you have the `rand_r' function. */
#define HAVE_RAND_R 1

/* Define to 1 if you have the <resolv.h> header file. */
#define HAVE_RESOLV_H 1

/* Have shl_load based dso */
/* #undef HAVE_SHLLOAD */

/* Define to 1 if you have the `stat' function. */
#define HAVE_STAT 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <sys/mman.h> header file. */
#define HAVE_SYS_MMAN_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/timeb.h> header file. */
#define HAVE_SYS_TIMEB_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Whether va_copy() is available */
/* #undef HAVE_VA_COPY */

/* Define to 1 if you have the <zlib.h> header file. */
/* #undef HAVE_ZLIB_H */

/* Whether __va_copy() is available */
/* #undef HAVE___VA_COPY */

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "libxml2"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "xml@gnome.org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libxml2"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libxml2 2.10.3"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libxml2"

/* Define to the home page for this package. */
#define PACKAGE_URL "https://gitlab.gnome.org/GNOME/libxml2"

/* Define to the version of this package. */
#define PACKAGE_VERSION "2.10.3"

/* Type cast for the send() function 2nd arg */
#define SEND_ARG2_CAST /**/

/* Support for IPv6 */
/* #undef SUPPORT_IP6 */

/* Define if va_list is an array type */
/* #undef VA_LIST_IS_ARRAY */

/* Version number of package */
#define VERSION "2.10.3"

/* Determine what socket length (socklen_t) data type is */
#define XML_SOCKLEN_T socklen_t

/* Define for Solaris 2.5.1 so the uint32_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
/* #undef _UINT32_T */

/* ss_family is not defined here, use __ss_family instead */
/* #undef ss_family */

/* Define to the type of an unsigned integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
/* #undef uint32_t */
