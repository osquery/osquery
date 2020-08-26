/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* GIT commit id revision used to build this package */
#define BUILD_REVISION "c1668f6"

/* The time this package was configured for a build */
#define BUILD_TIMESTAMP "<none>"

/* Define to 1 if translation of program messages to the user's native
   language is requested. */
#define ENABLE_NLS 1

/* Define to use the GNU C visibility attribute. */
#define GPGRT_USE_VISIBILITY 1

/* Define to 1 if you have the Mac OS X function CFLocaleCopyCurrent in the
   CoreFoundation framework. */
/* #undef HAVE_CFLOCALECOPYCURRENT */

/* Define to 1 if you have the Mac OS X function CFPreferencesCopyAppValue in
   the CoreFoundation framework. */
/* #undef HAVE_CFPREFERENCESCOPYAPPVALUE */

/* Define if the GNU dcgettext() function is already present or preinstalled.
   */
#define HAVE_DCGETTEXT 1

/* Define to 1 if you have the declaration of `strerror_r', and to 0 if you
   don't. */
#define HAVE_DECL_STRERROR_R 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `flockfile' function. */
#define HAVE_FLOCKFILE 1

/* Defined if a GCC style "__attribute__ ((aligned (n))" is supported */
#define HAVE_GCC_ATTRIBUTE_ALIGNED 1

/* Define if the GNU gettext() function is already present or preinstalled. */
#define HAVE_GETTEXT 1

/* Define if you have the iconv() function and it works. */
/* #undef HAVE_ICONV */

/* Define to 1 if the system has the type `intmax_t'. */
#define HAVE_INTMAX_T 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define if you have <langinfo.h> and nl_langinfo(THOUSANDS_SEP). */
#define HAVE_LANGINFO_THOUSANDS_SEP 1

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define to 1 if the system has the type `long double'. */
#define HAVE_LONG_DOUBLE 1

/* Define to 1 if the system has the type 'long long int'. */
#define HAVE_LONG_LONG_INT 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memrchr' function. */
#define HAVE_MEMRCHR 1

/* Define if the <pthread.h> defines PTHREAD_MUTEX_RECURSIVE. */
#define HAVE_PTHREAD_MUTEX_RECURSIVE 1

/* Define if the POSIX multithreading library has read/write locks. */
#define HAVE_PTHREAD_RWLOCK 1

/* Define to 1 if the system has the type `ptrdiff_t'. */
#define HAVE_PTRDIFF_T 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strerror_r' function. */
#define HAVE_STRERROR_R 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if the system has the type `uintmax_t'. */
#define HAVE_UINTMAX_T 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if the system has the type 'unsigned long long int'. */
#define HAVE_UNSIGNED_LONG_LONG_INT 1

/* Define to 1 if you have the `vasprintf' function. */
#define HAVE_VASPRINTF 1

/* Defined if we run on WindowsCE */
/* #undef HAVE_W32CE_SYSTEM */

/* Defined if we run on a W32 API based system */
/* #undef HAVE_W32_SYSTEM */

/* Defined if we run on 64 bit W32 API system */
/* #undef HAVE_W64_SYSTEM */

/* The host triplet */
#define HOST_TRIPLET_STRING "x86_64-pc-linux-gnu"

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Name of package */
#define PACKAGE "libgpg-error"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://bugs.gnupg.org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libgpg-error"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libgpg-error 1.27"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libgpg-error"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.27"

/* Define if the pthread_in_use() detection is hard. */
/* #undef PTHREAD_IN_USE_DETECTION_HARD */

/* Used by mkheader to insert the replacement type. */
#define REPLACEMENT_FOR_OFF_T "long"

/* The size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of `long', as computed by sizeof. */
#define SIZEOF_LONG 8

/* The size of `long long', as computed by sizeof. */
#define SIZEOF_LONG_LONG 8

/* The size of `pthread_mutex_t', as computed by sizeof. */
#define SIZEOF_PTHREAD_MUTEX_T 40

/* The size of `time_t', as computed by sizeof. */
#define SIZEOF_TIME_T 8

/* The size of `unsigned long', as computed by sizeof. */
#define SIZEOF_UNSIGNED_LONG 8

/* The size of `void *', as computed by sizeof. */
#define SIZEOF_VOID_P 8

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if strerror_r returns char *. */
#define STRERROR_R_CHAR_P 1

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Define if the POSIX multithreading library can be used. */
#define USE_POSIX_THREADS 1

/* Define if references to the POSIX multithreading library should be made
   weak. */
#define USE_POSIX_THREADS_WEAK 1

/* Define if the old Solaris multithreading library can be used. */
/* #undef USE_SOLARIS_THREADS */

/* Define if references to the old Solaris multithreading library should be
   made weak. */
/* #undef USE_SOLARIS_THREADS_WEAK */

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


/* Define if the native Windows multithreading API can be used. */
/* #undef USE_WINDOWS_THREADS */

/* Version number of package */
#define VERSION "1.27"

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

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

/* Define to the widest signed integer type if <stdint.h> and <inttypes.h> do
   not define. */
/* #undef intmax_t */

/* Define to the widest unsigned integer type if <stdint.h> and <inttypes.h>
   do not define. */
/* #undef uintmax_t */


/* Force using of NLS for W32 even if no libintl has been found.  This is
   okay because we have our own gettext implementation for W32.  */
#if defined(HAVE_W32_SYSTEM) && !defined(ENABLE_NLS)
#define ENABLE_NLS 1
#endif

/* Connect the generic estream-printf.c to our framework.  */
#define _ESTREAM_PRINTF_REALLOC _gpgrt_realloc
#define _ESTREAM_PRINTF_EXTRA_INCLUDE "gpgrt-int.h"

/* For building we need to define these macro.  */
#define GPG_ERR_ENABLE_GETTEXT_MACROS 1
#define GPG_ERR_ENABLE_ERRNO_MACROS 1
#define GPGRT_ENABLE_ES_MACROS 1

