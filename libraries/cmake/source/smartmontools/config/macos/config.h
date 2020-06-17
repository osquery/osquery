/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* freebsd ciss header location */
#define CISS_LOCATION "cissio_freebsd.h"

/* smartmontools CVS Tag */
#define CONFIG_H_CVSID "$Id$"

/* Define to 1 if C++ compiler supports __attribute__((packed)) */
#define HAVE_ATTR_PACKED 1

/* Define to 1 if you have the `clock_gettime' function. */
#define HAVE_CLOCK_GETTIME 1

/* Define to 1 if you have the <ddk/ntdddisk.h> header file. */
/* #undef HAVE_DDK_NTDDDISK_H */

/* Define to 1 if you have the <dev/ata/atavar.h> header file. */
/* #undef HAVE_DEV_ATA_ATAVAR_H */

/* Define to 1 if you have the <dev/ciss/cissio.h> header file. */
/* #undef HAVE_DEV_CISS_CISSIO_H */

/* Define to 1 if you have the `ftime' function. */
#define HAVE_FTIME 1

/* Define to 1 if you have the `getopt_long' function. */
#define HAVE_GETOPT_LONG 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if the system has the type `int64_t'. */
#define HAVE_INT64_T 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `cap-ng' library (-lcap-ng). */
/* #undef HAVE_LIBCAP_NG */

/* Define to 1 if you have the `selinux' library (-lselinux). */
/* #undef HAVE_LIBSELINUX */

/* Define to 1 if you have the `usb' library (-lusb). */
/* #undef HAVE_LIBUSB */

/* Define to 1 if you have the <linux/cciss_ioctl.h> header file. */
/* #undef HAVE_LINUX_CCISS_IOCTL_H */

/* Define to 1 if you have the <linux/compiler.h> header file. */
/* #undef HAVE_LINUX_COMPILER_H */

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <ntdddisk.h> header file. */
/* #undef HAVE_NTDDDISK_H */

/* Define to 1 if you have the `regcomp' function. */
#define HAVE_REGCOMP 1

/* Define to 1 if you have the <selinux/selinux.h> header file. */
/* #undef HAVE_SELINUX_SELINUX_H */

/* Define to 1 if you have the `sigset' function. */
#define HAVE_SIGSET 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strtoull' function. */
#define HAVE_STRTOULL 1

/* Define to 1 if you have the <sys/inttypes.h> header file. */
/* #undef HAVE_SYS_INTTYPES_H */

/* Define to 1 if you have the <sys/int_types.h> header file. */
/* #undef HAVE_SYS_INT_TYPES_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/tweio.h> header file. */
/* #undef HAVE_SYS_TWEIO_H */

/* Define to 1 if you have the <sys/twereg.h> header file. */
/* #undef HAVE_SYS_TWEREG_H */

/* Define to 1 if you have the <sys/tw_osl_ioctl.h> header file. */
/* #undef HAVE_SYS_TW_OSL_IOCTL_H */

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if the system has the type `uint64_t'. */
#define HAVE_UINT64_T 1

/* Define to 1 if you have the `uname' function. */
#define HAVE_UNAME 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the <wbemcli.h> header file. */
/* #undef HAVE_WBEMCLI_H */

/* Define to 1 if the `snprintf' function is sane. */
#define HAVE_WORKING_SNPRINTF 1

/* Define to 1 if os_*.cpp still uses the old interface */
/* #undef OLD_INTERFACE */

/* Name of package */
#define PACKAGE "smartmontools"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "smartmontools-support@listi.jpberlin.de"

/* smartmontools Home Page */
#define PACKAGE_HOMEPAGE "http://www.smartmontools.org/"

/* Define to the full name of this package. */
#define PACKAGE_NAME "smartmontools"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "smartmontools 6.6"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "smartmontools"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "6.6"

/* smartmontools Build Host */
#define SMARTMONTOOLS_BUILD_HOST "x86_64-apple-darwin19.4.0"

/* smartmontools Configure Arguments */
#define SMARTMONTOOLS_CONFIGURE_ARGS ""

/* smartmontools Release Date */
#define SMARTMONTOOLS_RELEASE_DATE "2017-11-05"

/* smartmontools Release Time */
#define SMARTMONTOOLS_RELEASE_TIME "15:20:58 UTC"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION "6.6"

/* Define to 1 to include NVMe devices in smartd DEVICESCAN. */
/* #undef WITH_NVME_DEVICESCAN */

/* Define to 1 if SELinux support is enabled */
/* #undef WITH_SELINUX */

/* Define to 1 to enable legacy ATA support on Solaris SPARC. */
/* #undef WITH_SOLARIS_SPARC_ATA */

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
