#ifndef __LIBXML_WIN32_CONFIG__
#define __LIBXML_WIN32_CONFIG__

#define SEND_ARG2_CAST
#define GETHOSTBYNAME_ARG_CAST

#define HAVE_SYS_STAT_H
#define HAVE_STAT
#define HAVE_FCNTL_H

#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER >= 1600)
#define HAVE_STDINT_H
#endif

#if defined(_MSC_VER)
#if _MSC_VER < 1900
#define snprintf _snprintf
#endif
#if _MSC_VER < 1500
#define vsnprintf(b,c,f,a) _vsnprintf(b,c,f,a)
#endif
#endif

#endif /* __LIBXML_WIN32_CONFIG__ */

