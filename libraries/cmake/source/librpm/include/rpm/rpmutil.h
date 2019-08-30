#ifndef _RPMUTIL_H
#define _RPMUTIL_H

#include <unistd.h>

/** \file rpmio/rpmutil.h
 *
 * Miscellaneous utility macros:
 * - portability wrappers for various gcc extensions like __attribute__()
 * - ...
 *
 * Copied from glib, names replaced to avoid clashing with glib.
 *
 */

/* Here we provide RPM_GNUC_EXTENSION as an alias for __extension__,
 * where this is valid. This allows for warningless compilation of
 * "long long" types even in the presence of '-ansi -pedantic'. 
 */
#if     __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 8)
#  define RPM_GNUC_EXTENSION __extension__
#else
#  define RPM_GNUC_EXTENSION
#endif

/* Provide macros to feature the GCC function attribute.
 */
#if    __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 96)
#define RPM_GNUC_PURE                            \
  __attribute__((__pure__))
#define RPM_GNUC_MALLOC    			\
  __attribute__((__malloc__))
#else
#define RPM_GNUC_PURE
#define RPM_GNUC_MALLOC
#endif

#if     (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
#define RPM_GNUC_ALLOC_SIZE(x) __attribute__((__alloc_size__(x)))
#define RPM_GNUC_ALLOC_SIZE2(x,y) __attribute__((__alloc_size__(x,y)))
#else
#define RPM_GNUC_ALLOC_SIZE(x)
#define RPM_GNUC_ALLOC_SIZE2(x,y)
#endif

#if     __GNUC__ >= 4
#define RPM_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#else
#define RPM_GNUC_NULL_TERMINATED
#endif

#if     __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
#define RPM_GNUC_PRINTF( format_idx, arg_idx )    \
  __attribute__((__format__ (__printf__, format_idx, arg_idx)))
#define RPM_GNUC_SCANF( format_idx, arg_idx )     \
  __attribute__((__format__ (__scanf__, format_idx, arg_idx)))
#define RPM_GNUC_FORMAT( arg_idx )                \
  __attribute__((__format_arg__ (arg_idx)))
#define RPM_GNUC_NORETURN                         \
  __attribute__((__noreturn__))
#define RPM_GNUC_CONST                            \
  __attribute__((__const__))
#define RPM_GNUC_UNUSED                           \
  __attribute__((__unused__))
#define RPM_GNUC_NO_INSTRUMENT			\
  __attribute__((__no_instrument_function__))
#else   /* !__GNUC__ */
#define RPM_GNUC_PRINTF( format_idx, arg_idx )
#define RPM_GNUC_SCANF( format_idx, arg_idx )
#define RPM_GNUC_FORMAT( arg_idx )
#define RPM_GNUC_NORETURN
#define RPM_GNUC_CONST
#define RPM_GNUC_UNUSED
#define RPM_GNUC_NO_INSTRUMENT
#endif  /* !__GNUC__ */

#if    __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
#define RPM_GNUC_DEPRECATED                            \
  __attribute__((__deprecated__))
#else
#define RPM_GNUC_DEPRECATED
#endif /* __GNUC__ */

#if     __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3)
#define RPM_GNUC_MAY_ALIAS __attribute__((may_alias))
#define RPM_GNUC_NONNULL( ... )	\
  __attribute__((__nonnull__ (__VA_ARGS__)))
#else
#define RPM_GNUC_MAY_ALIAS
#define RPM_GNUC_NONNULL( ... )
#endif

#if    __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
#define RPM_GNUC_WARN_UNUSED_RESULT 		\
  __attribute__((warn_unused_result))
#else
#define RPM_GNUC_WARN_UNUSED_RESULT
#endif /* __GNUC__ */

#if    __GNUC__ >= 4 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3)
#  define RPM_GNUC_INTERNAL __attribute__((visibility("hidden")))
#else
#  define RPM_GNUC_INTERNAL
#endif


/* Guard C code in headers, while including them from C++ */
#ifdef  __cplusplus
# define RPM_BEGIN_DECLS  extern "C" {
# define RPM_END_DECLS    }
#else
# define RPM_BEGIN_DECLS
# define RPM_END_DECLS
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Rpm specific allocators which never return NULL but terminate on failure */
RPM_GNUC_MALLOC RPM_GNUC_ALLOC_SIZE(1)
void * rmalloc(size_t size);

RPM_GNUC_MALLOC RPM_GNUC_ALLOC_SIZE2(1,2)
void * rcalloc(size_t nmemb, size_t size);

RPM_GNUC_ALLOC_SIZE(2)
void * rrealloc(void *ptr, size_t size);

char * rstrdup(const char *str);

/* Rpm specific free() which returns NULL */
void * rfree(void *ptr);

/** \ingroup rpmutil
 * Memory allocation failure callback prototype. When registered through
 * rpmSetMemFail(), this gets called if memory allocation through rmalloc()
 * and friends fails. If the application can somehow recover memory here,
 * it can return a newly allocated memory block of requested size, otherwise
 * it must return NULL after performing it's own shutdown deeds or 
 * terminate itself.
 * @param size		Size of allocation request in bytes
 * @param data		User data (or NULL)
 * @return		Allocated memory block of requested size or NULL
 */
typedef void * (*rpmMemFailFunc) (size_t size, void *data);

/** \ingroup rpmutil
 * Set memory allocation failure callback.
 * @param func		Allocation failure callback function
 * @param data		User data (or NULL)
 * @return		Previous callback function
 */
rpmMemFailFunc rpmSetMemFail(rpmMemFailFunc func, void *data);

#ifdef __cplusplus
}
#endif

#endif /* _RPMUTIL_H */
