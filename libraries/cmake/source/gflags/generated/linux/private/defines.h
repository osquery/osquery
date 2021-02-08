/* Generated from defines.h.in during build configuration using CMake. */

// Note: This header file is only used internally. It is not part of public interface!
//       Any cmakedefine is defined using the -D flag instead when Bazel is used.
//       For Bazel, this file is thus not used to avoid a private file in $(GENDIR).

#ifndef GFLAGS_DEFINES_H_
#define GFLAGS_DEFINES_H_


// Define if you build this library for a MS Windows OS.
/* #undef OS_WINDOWS */

// Define if you have the <stdint.h> header file.
#define HAVE_STDINT_H

// Define if you have the <sys/types.h> header file.
#define HAVE_SYS_TYPES_H

// Define if you have the <inttypes.h> header file.
#define HAVE_INTTYPES_H

// Define if you have the <sys/stat.h> header file.
#define HAVE_SYS_STAT_H

// Define if you have the <unistd.h> header file.
#define HAVE_UNISTD_H

// Define if you have the <fnmatch.h> header file.
#define HAVE_FNMATCH_H

// Define if you have the <shlwapi.h> header file (Windows 2000/XP).
/* #undef HAVE_SHLWAPI_H */

// Define if you have the strtoll function.
#define HAVE_STRTOLL

// Define if you have the strtoq function.
/* #undef HAVE_STRTOQ */

// Define if you have the <pthread.h> header file.
#define HAVE_PTHREAD

// Define if your pthread library defines the type pthread_rwlock_t
#define HAVE_RWLOCK


#endif // GFLAGS_DEFINES_H_
