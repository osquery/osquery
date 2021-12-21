/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* Provide a more complete sys/types.h.

   Copyright (C) 2011-2019 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <https://www.gnu.org/licenses/>.  */

#if __GNUC__ >= 3
#pragma GCC system_header
#endif


#if defined _WIN32 && !defined __CYGWIN__ \
    && (defined __need_off_t || defined __need___off64_t \
        || defined __need_ssize_t || defined __need_time_t)

/* Special invocation convention inside mingw header files.  */

#include_next <sys/types.h>

#else
/* Normal invocation convention.  */

#ifndef _GL_SYS_TYPES_H

/* The include_next requires a split double-inclusion guard.  */
# define _GL_INCLUDING_SYS_TYPES_H
#include_next <sys/types.h>
# undef _GL_INCLUDING_SYS_TYPES_H

#ifndef _GL_SYS_TYPES_H
#define _GL_SYS_TYPES_H

/* Override off_t if Large File Support is requested on native Windows.  */
#if 0
/* Same as int64_t in <stdint.h>.  */
# if defined _MSC_VER
#  define off_t __int64
# else
#  define off_t long long int
# endif
/* Indicator, for gnulib internal purposes.  */
# define _GL_WINDOWS_64_BIT_OFF_T 1
#endif

/* Override dev_t and ino_t if distinguishable inodes support is requested
   on native Windows.  */
#if 0

# if 0 == 2
/* Experimental, not useful in Windows 10.  */

/* Define dev_t to a 64-bit type.  */
#  if !defined GNULIB_defined_dev_t
typedef unsigned long long int rpl_dev_t;
#   undef dev_t
#   define dev_t rpl_dev_t
#   define GNULIB_defined_dev_t 1
#  endif

/* Define ino_t to a 128-bit type.  */
#  if !defined GNULIB_defined_ino_t
/* MSVC does not have a 128-bit integer type.
   GCC has a 128-bit integer type __int128, but only on 64-bit targets.  */
typedef struct { unsigned long long int _gl_ino[2]; } rpl_ino_t;
#   undef ino_t
#   define ino_t rpl_ino_t
#   define GNULIB_defined_ino_t 1
#  endif

# else /* 0 == 1 */

/* Define ino_t to a 64-bit type.  */
#  if !defined GNULIB_defined_ino_t
typedef unsigned long long int rpl_ino_t;
#   undef ino_t
#   define ino_t rpl_ino_t
#   define GNULIB_defined_ino_t 1
#  endif

# endif

/* Indicator, for gnulib internal purposes.  */
# define _GL_WINDOWS_STAT_INODES 0

#endif

/* MSVC 9 defines size_t in <stddef.h>, not in <sys/types.h>.  */
/* But avoid namespace pollution on glibc systems.  */
#if (defined _WIN32 && ! defined __CYGWIN__) && ! defined __GLIBC__
# include <stddef.h>
#endif

#endif /* _GL_SYS_TYPES_H */
#endif /* _GL_SYS_TYPES_H */
#endif /* __need_XXX */
