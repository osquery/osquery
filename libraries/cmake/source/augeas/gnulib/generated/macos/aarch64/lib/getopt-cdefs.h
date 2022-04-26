/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* getopt-on-non-glibc compatibility macros.
   Copyright (C) 1989-2019 Free Software Foundation, Inc.
   This file is part of gnulib.
   Unlike most of the getopt implementation, it is NOT shared
   with the GNU C Library.

   This file is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with gnulib; if not, see
   <https://www.gnu.org/licenses/>.  */

#ifndef _GETOPT_CDEFS_H
#define _GETOPT_CDEFS_H 1

/* This header should not be used directly; include getopt.h or
   unistd.h instead.  It does not have a protective #error, because
   the guard macro for getopt.h in gnulib is not fixed.  */

/* getopt-core.h and getopt-ext.h are shared with GNU libc, and expect
   a number of the internal macros supplied to GNU libc's headers by
   sys/cdefs.h.  Provide fallback definitions for all of them.  */
#if 1
# include <sys/cdefs.h>
#endif

#ifndef __BEGIN_DECLS
# ifdef __cplusplus
#  define __BEGIN_DECLS extern "C" {
# else
#  define __BEGIN_DECLS /* nothing */
# endif
#endif
#ifndef __END_DECLS
# ifdef __cplusplus
#  define __END_DECLS }
# else
#  define __END_DECLS /* nothing */
# endif
#endif

#ifndef __GNUC_PREREQ
# if defined __GNUC__ && defined __GNUC_VERSION__
# define __GNUC_PREREQ(maj, min) \
        ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
# else
#  define __GNUC_PREREQ(maj, min) 0
# endif
#endif

#ifndef __THROW
# if defined __cplusplus && __GNUC_PREREQ (2,8)
#  define __THROW       throw ()
# else
#  define __THROW
# endif
#endif

#endif /* _GETOPT_CDEFS_H */
