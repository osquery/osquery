/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* Declarations for getopt.
   Copyright (C) 1989-2019 Free Software Foundation, Inc.
   This file is part of gnulib.
   Unlike most of the getopt implementation, it is NOT shared
   with the GNU C Library, which supplies a different version of
   this file.

   This file is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with gnulib; if not, see <https://www.gnu.org/licenses/>.  */

#ifndef _GL_GETOPT_H

#if __GNUC__ >= 3
#pragma GCC system_header
#endif


/* The include_next requires a split double-inclusion guard.  We must
   also inform the replacement unistd.h to not recursively use
   <getopt.h>; our definitions will be present soon enough.  */
#if 1
# define _GL_SYSTEM_GETOPT
# include_next <getopt.h>
# undef _GL_SYSTEM_GETOPT
#endif

#define _GL_GETOPT_H 1

/* Standalone applications should #define __GETOPT_PREFIX to an
   identifier that prefixes the external functions and variables
   defined in getopt-core.h and getopt-ext.h.  When this happens,
   include the headers that might declare getopt so that they will not
   cause confusion if included after this file (if the system had
   <getopt.h>, we have already included it).  */
#if defined __GETOPT_PREFIX
# if !1
#  define __need_system_stdlib_h
#  include <stdlib.h>
#  undef __need_system_stdlib_h
#  include <stdio.h>
#  include <unistd.h>
# endif
#endif

/* The definition of _GL_ARG_NONNULL is copied here.  */
/* A C macro for declaring that specific arguments must not be NULL.
   Copyright (C) 2009-2019 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as published
   by the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* _GL_ARG_NONNULL((n,...,m)) tells the compiler and static analyzer tools
   that the values passed as arguments n, ..., m must be non-NULL pointers.
   n = 1 stands for the first argument, n = 2 for the second argument etc.  */
#ifndef _GL_ARG_NONNULL
# if (__GNUC__ == 3 && __GNUC_MINOR__ >= 3) || __GNUC__ > 3
#  define _GL_ARG_NONNULL(params) __attribute__ ((__nonnull__ params))
# else
#  define _GL_ARG_NONNULL(params)
# endif
#endif

#include <getopt-cdefs.h>
#include <getopt-pfx-core.h>
#include <getopt-pfx-ext.h>

#endif /* _GL_GETOPT_H */
