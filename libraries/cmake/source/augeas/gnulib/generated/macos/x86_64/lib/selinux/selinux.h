/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* Replacement <selinux/selinux.h> for platforms that lack it.
   Copyright (C) 2008-2019 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

#if __GNUC__ >= 3
#pragma GCC system_header
#endif


#if HAVE_SELINUX_SELINUX_H

#include_next 

#else
# if !defined _GL_SELINUX_SELINUX_H
#  define _GL_SELINUX_SELINUX_H

#  include <sys/types.h>
#  include <errno.h>

#  ifndef _GL_INLINE_HEADER_BEGIN
    #error "Please include config.h first."
#  endif
_GL_INLINE_HEADER_BEGIN
#  ifndef SE_SELINUX_INLINE
#   define SE_SELINUX_INLINE _GL_INLINE
#  endif

/* The definition of _GL_UNUSED_PARAMETER is copied here.  */
/* A C macro for declaring that specific function parameters are not used.
   Copyright (C) 2008-2019 Free Software Foundation, Inc.

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

/* _GL_UNUSED_PARAMETER is a marker that can be appended to function parameter
   declarations for parameters that are not used.  This helps to reduce
   warnings, such as from GCC -Wunused-parameter.  The syntax is as follows:
       type param _GL_UNUSED_PARAMETER
   or more generally
       param_decl _GL_UNUSED_PARAMETER
   For example:
       int param _GL_UNUSED_PARAMETER
       int *(*param)(void) _GL_UNUSED_PARAMETER
   Other possible, but obscure and discouraged syntaxes:
       int _GL_UNUSED_PARAMETER *(*param)(void)
       _GL_UNUSED_PARAMETER int *(*param)(void)
 */
#ifndef _GL_UNUSED_PARAMETER
# if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
#  define _GL_UNUSED_PARAMETER __attribute__ ((__unused__))
# else
#  define _GL_UNUSED_PARAMETER
# endif
#endif

#  if !GNULIB_defined_security_types

typedef unsigned short security_class_t;
typedef char *security_context_t;
#   define is_selinux_enabled() 0

SE_SELINUX_INLINE int
getcon (security_context_t *con _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }
SE_SELINUX_INLINE void
freecon (security_context_t con _GL_UNUSED_PARAMETER) {}

SE_SELINUX_INLINE int
getfscreatecon (security_context_t *con _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }
SE_SELINUX_INLINE int
setfscreatecon (security_context_t con _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }
SE_SELINUX_INLINE int
matchpathcon (char const *file _GL_UNUSED_PARAMETER,
              mode_t m _GL_UNUSED_PARAMETER,
  security_context_t *con _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }
SE_SELINUX_INLINE int
getfilecon (char const *file _GL_UNUSED_PARAMETER,
            security_context_t *con _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }
SE_SELINUX_INLINE int
lgetfilecon (char const *file _GL_UNUSED_PARAMETER,
             security_context_t *con _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }
SE_SELINUX_INLINE int
fgetfilecon (int fd, security_context_t *con _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }
SE_SELINUX_INLINE int
setfilecon (char const *file _GL_UNUSED_PARAMETER,
            security_context_t con _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }
SE_SELINUX_INLINE int
lsetfilecon (char const *file _GL_UNUSED_PARAMETER,
             security_context_t con _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }
SE_SELINUX_INLINE int
fsetfilecon (int fd _GL_UNUSED_PARAMETER,
             security_context_t con _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }

SE_SELINUX_INLINE int
security_check_context (security_context_t con _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }
SE_SELINUX_INLINE int
security_check_context_raw (security_context_t con _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }
SE_SELINUX_INLINE int
setexeccon (security_context_t con _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }
SE_SELINUX_INLINE int
security_compute_create (security_context_t scon _GL_UNUSED_PARAMETER,
                         security_context_t tcon _GL_UNUSED_PARAMETER,
                         security_class_t tclass _GL_UNUSED_PARAMETER,
                         security_context_t *newcon _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }
SE_SELINUX_INLINE security_class_t
string_to_security_class (char const *name)
  { errno = ENOTSUP; return 0; }
SE_SELINUX_INLINE int
matchpathcon_init_prefix (char const *path _GL_UNUSED_PARAMETER,
                          char const *prefix _GL_UNUSED_PARAMETER)
  { errno = ENOTSUP; return -1; }

#   define GNULIB_defined_security_types 1
#  endif

_GL_INLINE_HEADER_END

# endif
#endif
