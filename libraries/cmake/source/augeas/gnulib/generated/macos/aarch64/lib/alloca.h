/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* Memory allocation on the stack.

   Copyright (C) 1995, 1999, 2001-2004, 2006-2019 Free Software Foundation,
   Inc.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as published
   by the Free Software Foundation; either version 2.1, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see
   <https://www.gnu.org/licenses/>.
  */

/* Avoid using the symbol _ALLOCA_H here, as Bison assumes _ALLOCA_H
   means there is a real alloca function.  */
#ifndef _GL_ALLOCA_H
#define _GL_ALLOCA_H

/* alloca (N) returns a pointer to N bytes of memory
   allocated on the stack, which will last until the function returns.
   Use of alloca should be avoided:
     - inside arguments of function calls - undefined behaviour,
     - in inline functions - the allocation may actually last until the
       calling function returns,
     - for huge N (say, N >= 65536) - you never know how large (or small)
       the stack is, and when the stack cannot fulfill the memory allocation
       request, the program just crashes.
 */

#ifndef alloca
# ifdef __GNUC__
   /* Some version of mingw have an <alloca.h> that causes trouble when
      included after 'alloca' gets defined as a macro.  As a workaround, include
      this <alloca.h> first and define 'alloca' as a macro afterwards.  */
#  if (defined _WIN32 && ! defined __CYGWIN__) && 1
#   include_next <alloca.h>
#  endif
#  define alloca __builtin_alloca
# elif defined _AIX
#  define alloca __alloca
# elif defined _MSC_VER
#  include <malloc.h>
#  define alloca _alloca
# elif defined __DECC && defined __VMS
#  define alloca __ALLOCA
# elif defined __TANDEM && defined _TNS_E_TARGET
#  ifdef  __cplusplus
extern "C"
#  endif
void *_alloca (unsigned short);
#  pragma intrinsic (_alloca)
#  define alloca _alloca
# elif defined __MVS__
#  include <stdlib.h>
# else
#  include <stddef.h>
#  ifdef  __cplusplus
extern "C"
#  endif
void *alloca (size_t);
# endif
#endif

#endif /* _GL_ALLOCA_H */
