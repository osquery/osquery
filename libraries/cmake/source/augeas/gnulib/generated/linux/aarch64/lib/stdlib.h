/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* A GNU-like <stdlib.h>.

   Copyright (C) 1995, 2001-2004, 2006-2019 Free Software Foundation, Inc.

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


#if defined __need_system_stdlib_h || defined __need_malloc_and_calloc
/* Special invocation conventions inside some gnulib header files,
   and inside some glibc header files, respectively.  */

#include_next <stdlib.h>

#else
/* Normal invocation convention.  */

#ifndef _GL_STDLIB_H

/* The include_next requires a split double-inclusion guard.  */
#include_next <stdlib.h>

#ifndef _GL_STDLIB_H
#define _GL_STDLIB_H

/* NetBSD 5.0 mis-defines NULL.  */
#include <stddef.h>

/* MirBSD 10 defines WEXITSTATUS in <sys/wait.h>, not in <stdlib.h>.  */
#if 0 && !defined WEXITSTATUS
# include <sys/wait.h>
#endif

/* Solaris declares getloadavg() in <sys/loadavg.h>.  */
#if (0 || defined GNULIB_POSIXCHECK) && 0
/* OpenIndiana has a bug: <sys/time.h> must be included before
   <sys/loadavg.h>.  */
# include <sys/time.h>
# include <sys/loadavg.h>
#endif

/* Native Windows platforms declare mktemp() in <io.h>.  */
#if 0 && (defined _WIN32 && ! defined __CYGWIN__)
# include <io.h>
#endif

#if 0

/* OSF/1 5.1 declares 'struct random_data' in <random.h>, which is included
   from <stdlib.h> if _REENTRANT is defined.  Include it whenever we need
   'struct random_data'.  */
# if 1
#  include <random.h>
# endif

# if !1 || 0 || !1
#  include <stdint.h>
# endif

# if !1
/* Define 'struct random_data'.
   But allow multiple gnulib generated <stdlib.h> replacements to coexist.  */
#  if !GNULIB_defined_struct_random_data
struct random_data
{
  int32_t *fptr;                /* Front pointer.  */
  int32_t *rptr;                /* Rear pointer.  */
  int32_t *state;               /* Array of state values.  */
  int rand_type;                /* Type of random number generator.  */
  int rand_deg;                 /* Degree of random number generator.  */
  int rand_sep;                 /* Distance between front and rear.  */
  int32_t *end_ptr;             /* Pointer behind state table.  */
};
#   define GNULIB_defined_struct_random_data 1
#  endif
# endif
#endif

#if (1 || 0 || 0 || 0 || 0 || defined GNULIB_POSIXCHECK) && ! defined __GLIBC__ && !(defined _WIN32 && ! defined __CYGWIN__)
/* On Mac OS X 10.3, only <unistd.h> declares mkstemp.  */
/* On Mac OS X 10.5, only <unistd.h> declares mkstemps.  */
/* On Mac OS X 10.13, only <unistd.h> declares mkostemp and mkostemps.  */
/* On Cygwin 1.7.1, only <unistd.h> declares getsubopt.  */
/* But avoid namespace pollution on glibc systems and native Windows.  */
# include <unistd.h>
#endif

/* The __attribute__ feature is available in gcc versions 2.5 and later.
   The attribute __pure__ was added in gcc 2.96.  */
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 96)
# define _GL_ATTRIBUTE_PURE __attribute__ ((__pure__))
#else
# define _GL_ATTRIBUTE_PURE /* empty */
#endif

/* The definition of _Noreturn is copied here.  */
/* A C macro for declaring that a function does not return.
   Copyright (C) 2011-2019 Free Software Foundation, Inc.

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

#ifndef _Noreturn
# if (defined __cplusplus \
      && ((201103 <= __cplusplus && !(__GNUC__ == 4 && __GNUC_MINOR__ == 7)) \
          || (defined _MSC_VER && 1900 <= _MSC_VER)))
#  define _Noreturn [[noreturn]]
# elif ((!defined __cplusplus || defined __clang__)                     \
        && (201112 <= (defined __STDC_VERSION__ ? __STDC_VERSION__ : 0)  \
            || 4 < __GNUC__ + (7 <= __GNUC_MINOR__)))
   /* _Noreturn works as-is.  */
# elif 2 < __GNUC__ + (8 <= __GNUC_MINOR__) || 0x5110 <= __SUNPRO_C
#  define _Noreturn __attribute__ ((__noreturn__))
# elif 1200 <= (defined _MSC_VER ? _MSC_VER : 0)
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn
# endif
#endif

/* The definitions of _GL_FUNCDECL_RPL etc. are copied here.  */
/* C++ compatible function declaration macros.
   Copyright (C) 2010-2019 Free Software Foundation, Inc.

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

#ifndef _GL_CXXDEFS_H
#define _GL_CXXDEFS_H

/* Begin/end the GNULIB_NAMESPACE namespace.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_BEGIN_NAMESPACE namespace GNULIB_NAMESPACE {
# define _GL_END_NAMESPACE }
#else
# define _GL_BEGIN_NAMESPACE
# define _GL_END_NAMESPACE
#endif

/* The three most frequent use cases of these macros are:

   * For providing a substitute for a function that is missing on some
     platforms, but is declared and works fine on the platforms on which
     it exists:

       #if @GNULIB_FOO@
       # if !@HAVE_FOO@
       _GL_FUNCDECL_SYS (foo, ...);
       # endif
       _GL_CXXALIAS_SYS (foo, ...);
       _GL_CXXALIASWARN (foo);
       #elif defined GNULIB_POSIXCHECK
       ...
       #endif

   * For providing a replacement for a function that exists on all platforms,
     but is broken/insufficient and needs to be replaced on some platforms:

       #if @GNULIB_FOO@
       # if @REPLACE_FOO@
       #  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
       #   undef foo
       #   define foo rpl_foo
       #  endif
       _GL_FUNCDECL_RPL (foo, ...);
       _GL_CXXALIAS_RPL (foo, ...);
       # else
       _GL_CXXALIAS_SYS (foo, ...);
       # endif
       _GL_CXXALIASWARN (foo);
       #elif defined GNULIB_POSIXCHECK
       ...
       #endif

   * For providing a replacement for a function that exists on some platforms
     but is broken/insufficient and needs to be replaced on some of them and
     is additionally either missing or undeclared on some other platforms:

       #if @GNULIB_FOO@
       # if @REPLACE_FOO@
       #  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
       #   undef foo
       #   define foo rpl_foo
       #  endif
       _GL_FUNCDECL_RPL (foo, ...);
       _GL_CXXALIAS_RPL (foo, ...);
       # else
       #  if !@HAVE_FOO@   or   if !@HAVE_DECL_FOO@
       _GL_FUNCDECL_SYS (foo, ...);
       #  endif
       _GL_CXXALIAS_SYS (foo, ...);
       # endif
       _GL_CXXALIASWARN (foo);
       #elif defined GNULIB_POSIXCHECK
       ...
       #endif
*/

/* _GL_EXTERN_C declaration;
   performs the declaration with C linkage.  */
#if defined __cplusplus
# define _GL_EXTERN_C extern "C"
#else
# define _GL_EXTERN_C extern
#endif

/* _GL_FUNCDECL_RPL (func, rettype, parameters_and_attributes);
   declares a replacement function, named rpl_func, with the given prototype,
   consisting of return type, parameters, and attributes.
   Example:
     _GL_FUNCDECL_RPL (open, int, (const char *filename, int flags, ...)
                                  _GL_ARG_NONNULL ((1)));
 */
#define _GL_FUNCDECL_RPL(func,rettype,parameters_and_attributes) \
  _GL_FUNCDECL_RPL_1 (rpl_##func, rettype, parameters_and_attributes)
#define _GL_FUNCDECL_RPL_1(rpl_func,rettype,parameters_and_attributes) \
  _GL_EXTERN_C rettype rpl_func parameters_and_attributes

/* _GL_FUNCDECL_SYS (func, rettype, parameters_and_attributes);
   declares the system function, named func, with the given prototype,
   consisting of return type, parameters, and attributes.
   Example:
     _GL_FUNCDECL_SYS (open, int, (const char *filename, int flags, ...)
                                  _GL_ARG_NONNULL ((1)));
 */
#define _GL_FUNCDECL_SYS(func,rettype,parameters_and_attributes) \
  _GL_EXTERN_C rettype func parameters_and_attributes

/* _GL_CXXALIAS_RPL (func, rettype, parameters);
   declares a C++ alias called GNULIB_NAMESPACE::func
   that redirects to rpl_func, if GNULIB_NAMESPACE is defined.
   Example:
     _GL_CXXALIAS_RPL (open, int, (const char *filename, int flags, ...));

   Wrapping rpl_func in an object with an inline conversion operator
   avoids a reference to rpl_func unless GNULIB_NAMESPACE::func is
   actually used in the program.  */
#define _GL_CXXALIAS_RPL(func,rettype,parameters) \
  _GL_CXXALIAS_RPL_1 (func, rpl_##func, rettype, parameters)
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_CXXALIAS_RPL_1(func,rpl_func,rettype,parameters) \
    namespace GNULIB_NAMESPACE                                \
    {                                                         \
      static const struct _gl_ ## func ## _wrapper            \
      {                                                       \
        typedef rettype (*type) parameters;                   \
                                                              \
        inline operator type () const                         \
        {                                                     \
          return ::rpl_func;                                  \
        }                                                     \
      } func = {};                                            \
    }                                                         \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#else
# define _GL_CXXALIAS_RPL_1(func,rpl_func,rettype,parameters) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

/* _GL_CXXALIAS_RPL_CAST_1 (func, rpl_func, rettype, parameters);
   is like  _GL_CXXALIAS_RPL_1 (func, rpl_func, rettype, parameters);
   except that the C function rpl_func may have a slightly different
   declaration.  A cast is used to silence the "invalid conversion" error
   that would otherwise occur.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_CXXALIAS_RPL_CAST_1(func,rpl_func,rettype,parameters) \
    namespace GNULIB_NAMESPACE                                     \
    {                                                              \
      static const struct _gl_ ## func ## _wrapper                 \
      {                                                            \
        typedef rettype (*type) parameters;                        \
                                                                   \
        inline operator type () const                              \
        {                                                          \
          return reinterpret_cast<type>(::rpl_func);               \
        }                                                          \
      } func = {};                                                 \
    }                                                              \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#else
# define _GL_CXXALIAS_RPL_CAST_1(func,rpl_func,rettype,parameters) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

/* _GL_CXXALIAS_SYS (func, rettype, parameters);
   declares a C++ alias called GNULIB_NAMESPACE::func
   that redirects to the system provided function func, if GNULIB_NAMESPACE
   is defined.
   Example:
     _GL_CXXALIAS_SYS (open, int, (const char *filename, int flags, ...));

   Wrapping func in an object with an inline conversion operator
   avoids a reference to func unless GNULIB_NAMESPACE::func is
   actually used in the program.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_CXXALIAS_SYS(func,rettype,parameters)            \
    namespace GNULIB_NAMESPACE                                \
    {                                                         \
      static const struct _gl_ ## func ## _wrapper            \
      {                                                       \
        typedef rettype (*type) parameters;                   \
                                                              \
        inline operator type () const                         \
        {                                                     \
          return ::func;                                      \
        }                                                     \
      } func = {};                                            \
    }                                                         \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#else
# define _GL_CXXALIAS_SYS(func,rettype,parameters) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

/* _GL_CXXALIAS_SYS_CAST (func, rettype, parameters);
   is like  _GL_CXXALIAS_SYS (func, rettype, parameters);
   except that the C function func may have a slightly different declaration.
   A cast is used to silence the "invalid conversion" error that would
   otherwise occur.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_CXXALIAS_SYS_CAST(func,rettype,parameters) \
    namespace GNULIB_NAMESPACE                          \
    {                                                   \
      static const struct _gl_ ## func ## _wrapper      \
      {                                                 \
        typedef rettype (*type) parameters;             \
                                                        \
        inline operator type () const                   \
        {                                               \
          return reinterpret_cast<type>(::func);        \
        }                                               \
      } func = {};                                      \
    }                                                   \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#else
# define _GL_CXXALIAS_SYS_CAST(func,rettype,parameters) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

/* _GL_CXXALIAS_SYS_CAST2 (func, rettype, parameters, rettype2, parameters2);
   is like  _GL_CXXALIAS_SYS (func, rettype, parameters);
   except that the C function is picked among a set of overloaded functions,
   namely the one with rettype2 and parameters2.  Two consecutive casts
   are used to silence the "cannot find a match" and "invalid conversion"
   errors that would otherwise occur.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
  /* The outer cast must be a reinterpret_cast.
     The inner cast: When the function is defined as a set of overloaded
     functions, it works as a static_cast<>, choosing the designated variant.
     When the function is defined as a single variant, it works as a
     reinterpret_cast<>. The parenthesized cast syntax works both ways.  */
# define _GL_CXXALIAS_SYS_CAST2(func,rettype,parameters,rettype2,parameters2) \
    namespace GNULIB_NAMESPACE                                                \
    {                                                                         \
      static const struct _gl_ ## func ## _wrapper                            \
      {                                                                       \
        typedef rettype (*type) parameters;                                   \
                                                                              \
        inline operator type () const                                         \
        {                                                                     \
          return reinterpret_cast<type>((rettype2 (*) parameters2)(::func));  \
        }                                                                     \
      } func = {};                                                            \
    }                                                                         \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#else
# define _GL_CXXALIAS_SYS_CAST2(func,rettype,parameters,rettype2,parameters2) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

/* _GL_CXXALIASWARN (func);
   causes a warning to be emitted when ::func is used but not when
   GNULIB_NAMESPACE::func is used.  func must be defined without overloaded
   variants.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_CXXALIASWARN(func) \
   _GL_CXXALIASWARN_1 (func, GNULIB_NAMESPACE)
# define _GL_CXXALIASWARN_1(func,namespace) \
   _GL_CXXALIASWARN_2 (func, namespace)
/* To work around GCC bug <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=43881>,
   we enable the warning only when not optimizing.  */
# if !__OPTIMIZE__
#  define _GL_CXXALIASWARN_2(func,namespace) \
    _GL_WARN_ON_USE (func, \
                     "The symbol ::" #func " refers to the system function. " \
                     "Use " #namespace "::" #func " instead.")
# elif __GNUC__ >= 3 && GNULIB_STRICT_CHECKING
#  define _GL_CXXALIASWARN_2(func,namespace) \
     extern __typeof__ (func) func
# else
#  define _GL_CXXALIASWARN_2(func,namespace) \
     _GL_EXTERN_C int _gl_cxxalias_dummy
# endif
#else
# define _GL_CXXALIASWARN(func) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

/* _GL_CXXALIASWARN1 (func, rettype, parameters_and_attributes);
   causes a warning to be emitted when the given overloaded variant of ::func
   is used but not when GNULIB_NAMESPACE::func is used.  */
#if defined __cplusplus && defined GNULIB_NAMESPACE
# define _GL_CXXALIASWARN1(func,rettype,parameters_and_attributes) \
   _GL_CXXALIASWARN1_1 (func, rettype, parameters_and_attributes, \
                        GNULIB_NAMESPACE)
# define _GL_CXXALIASWARN1_1(func,rettype,parameters_and_attributes,namespace) \
   _GL_CXXALIASWARN1_2 (func, rettype, parameters_and_attributes, namespace)
/* To work around GCC bug <https://gcc.gnu.org/bugzilla/show_bug.cgi?id=43881>,
   we enable the warning only when not optimizing.  */
# if !__OPTIMIZE__
#  define _GL_CXXALIASWARN1_2(func,rettype,parameters_and_attributes,namespace) \
    _GL_WARN_ON_USE_CXX (func, rettype, parameters_and_attributes, \
                         "The symbol ::" #func " refers to the system function. " \
                         "Use " #namespace "::" #func " instead.")
# elif __GNUC__ >= 3 && GNULIB_STRICT_CHECKING
#  define _GL_CXXALIASWARN1_2(func,rettype,parameters_and_attributes,namespace) \
     extern __typeof__ (func) func
# else
#  define _GL_CXXALIASWARN1_2(func,rettype,parameters_and_attributes,namespace) \
     _GL_EXTERN_C int _gl_cxxalias_dummy
# endif
#else
# define _GL_CXXALIASWARN1(func,rettype,parameters_and_attributes) \
    _GL_EXTERN_C int _gl_cxxalias_dummy
#endif

#endif /* _GL_CXXDEFS_H */

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

/* The definition of _GL_WARN_ON_USE is copied here.  */
/* A C macro for emitting warnings if a function is used.
   Copyright (C) 2010-2019 Free Software Foundation, Inc.

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

/* _GL_WARN_ON_USE (function, "literal string") issues a declaration
   for FUNCTION which will then trigger a compiler warning containing
   the text of "literal string" anywhere that function is called, if
   supported by the compiler.  If the compiler does not support this
   feature, the macro expands to an unused extern declaration.

   _GL_WARN_ON_USE_ATTRIBUTE ("literal string") expands to the
   attribute used in _GL_WARN_ON_USE.  If the compiler does not support
   this feature, it expands to empty.

   These macros are useful for marking a function as a potential
   portability trap, with the intent that "literal string" include
   instructions on the replacement function that should be used
   instead.
   _GL_WARN_ON_USE is for functions with 'extern' linkage.
   _GL_WARN_ON_USE_ATTRIBUTE is for functions with 'static' or 'inline'
   linkage.

   However, one of the reasons that a function is a portability trap is
   if it has the wrong signature.  Declaring FUNCTION with a different
   signature in C is a compilation error, so this macro must use the
   same type as any existing declaration so that programs that avoid
   the problematic FUNCTION do not fail to compile merely because they
   included a header that poisoned the function.  But this implies that
   _GL_WARN_ON_USE is only safe to use if FUNCTION is known to already
   have a declaration.  Use of this macro implies that there must not
   be any other macro hiding the declaration of FUNCTION; but
   undefining FUNCTION first is part of the poisoning process anyway
   (although for symbols that are provided only via a macro, the result
   is a compilation error rather than a warning containing
   "literal string").  Also note that in C++, it is only safe to use if
   FUNCTION has no overloads.

   For an example, it is possible to poison 'getline' by:
   - adding a call to gl_WARN_ON_USE_PREPARE([[#include <stdio.h>]],
     [getline]) in configure.ac, which potentially defines
     HAVE_RAW_DECL_GETLINE
   - adding this code to a header that wraps the system <stdio.h>:
     #undef getline
     #if HAVE_RAW_DECL_GETLINE
     _GL_WARN_ON_USE (getline, "getline is required by POSIX 2008, but"
       "not universally present; use the gnulib module getline");
     #endif

   It is not possible to directly poison global variables.  But it is
   possible to write a wrapper accessor function, and poison that
   (less common usage, like &environ, will cause a compilation error
   rather than issue the nice warning, but the end result of informing
   the developer about their portability problem is still achieved):
     #if HAVE_RAW_DECL_ENVIRON
     static char ***
     rpl_environ (void) { return &environ; }
     _GL_WARN_ON_USE (rpl_environ, "environ is not always properly declared");
     # undef environ
     # define environ (*rpl_environ ())
     #endif
   or better (avoiding contradictory use of 'static' and 'extern'):
     #if HAVE_RAW_DECL_ENVIRON
     static char ***
     _GL_WARN_ON_USE_ATTRIBUTE ("environ is not always properly declared")
     rpl_environ (void) { return &environ; }
     # undef environ
     # define environ (*rpl_environ ())
     #endif
   */
#ifndef _GL_WARN_ON_USE

# if 4 < __GNUC__ || (__GNUC__ == 4 && 3 <= __GNUC_MINOR__)
/* A compiler attribute is available in gcc versions 4.3.0 and later.  */
#  define _GL_WARN_ON_USE(function, message) \
extern __typeof__ (function) function __attribute__ ((__warning__ (message)))
#  define _GL_WARN_ON_USE_ATTRIBUTE(message) \
  __attribute__ ((__warning__ (message)))
# elif __GNUC__ >= 3 && GNULIB_STRICT_CHECKING
/* Verify the existence of the function.  */
#  define _GL_WARN_ON_USE(function, message) \
extern __typeof__ (function) function
#  define _GL_WARN_ON_USE_ATTRIBUTE(message)
# else /* Unsupported.  */
#  define _GL_WARN_ON_USE(function, message) \
_GL_WARN_EXTERN_C int _gl_warn_on_use
#  define _GL_WARN_ON_USE_ATTRIBUTE(message)
# endif
#endif

/* _GL_WARN_ON_USE_CXX (function, rettype, parameters_and_attributes, "string")
   is like _GL_WARN_ON_USE (function, "string"), except that the function is
   declared with the given prototype, consisting of return type, parameters,
   and attributes.
   This variant is useful for overloaded functions in C++. _GL_WARN_ON_USE does
   not work in this case.  */
#ifndef _GL_WARN_ON_USE_CXX
# if 4 < __GNUC__ || (__GNUC__ == 4 && 3 <= __GNUC_MINOR__)
#  define _GL_WARN_ON_USE_CXX(function,rettype,parameters_and_attributes,msg) \
extern rettype function parameters_and_attributes \
     __attribute__ ((__warning__ (msg)))
# elif __GNUC__ >= 3 && GNULIB_STRICT_CHECKING
/* Verify the existence of the function.  */
#  define _GL_WARN_ON_USE_CXX(function,rettype,parameters_and_attributes,msg) \
extern rettype function parameters_and_attributes
# else /* Unsupported.  */
#  define _GL_WARN_ON_USE_CXX(function,rettype,parameters_and_attributes,msg) \
_GL_WARN_EXTERN_C int _gl_warn_on_use
# endif
#endif

/* _GL_WARN_EXTERN_C declaration;
   performs the declaration with C linkage.  */
#ifndef _GL_WARN_EXTERN_C
# if defined __cplusplus
#  define _GL_WARN_EXTERN_C extern "C"
# else
#  define _GL_WARN_EXTERN_C extern
# endif
#endif


/* Some systems do not define EXIT_*, despite otherwise supporting C89.  */
#ifndef EXIT_SUCCESS
# define EXIT_SUCCESS 0
#endif
/* Tandem/NSK and other platforms that define EXIT_FAILURE as -1 interfere
   with proper operation of xargs.  */
#ifndef EXIT_FAILURE
# define EXIT_FAILURE 1
#elif EXIT_FAILURE != 1
# undef EXIT_FAILURE
# define EXIT_FAILURE 1
#endif


#if 0
/* Terminate the current process with the given return code, without running
   the 'atexit' handlers.  */
# if !1
_GL_FUNCDECL_SYS (_Exit, _Noreturn void, (int status));
# endif
_GL_CXXALIAS_SYS (_Exit, void, (int status));
_GL_CXXALIASWARN (_Exit);
#elif defined GNULIB_POSIXCHECK
# undef _Exit
# if HAVE_RAW_DECL__EXIT
_GL_WARN_ON_USE (_Exit, "_Exit is unportable - "
                 "use gnulib module _Exit for portability");
# endif
#endif


#if 0
/* Parse a signed decimal integer.
   Returns the value of the integer.  Errors are not detected.  */
# if !1
_GL_FUNCDECL_SYS (atoll, long long, (const char *string)
                                    _GL_ATTRIBUTE_PURE
                                    _GL_ARG_NONNULL ((1)));
# endif
_GL_CXXALIAS_SYS (atoll, long long, (const char *string));
_GL_CXXALIASWARN (atoll);
#elif defined GNULIB_POSIXCHECK
# undef atoll
# if HAVE_RAW_DECL_ATOLL
_GL_WARN_ON_USE (atoll, "atoll is unportable - "
                 "use gnulib module atoll for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef calloc
#   define calloc rpl_calloc
#  endif
_GL_FUNCDECL_RPL (calloc, void *, (size_t nmemb, size_t size));
_GL_CXXALIAS_RPL (calloc, void *, (size_t nmemb, size_t size));
# else
_GL_CXXALIAS_SYS (calloc, void *, (size_t nmemb, size_t size));
# endif
_GL_CXXALIASWARN (calloc);
#elif defined GNULIB_POSIXCHECK
# undef calloc
/* Assume calloc is always declared.  */
_GL_WARN_ON_USE (calloc, "calloc is not POSIX compliant everywhere - "
                 "use gnulib module calloc-posix for portability");
#endif

#if 1
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   define canonicalize_file_name rpl_canonicalize_file_name
#  endif
_GL_FUNCDECL_RPL (canonicalize_file_name, char *, (const char *name)
                                                  _GL_ARG_NONNULL ((1)));
_GL_CXXALIAS_RPL (canonicalize_file_name, char *, (const char *name));
# else
#  if !1
_GL_FUNCDECL_SYS (canonicalize_file_name, char *, (const char *name)
                                                  _GL_ARG_NONNULL ((1)));
#  endif
_GL_CXXALIAS_SYS (canonicalize_file_name, char *, (const char *name));
# endif
_GL_CXXALIASWARN (canonicalize_file_name);
#elif defined GNULIB_POSIXCHECK
# undef canonicalize_file_name
# if HAVE_RAW_DECL_CANONICALIZE_FILE_NAME
_GL_WARN_ON_USE (canonicalize_file_name,
                 "canonicalize_file_name is unportable - "
                 "use gnulib module canonicalize-lgpl for portability");
# endif
#endif

#if 0
/* Store max(NELEM,3) load average numbers in LOADAVG[].
   The three numbers are the load average of the last 1 minute, the last 5
   minutes, and the last 15 minutes, respectively.
   LOADAVG is an array of NELEM numbers.  */
# if !1
_GL_FUNCDECL_SYS (getloadavg, int, (double loadavg[], int nelem)
                                   _GL_ARG_NONNULL ((1)));
# endif
_GL_CXXALIAS_SYS (getloadavg, int, (double loadavg[], int nelem));
_GL_CXXALIASWARN (getloadavg);
#elif defined GNULIB_POSIXCHECK
# undef getloadavg
# if HAVE_RAW_DECL_GETLOADAVG
_GL_WARN_ON_USE (getloadavg, "getloadavg is not portable - "
                 "use gnulib module getloadavg for portability");
# endif
#endif

#if 0
/* Assuming *OPTIONP is a comma separated list of elements of the form
   "token" or "token=value", getsubopt parses the first of these elements.
   If the first element refers to a "token" that is member of the given
   NULL-terminated array of tokens:
     - It replaces the comma with a NUL byte, updates *OPTIONP to point past
       the first option and the comma, sets *VALUEP to the value of the
       element (or NULL if it doesn't contain an "=" sign),
     - It returns the index of the "token" in the given array of tokens.
   Otherwise it returns -1, and *OPTIONP and *VALUEP are undefined.
   For more details see the POSIX:2001 specification.
   http://www.opengroup.org/susv3xsh/getsubopt.html */
# if !1
_GL_FUNCDECL_SYS (getsubopt, int,
                  (char **optionp, char *const *tokens, char **valuep)
                  _GL_ARG_NONNULL ((1, 2, 3)));
# endif
_GL_CXXALIAS_SYS (getsubopt, int,
                  (char **optionp, char *const *tokens, char **valuep));
_GL_CXXALIASWARN (getsubopt);
#elif defined GNULIB_POSIXCHECK
# undef getsubopt
# if HAVE_RAW_DECL_GETSUBOPT
_GL_WARN_ON_USE (getsubopt, "getsubopt is unportable - "
                 "use gnulib module getsubopt for portability");
# endif
#endif

#if 0
/* Change the ownership and access permission of the slave side of the
   pseudo-terminal whose master side is specified by FD.  */
# if !1
_GL_FUNCDECL_SYS (grantpt, int, (int fd));
# endif
_GL_CXXALIAS_SYS (grantpt, int, (int fd));
_GL_CXXALIASWARN (grantpt);
#elif defined GNULIB_POSIXCHECK
# undef grantpt
# if HAVE_RAW_DECL_GRANTPT
_GL_WARN_ON_USE (grantpt, "grantpt is not portable - "
                 "use gnulib module grantpt for portability");
# endif
#endif

/* If _GL_USE_STDLIB_ALLOC is nonzero, the including module does not
   rely on GNU or POSIX semantics for malloc and realloc (for example,
   by never specifying a zero size), so it does not need malloc or
   realloc to be redefined.  */
#if 1
# if 0
#  if !((defined __cplusplus && defined GNULIB_NAMESPACE) \
        || _GL_USE_STDLIB_ALLOC)
#   undef malloc
#   define malloc rpl_malloc
#  endif
_GL_FUNCDECL_RPL (malloc, void *, (size_t size));
_GL_CXXALIAS_RPL (malloc, void *, (size_t size));
# else
_GL_CXXALIAS_SYS (malloc, void *, (size_t size));
# endif
_GL_CXXALIASWARN (malloc);
#elif defined GNULIB_POSIXCHECK && !_GL_USE_STDLIB_ALLOC
# undef malloc
/* Assume malloc is always declared.  */
_GL_WARN_ON_USE (malloc, "malloc is not POSIX compliant everywhere - "
                 "use gnulib module malloc-posix for portability");
#endif

/* Convert a multibyte character to a wide character.  */
#if 1
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef mbtowc
#   define mbtowc rpl_mbtowc
#  endif
_GL_FUNCDECL_RPL (mbtowc, int, (wchar_t *pwc, const char *s, size_t n));
_GL_CXXALIAS_RPL (mbtowc, int, (wchar_t *pwc, const char *s, size_t n));
# else
#  if !1
_GL_FUNCDECL_SYS (mbtowc, int, (wchar_t *pwc, const char *s, size_t n));
#  endif
_GL_CXXALIAS_SYS (mbtowc, int, (wchar_t *pwc, const char *s, size_t n));
# endif
_GL_CXXALIASWARN (mbtowc);
#elif defined GNULIB_POSIXCHECK
# undef mbtowc
# if HAVE_RAW_DECL_MBTOWC
_GL_WARN_ON_USE (mbtowc, "mbtowc is not portable - "
                 "use gnulib module mbtowc for portability");
# endif
#endif

#if 0
/* Create a unique temporary directory from TEMPLATE.
   The last six characters of TEMPLATE must be "XXXXXX";
   they are replaced with a string that makes the directory name unique.
   Returns TEMPLATE, or a null pointer if it cannot get a unique name.
   The directory is created mode 700.  */
# if !1
_GL_FUNCDECL_SYS (mkdtemp, char *, (char * /*template*/) _GL_ARG_NONNULL ((1)));
# endif
_GL_CXXALIAS_SYS (mkdtemp, char *, (char * /*template*/));
_GL_CXXALIASWARN (mkdtemp);
#elif defined GNULIB_POSIXCHECK
# undef mkdtemp
# if HAVE_RAW_DECL_MKDTEMP
_GL_WARN_ON_USE (mkdtemp, "mkdtemp is unportable - "
                 "use gnulib module mkdtemp for portability");
# endif
#endif

#if 0
/* Create a unique temporary file from TEMPLATE.
   The last six characters of TEMPLATE must be "XXXXXX";
   they are replaced with a string that makes the file name unique.
   The flags are a bitmask, possibly including O_CLOEXEC (defined in <fcntl.h>)
   and O_TEXT, O_BINARY (defined in "binary-io.h").
   The file is then created, with the specified flags, ensuring it didn't exist
   before.
   The file is created read-write (mask at least 0600 & ~umask), but it may be
   world-readable and world-writable (mask 0666 & ~umask), depending on the
   implementation.
   Returns the open file descriptor if successful, otherwise -1 and errno
   set.  */
# if !1
_GL_FUNCDECL_SYS (mkostemp, int, (char * /*template*/, int /*flags*/)
                                 _GL_ARG_NONNULL ((1)));
# endif
_GL_CXXALIAS_SYS (mkostemp, int, (char * /*template*/, int /*flags*/));
_GL_CXXALIASWARN (mkostemp);
#elif defined GNULIB_POSIXCHECK
# undef mkostemp
# if HAVE_RAW_DECL_MKOSTEMP
_GL_WARN_ON_USE (mkostemp, "mkostemp is unportable - "
                 "use gnulib module mkostemp for portability");
# endif
#endif

#if 0
/* Create a unique temporary file from TEMPLATE.
   The last six characters of TEMPLATE before a suffix of length
   SUFFIXLEN must be "XXXXXX";
   they are replaced with a string that makes the file name unique.
   The flags are a bitmask, possibly including O_CLOEXEC (defined in <fcntl.h>)
   and O_TEXT, O_BINARY (defined in "binary-io.h").
   The file is then created, with the specified flags, ensuring it didn't exist
   before.
   The file is created read-write (mask at least 0600 & ~umask), but it may be
   world-readable and world-writable (mask 0666 & ~umask), depending on the
   implementation.
   Returns the open file descriptor if successful, otherwise -1 and errno
   set.  */
# if !1
_GL_FUNCDECL_SYS (mkostemps, int,
                  (char * /*template*/, int /*suffixlen*/, int /*flags*/)
                  _GL_ARG_NONNULL ((1)));
# endif
_GL_CXXALIAS_SYS (mkostemps, int,
                  (char * /*template*/, int /*suffixlen*/, int /*flags*/));
_GL_CXXALIASWARN (mkostemps);
#elif defined GNULIB_POSIXCHECK
# undef mkostemps
# if HAVE_RAW_DECL_MKOSTEMPS
_GL_WARN_ON_USE (mkostemps, "mkostemps is unportable - "
                 "use gnulib module mkostemps for portability");
# endif
#endif

#if 1
/* Create a unique temporary file from TEMPLATE.
   The last six characters of TEMPLATE must be "XXXXXX";
   they are replaced with a string that makes the file name unique.
   The file is then created, ensuring it didn't exist before.
   The file is created read-write (mask at least 0600 & ~umask), but it may be
   world-readable and world-writable (mask 0666 & ~umask), depending on the
   implementation.
   Returns the open file descriptor if successful, otherwise -1 and errno
   set.  */
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   define mkstemp rpl_mkstemp
#  endif
_GL_FUNCDECL_RPL (mkstemp, int, (char * /*template*/) _GL_ARG_NONNULL ((1)));
_GL_CXXALIAS_RPL (mkstemp, int, (char * /*template*/));
# else
#  if ! 1
_GL_FUNCDECL_SYS (mkstemp, int, (char * /*template*/) _GL_ARG_NONNULL ((1)));
#  endif
_GL_CXXALIAS_SYS (mkstemp, int, (char * /*template*/));
# endif
_GL_CXXALIASWARN (mkstemp);
#elif defined GNULIB_POSIXCHECK
# undef mkstemp
# if HAVE_RAW_DECL_MKSTEMP
_GL_WARN_ON_USE (mkstemp, "mkstemp is unportable - "
                 "use gnulib module mkstemp for portability");
# endif
#endif

#if 0
/* Create a unique temporary file from TEMPLATE.
   The last six characters of TEMPLATE prior to a suffix of length
   SUFFIXLEN must be "XXXXXX";
   they are replaced with a string that makes the file name unique.
   The file is then created, ensuring it didn't exist before.
   The file is created read-write (mask at least 0600 & ~umask), but it may be
   world-readable and world-writable (mask 0666 & ~umask), depending on the
   implementation.
   Returns the open file descriptor if successful, otherwise -1 and errno
   set.  */
# if !1
_GL_FUNCDECL_SYS (mkstemps, int, (char * /*template*/, int /*suffixlen*/)
                                 _GL_ARG_NONNULL ((1)));
# endif
_GL_CXXALIAS_SYS (mkstemps, int, (char * /*template*/, int /*suffixlen*/));
_GL_CXXALIASWARN (mkstemps);
#elif defined GNULIB_POSIXCHECK
# undef mkstemps
# if HAVE_RAW_DECL_MKSTEMPS
_GL_WARN_ON_USE (mkstemps, "mkstemps is unportable - "
                 "use gnulib module mkstemps for portability");
# endif
#endif

#if 0
/* Return an FD open to the master side of a pseudo-terminal.  Flags should
   include O_RDWR, and may also include O_NOCTTY.  */
# if !1
_GL_FUNCDECL_SYS (posix_openpt, int, (int flags));
# endif
_GL_CXXALIAS_SYS (posix_openpt, int, (int flags));
_GL_CXXALIASWARN (posix_openpt);
#elif defined GNULIB_POSIXCHECK
# undef posix_openpt
# if HAVE_RAW_DECL_POSIX_OPENPT
_GL_WARN_ON_USE (posix_openpt, "posix_openpt is not portable - "
                 "use gnulib module posix_openpt for portability");
# endif
#endif

#if 0
/* Return the pathname of the pseudo-terminal slave associated with
   the master FD is open on, or NULL on errors.  */
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef ptsname
#   define ptsname rpl_ptsname
#  endif
_GL_FUNCDECL_RPL (ptsname, char *, (int fd));
_GL_CXXALIAS_RPL (ptsname, char *, (int fd));
# else
#  if !1
_GL_FUNCDECL_SYS (ptsname, char *, (int fd));
#  endif
_GL_CXXALIAS_SYS (ptsname, char *, (int fd));
# endif
_GL_CXXALIASWARN (ptsname);
#elif defined GNULIB_POSIXCHECK
# undef ptsname
# if HAVE_RAW_DECL_PTSNAME
_GL_WARN_ON_USE (ptsname, "ptsname is not portable - "
                 "use gnulib module ptsname for portability");
# endif
#endif

#if 0
/* Set the pathname of the pseudo-terminal slave associated with
   the master FD is open on and return 0, or set errno and return
   non-zero on errors.  */
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef ptsname_r
#   define ptsname_r rpl_ptsname_r
#  endif
_GL_FUNCDECL_RPL (ptsname_r, int, (int fd, char *buf, size_t len));
_GL_CXXALIAS_RPL (ptsname_r, int, (int fd, char *buf, size_t len));
# else
#  if !1
_GL_FUNCDECL_SYS (ptsname_r, int, (int fd, char *buf, size_t len));
#  endif
_GL_CXXALIAS_SYS (ptsname_r, int, (int fd, char *buf, size_t len));
# endif
_GL_CXXALIASWARN (ptsname_r);
#elif defined GNULIB_POSIXCHECK
# undef ptsname_r
# if HAVE_RAW_DECL_PTSNAME_R
_GL_WARN_ON_USE (ptsname_r, "ptsname_r is not portable - "
                 "use gnulib module ptsname_r for portability");
# endif
#endif

#if IN_AUGEAS_GNULIB_TESTS
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef putenv
#   define putenv rpl_putenv
#  endif
_GL_FUNCDECL_RPL (putenv, int, (char *string) _GL_ARG_NONNULL ((1)));
_GL_CXXALIAS_RPL (putenv, int, (char *string));
# else
_GL_CXXALIAS_SYS (putenv, int, (char *string));
# endif
_GL_CXXALIASWARN (putenv);
#endif

#if 0
/* Sort an array of NMEMB elements, starting at address BASE, each element
   occupying SIZE bytes, in ascending order according to the comparison
   function COMPARE.  */
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef qsort_r
#   define qsort_r rpl_qsort_r
#  endif
_GL_FUNCDECL_RPL (qsort_r, void, (void *base, size_t nmemb, size_t size,
                                  int (*compare) (void const *, void const *,
                                                  void *),
                                  void *arg) _GL_ARG_NONNULL ((1, 4)));
_GL_CXXALIAS_RPL (qsort_r, void, (void *base, size_t nmemb, size_t size,
                                  int (*compare) (void const *, void const *,
                                                  void *),
                                  void *arg));
# else
#  if !1
_GL_FUNCDECL_SYS (qsort_r, void, (void *base, size_t nmemb, size_t size,
                                  int (*compare) (void const *, void const *,
                                                  void *),
                                  void *arg) _GL_ARG_NONNULL ((1, 4)));
#  endif
_GL_CXXALIAS_SYS (qsort_r, void, (void *base, size_t nmemb, size_t size,
                                  int (*compare) (void const *, void const *,
                                                  void *),
                                  void *arg));
# endif
_GL_CXXALIASWARN (qsort_r);
#elif defined GNULIB_POSIXCHECK
# undef qsort_r
# if HAVE_RAW_DECL_QSORT_R
_GL_WARN_ON_USE (qsort_r, "qsort_r is not portable - "
                 "use gnulib module qsort_r for portability");
# endif
#endif


#if 0
# if !1
#  ifndef RAND_MAX
#   define RAND_MAX 2147483647
#  endif
# endif
#endif


#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef random
#   define random rpl_random
#  endif
_GL_FUNCDECL_RPL (random, long, (void));
_GL_CXXALIAS_RPL (random, long, (void));
# else
#  if !1
_GL_FUNCDECL_SYS (random, long, (void));
#  endif
_GL_CXXALIAS_SYS (random, long, (void));
# endif
_GL_CXXALIASWARN (random);
#elif defined GNULIB_POSIXCHECK
# undef random
# if HAVE_RAW_DECL_RANDOM
_GL_WARN_ON_USE (random, "random is unportable - "
                 "use gnulib module random for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef srandom
#   define srandom rpl_srandom
#  endif
_GL_FUNCDECL_RPL (srandom, void, (unsigned int seed));
_GL_CXXALIAS_RPL (srandom, void, (unsigned int seed));
# else
#  if !1
_GL_FUNCDECL_SYS (srandom, void, (unsigned int seed));
#  endif
_GL_CXXALIAS_SYS (srandom, void, (unsigned int seed));
# endif
_GL_CXXALIASWARN (srandom);
#elif defined GNULIB_POSIXCHECK
# undef srandom
# if HAVE_RAW_DECL_SRANDOM
_GL_WARN_ON_USE (srandom, "srandom is unportable - "
                 "use gnulib module random for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef initstate
#   define initstate rpl_initstate
#  endif
_GL_FUNCDECL_RPL (initstate, char *,
                  (unsigned int seed, char *buf, size_t buf_size)
                  _GL_ARG_NONNULL ((2)));
_GL_CXXALIAS_RPL (initstate, char *,
                  (unsigned int seed, char *buf, size_t buf_size));
# else
#  if !1 || !1
_GL_FUNCDECL_SYS (initstate, char *,
                  (unsigned int seed, char *buf, size_t buf_size)
                  _GL_ARG_NONNULL ((2)));
#  endif
_GL_CXXALIAS_SYS (initstate, char *,
                  (unsigned int seed, char *buf, size_t buf_size));
# endif
_GL_CXXALIASWARN (initstate);
#elif defined GNULIB_POSIXCHECK
# undef initstate
# if HAVE_RAW_DECL_INITSTATE
_GL_WARN_ON_USE (initstate, "initstate is unportable - "
                 "use gnulib module random for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef setstate
#   define setstate rpl_setstate
#  endif
_GL_FUNCDECL_RPL (setstate, char *, (char *arg_state) _GL_ARG_NONNULL ((1)));
_GL_CXXALIAS_RPL (setstate, char *, (char *arg_state));
# else
#  if !1 || !1
_GL_FUNCDECL_SYS (setstate, char *, (char *arg_state) _GL_ARG_NONNULL ((1)));
#  endif
_GL_CXXALIAS_SYS (setstate, char *, (char *arg_state));
# endif
_GL_CXXALIASWARN (setstate);
#elif defined GNULIB_POSIXCHECK
# undef setstate
# if HAVE_RAW_DECL_SETSTATE
_GL_WARN_ON_USE (setstate, "setstate is unportable - "
                 "use gnulib module random for portability");
# endif
#endif


#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef random_r
#   define random_r rpl_random_r
#  endif
_GL_FUNCDECL_RPL (random_r, int, (struct random_data *buf, int32_t *result)
                                 _GL_ARG_NONNULL ((1, 2)));
_GL_CXXALIAS_RPL (random_r, int, (struct random_data *buf, int32_t *result));
# else
#  if !1
_GL_FUNCDECL_SYS (random_r, int, (struct random_data *buf, int32_t *result)
                                 _GL_ARG_NONNULL ((1, 2)));
#  endif
_GL_CXXALIAS_SYS (random_r, int, (struct random_data *buf, int32_t *result));
# endif
_GL_CXXALIASWARN (random_r);
#elif defined GNULIB_POSIXCHECK
# undef random_r
# if HAVE_RAW_DECL_RANDOM_R
_GL_WARN_ON_USE (random_r, "random_r is unportable - "
                 "use gnulib module random_r for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef srandom_r
#   define srandom_r rpl_srandom_r
#  endif
_GL_FUNCDECL_RPL (srandom_r, int,
                  (unsigned int seed, struct random_data *rand_state)
                  _GL_ARG_NONNULL ((2)));
_GL_CXXALIAS_RPL (srandom_r, int,
                  (unsigned int seed, struct random_data *rand_state));
# else
#  if !1
_GL_FUNCDECL_SYS (srandom_r, int,
                  (unsigned int seed, struct random_data *rand_state)
                  _GL_ARG_NONNULL ((2)));
#  endif
_GL_CXXALIAS_SYS (srandom_r, int,
                  (unsigned int seed, struct random_data *rand_state));
# endif
_GL_CXXALIASWARN (srandom_r);
#elif defined GNULIB_POSIXCHECK
# undef srandom_r
# if HAVE_RAW_DECL_SRANDOM_R
_GL_WARN_ON_USE (srandom_r, "srandom_r is unportable - "
                 "use gnulib module random_r for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef initstate_r
#   define initstate_r rpl_initstate_r
#  endif
_GL_FUNCDECL_RPL (initstate_r, int,
                  (unsigned int seed, char *buf, size_t buf_size,
                   struct random_data *rand_state)
                  _GL_ARG_NONNULL ((2, 4)));
_GL_CXXALIAS_RPL (initstate_r, int,
                  (unsigned int seed, char *buf, size_t buf_size,
                   struct random_data *rand_state));
# else
#  if !1
_GL_FUNCDECL_SYS (initstate_r, int,
                  (unsigned int seed, char *buf, size_t buf_size,
                   struct random_data *rand_state)
                  _GL_ARG_NONNULL ((2, 4)));
#  endif
_GL_CXXALIAS_SYS (initstate_r, int,
                  (unsigned int seed, char *buf, size_t buf_size,
                   struct random_data *rand_state));
# endif
_GL_CXXALIASWARN (initstate_r);
#elif defined GNULIB_POSIXCHECK
# undef initstate_r
# if HAVE_RAW_DECL_INITSTATE_R
_GL_WARN_ON_USE (initstate_r, "initstate_r is unportable - "
                 "use gnulib module random_r for portability");
# endif
#endif

#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef setstate_r
#   define setstate_r rpl_setstate_r
#  endif
_GL_FUNCDECL_RPL (setstate_r, int,
                  (char *arg_state, struct random_data *rand_state)
                  _GL_ARG_NONNULL ((1, 2)));
_GL_CXXALIAS_RPL (setstate_r, int,
                  (char *arg_state, struct random_data *rand_state));
# else
#  if !1
_GL_FUNCDECL_SYS (setstate_r, int,
                  (char *arg_state, struct random_data *rand_state)
                  _GL_ARG_NONNULL ((1, 2)));
#  endif
_GL_CXXALIAS_SYS (setstate_r, int,
                  (char *arg_state, struct random_data *rand_state));
# endif
_GL_CXXALIASWARN (setstate_r);
#elif defined GNULIB_POSIXCHECK
# undef setstate_r
# if HAVE_RAW_DECL_SETSTATE_R
_GL_WARN_ON_USE (setstate_r, "setstate_r is unportable - "
                 "use gnulib module random_r for portability");
# endif
#endif


#if 0
# if 0
#  if !((defined __cplusplus && defined GNULIB_NAMESPACE) \
        || _GL_USE_STDLIB_ALLOC)
#   undef realloc
#   define realloc rpl_realloc
#  endif
_GL_FUNCDECL_RPL (realloc, void *, (void *ptr, size_t size));
_GL_CXXALIAS_RPL (realloc, void *, (void *ptr, size_t size));
# else
_GL_CXXALIAS_SYS (realloc, void *, (void *ptr, size_t size));
# endif
_GL_CXXALIASWARN (realloc);
#elif defined GNULIB_POSIXCHECK && !_GL_USE_STDLIB_ALLOC
# undef realloc
/* Assume realloc is always declared.  */
_GL_WARN_ON_USE (realloc, "realloc is not POSIX compliant everywhere - "
                 "use gnulib module realloc-posix for portability");
#endif


#if 0
# if ! 1
_GL_FUNCDECL_SYS (reallocarray, void *,
                  (void *ptr, size_t nmemb, size_t size));
# endif
_GL_CXXALIAS_SYS (reallocarray, void *,
                  (void *ptr, size_t nmemb, size_t size));
_GL_CXXALIASWARN (reallocarray);
#elif defined GNULIB_POSIXCHECK
# undef reallocarray
# if HAVE_RAW_DECL_REALLOCARRAY
_GL_WARN_ON_USE (reallocarray, "reallocarray is not portable - "
                 "use gnulib module reallocarray for portability");
# endif
#endif

#if 1
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   define realpath rpl_realpath
#  endif
_GL_FUNCDECL_RPL (realpath, char *, (const char *name, char *resolved)
                                    _GL_ARG_NONNULL ((1)));
_GL_CXXALIAS_RPL (realpath, char *, (const char *name, char *resolved));
# else
#  if !1
_GL_FUNCDECL_SYS (realpath, char *, (const char *name, char *resolved)
                                    _GL_ARG_NONNULL ((1)));
#  endif
_GL_CXXALIAS_SYS (realpath, char *, (const char *name, char *resolved));
# endif
_GL_CXXALIASWARN (realpath);
#elif defined GNULIB_POSIXCHECK
# undef realpath
# if HAVE_RAW_DECL_REALPATH
_GL_WARN_ON_USE (realpath, "realpath is unportable - use gnulib module "
                 "canonicalize or canonicalize-lgpl for portability");
# endif
#endif

#if 0
/* Test a user response to a question.
   Return 1 if it is affirmative, 0 if it is negative, or -1 if not clear.  */
# if !1
_GL_FUNCDECL_SYS (rpmatch, int, (const char *response) _GL_ARG_NONNULL ((1)));
# endif
_GL_CXXALIAS_SYS (rpmatch, int, (const char *response));
_GL_CXXALIASWARN (rpmatch);
#elif defined GNULIB_POSIXCHECK
# undef rpmatch
# if HAVE_RAW_DECL_RPMATCH
_GL_WARN_ON_USE (rpmatch, "rpmatch is unportable - "
                 "use gnulib module rpmatch for portability");
# endif
#endif

#if 0
/* Look up NAME in the environment, returning 0 in insecure situations.  */
# if !1
_GL_FUNCDECL_SYS (secure_getenv, char *,
                  (char const *name) _GL_ARG_NONNULL ((1)));
# endif
_GL_CXXALIAS_SYS (secure_getenv, char *, (char const *name));
_GL_CXXALIASWARN (secure_getenv);
#elif defined GNULIB_POSIXCHECK
# undef secure_getenv
# if HAVE_RAW_DECL_SECURE_GETENV
_GL_WARN_ON_USE (secure_getenv, "secure_getenv is unportable - "
                 "use gnulib module secure_getenv for portability");
# endif
#endif

#if IN_AUGEAS_GNULIB_TESTS
/* Set NAME to VALUE in the environment.
   If REPLACE is nonzero, overwrite an existing value.  */
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef setenv
#   define setenv rpl_setenv
#  endif
_GL_FUNCDECL_RPL (setenv, int,
                  (const char *name, const char *value, int replace)
                  _GL_ARG_NONNULL ((1)));
_GL_CXXALIAS_RPL (setenv, int,
                  (const char *name, const char *value, int replace));
# else
#  if !1
_GL_FUNCDECL_SYS (setenv, int,
                  (const char *name, const char *value, int replace)
                  _GL_ARG_NONNULL ((1)));
#  endif
_GL_CXXALIAS_SYS (setenv, int,
                  (const char *name, const char *value, int replace));
# endif
# if !(0 && !1)
_GL_CXXALIASWARN (setenv);
# endif
#elif defined GNULIB_POSIXCHECK
# undef setenv
# if HAVE_RAW_DECL_SETENV
_GL_WARN_ON_USE (setenv, "setenv is unportable - "
                 "use gnulib module setenv for portability");
# endif
#endif

#if 0
 /* Parse a double from STRING, updating ENDP if appropriate.  */
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   define strtod rpl_strtod
#  endif
#  define GNULIB_defined_strtod_function 1
_GL_FUNCDECL_RPL (strtod, double, (const char *str, char **endp)
                                  _GL_ARG_NONNULL ((1)));
_GL_CXXALIAS_RPL (strtod, double, (const char *str, char **endp));
# else
#  if !1
_GL_FUNCDECL_SYS (strtod, double, (const char *str, char **endp)
                                  _GL_ARG_NONNULL ((1)));
#  endif
_GL_CXXALIAS_SYS (strtod, double, (const char *str, char **endp));
# endif
_GL_CXXALIASWARN (strtod);
#elif defined GNULIB_POSIXCHECK
# undef strtod
# if HAVE_RAW_DECL_STRTOD
_GL_WARN_ON_USE (strtod, "strtod is unportable - "
                 "use gnulib module strtod for portability");
# endif
#endif

#if 0
 /* Parse a 'long double' from STRING, updating ENDP if appropriate.  */
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   define strtold rpl_strtold
#  endif
#  define GNULIB_defined_strtold_function 1
_GL_FUNCDECL_RPL (strtold, long double, (const char *str, char **endp)
                                        _GL_ARG_NONNULL ((1)));
_GL_CXXALIAS_RPL (strtold, long double, (const char *str, char **endp));
# else
#  if !1
_GL_FUNCDECL_SYS (strtold, long double, (const char *str, char **endp)
                                        _GL_ARG_NONNULL ((1)));
#  endif
_GL_CXXALIAS_SYS (strtold, long double, (const char *str, char **endp));
# endif
_GL_CXXALIASWARN (strtold);
#elif defined GNULIB_POSIXCHECK
# undef strtold
# if HAVE_RAW_DECL_STRTOLD
_GL_WARN_ON_USE (strtold, "strtold is unportable - "
                 "use gnulib module strtold for portability");
# endif
#endif

#if 0
/* Parse a signed integer whose textual representation starts at STRING.
   The integer is expected to be in base BASE (2 <= BASE <= 36); if BASE == 0,
   it may be decimal or octal (with prefix "0") or hexadecimal (with prefix
   "0x").
   If ENDPTR is not NULL, the address of the first byte after the integer is
   stored in *ENDPTR.
   Upon overflow, the return value is LLONG_MAX or LLONG_MIN, and errno is set
   to ERANGE.  */
# if !1
_GL_FUNCDECL_SYS (strtoll, long long,
                  (const char *string, char **endptr, int base)
                  _GL_ARG_NONNULL ((1)));
# endif
_GL_CXXALIAS_SYS (strtoll, long long,
                  (const char *string, char **endptr, int base));
_GL_CXXALIASWARN (strtoll);
#elif defined GNULIB_POSIXCHECK
# undef strtoll
# if HAVE_RAW_DECL_STRTOLL
_GL_WARN_ON_USE (strtoll, "strtoll is unportable - "
                 "use gnulib module strtoll for portability");
# endif
#endif

#if 0
/* Parse an unsigned integer whose textual representation starts at STRING.
   The integer is expected to be in base BASE (2 <= BASE <= 36); if BASE == 0,
   it may be decimal or octal (with prefix "0") or hexadecimal (with prefix
   "0x").
   If ENDPTR is not NULL, the address of the first byte after the integer is
   stored in *ENDPTR.
   Upon overflow, the return value is ULLONG_MAX, and errno is set to
   ERANGE.  */
# if !1
_GL_FUNCDECL_SYS (strtoull, unsigned long long,
                  (const char *string, char **endptr, int base)
                  _GL_ARG_NONNULL ((1)));
# endif
_GL_CXXALIAS_SYS (strtoull, unsigned long long,
                  (const char *string, char **endptr, int base));
_GL_CXXALIASWARN (strtoull);
#elif defined GNULIB_POSIXCHECK
# undef strtoull
# if HAVE_RAW_DECL_STRTOULL
_GL_WARN_ON_USE (strtoull, "strtoull is unportable - "
                 "use gnulib module strtoull for portability");
# endif
#endif

#if 0
/* Unlock the slave side of the pseudo-terminal whose master side is specified
   by FD, so that it can be opened.  */
# if !1
_GL_FUNCDECL_SYS (unlockpt, int, (int fd));
# endif
_GL_CXXALIAS_SYS (unlockpt, int, (int fd));
_GL_CXXALIASWARN (unlockpt);
#elif defined GNULIB_POSIXCHECK
# undef unlockpt
# if HAVE_RAW_DECL_UNLOCKPT
_GL_WARN_ON_USE (unlockpt, "unlockpt is not portable - "
                 "use gnulib module unlockpt for portability");
# endif
#endif

#if IN_AUGEAS_GNULIB_TESTS
/* Remove the variable NAME from the environment.  */
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef unsetenv
#   define unsetenv rpl_unsetenv
#  endif
_GL_FUNCDECL_RPL (unsetenv, int, (const char *name) _GL_ARG_NONNULL ((1)));
_GL_CXXALIAS_RPL (unsetenv, int, (const char *name));
# else
#  if !1
_GL_FUNCDECL_SYS (unsetenv, int, (const char *name) _GL_ARG_NONNULL ((1)));
#  endif
_GL_CXXALIAS_SYS (unsetenv, int, (const char *name));
# endif
# if !(0 && !1)
_GL_CXXALIASWARN (unsetenv);
# endif
#elif defined GNULIB_POSIXCHECK
# undef unsetenv
# if HAVE_RAW_DECL_UNSETENV
_GL_WARN_ON_USE (unsetenv, "unsetenv is unportable - "
                 "use gnulib module unsetenv for portability");
# endif
#endif

/* Convert a wide character to a multibyte character.  */
#if IN_AUGEAS_GNULIB_TESTS
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef wctomb
#   define wctomb rpl_wctomb
#  endif
_GL_FUNCDECL_RPL (wctomb, int, (char *s, wchar_t wc));
_GL_CXXALIAS_RPL (wctomb, int, (char *s, wchar_t wc));
# else
_GL_CXXALIAS_SYS (wctomb, int, (char *s, wchar_t wc));
# endif
_GL_CXXALIASWARN (wctomb);
#endif


#endif /* _GL_STDLIB_H */
#endif /* _GL_STDLIB_H */
#endif
