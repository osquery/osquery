/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* A substitute for ISO C99 <wctype.h>, for platforms that lack it.

   Copyright (C) 2006-2019 Free Software Foundation, Inc.

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

/* Written by Bruno Haible and Paul Eggert.  */

/*
 * ISO C 99 <wctype.h> for platforms that lack it.
 * <http://www.opengroup.org/susv3xbd/wctype.h.html>
 *
 * iswctype, towctrans, towlower, towupper, wctrans, wctype,
 * wctrans_t, and wctype_t are not yet implemented.
 */

#if __GNUC__ >= 3
#pragma GCC system_header
#endif


#if (defined __MINGW32__ && defined __CTYPE_H_SOURCED__)

/* Special invocation convention:
   - With MinGW 3.22, when <ctype.h> includes <wctype.h>, only some part of
     <wctype.h> is being processed, which doesn't include the idempotency
     guard.   */

#include_next <wctype.h>

#else
/* Normal invocation convention.  */

#ifndef _GL_WCTYPE_H

#if 1
/* Solaris 2.5 has a bug: <wchar.h> must be included before <wctype.h>.
   Tru64 with Desktop Toolkit C has a bug: <stdio.h> must be included before
   <wchar.h>.
   BSD/OS 4.0.1 has a bug: <stddef.h>, <stdio.h> and <time.h> must be
   included before <wchar.h>.  */
# include <stddef.h>
# include <stdio.h>
# include <time.h>
# include <wchar.h>
#endif

/* Native Windows (mingw, MSVC) have declarations of towupper, towlower, and
   isw* functions in <ctype.h>, <wchar.h> as well as in <wctype.h>.  Include
   <ctype.h>, <wchar.h> in advance to avoid rpl_ prefix being added to the
   declarations.  */
#if defined _WIN32 && ! defined __CYGWIN__
# include <ctype.h>
# include <wchar.h>
#endif

/* Include the original <wctype.h> if it exists.
   BeOS 5 has the functions but no <wctype.h>.  */
/* The include_next requires a split double-inclusion guard.  */
#if 1
# include_next <wctype.h>
#endif

#ifndef _GL_WCTYPE_H
#define _GL_WCTYPE_H

#ifndef _GL_INLINE_HEADER_BEGIN
 #error "Please include config.h first."
#endif
_GL_INLINE_HEADER_BEGIN
#ifndef _GL_WCTYPE_INLINE
# define _GL_WCTYPE_INLINE _GL_INLINE
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

/* Solaris 2.6 <wctype.h> includes <widec.h> which includes <euc.h> which
   #defines a number of identifiers in the application namespace.  Revert
   these #defines.  */
#ifdef __sun
# undef multibyte
# undef eucw1
# undef eucw2
# undef eucw3
# undef scrw1
# undef scrw2
# undef scrw3
#endif

/* Define wint_t and WEOF.  (Also done in wchar.in.h.)  */
#if !1 && !defined wint_t
# define wint_t int
# ifndef WEOF
#  define WEOF -1
# endif
#else
/* mingw and MSVC define wint_t as 'unsigned short' in <crtdefs.h> or
   <stddef.h>.  This is too small: ISO C 99 section 7.24.1.(2) says that
   wint_t must be "unchanged by default argument promotions".  Override it.  */
# if 0
#  if !GNULIB_defined_wint_t
#   if 0
#    include <crtdefs.h>
#   else
#    include <stddef.h>
#   endif
typedef unsigned int rpl_wint_t;
#   undef wint_t
#   define wint_t rpl_wint_t
#   define GNULIB_defined_wint_t 1
#  endif
# endif
# ifndef WEOF
#  define WEOF ((wint_t) -1)
# endif
#endif


#if !GNULIB_defined_wctype_functions

/* FreeBSD 4.4 to 4.11 has <wctype.h> but lacks the functions.
   Linux libc5 has <wctype.h> and the functions but they are broken.
   Assume all 11 functions (all isw* except iswblank) are implemented the
   same way, or not at all.  */
# if ! 1 || 0

/* IRIX 5.3 has macros but no functions, its isw* macros refer to an
   undefined variable _ctmp_ and to <ctype.h> macros like _P, and they
   refer to system functions like _iswctype that are not in the
   standard C library.  Rather than try to get ancient buggy
   implementations like this to work, just disable them.  */
#  undef iswalnum
#  undef iswalpha
#  undef iswblank
#  undef iswcntrl
#  undef iswdigit
#  undef iswgraph
#  undef iswlower
#  undef iswprint
#  undef iswpunct
#  undef iswspace
#  undef iswupper
#  undef iswxdigit
#  undef towlower
#  undef towupper

/* Linux libc5 has <wctype.h> and the functions but they are broken.  */
#  if 0
#   if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#    define iswalnum rpl_iswalnum
#    define iswalpha rpl_iswalpha
#    define iswblank rpl_iswblank
#    define iswcntrl rpl_iswcntrl
#    define iswdigit rpl_iswdigit
#    define iswgraph rpl_iswgraph
#    define iswlower rpl_iswlower
#    define iswprint rpl_iswprint
#    define iswpunct rpl_iswpunct
#    define iswspace rpl_iswspace
#    define iswupper rpl_iswupper
#    define iswxdigit rpl_iswxdigit
#   endif
#  endif
#  if 0
#   if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#    define towlower rpl_towlower
#    define towupper rpl_towupper
#   endif
#  endif

_GL_WCTYPE_INLINE int
#  if 0
rpl_iswalnum
#  else
iswalnum
#  endif
         (wint_t wc)
{
  return ((wc >= '0' && wc <= '9')
          || ((wc & ~0x20) >= 'A' && (wc & ~0x20) <= 'Z'));
}

_GL_WCTYPE_INLINE int
#  if 0
rpl_iswalpha
#  else
iswalpha
#  endif
         (wint_t wc)
{
  return (wc & ~0x20) >= 'A' && (wc & ~0x20) <= 'Z';
}

_GL_WCTYPE_INLINE int
#  if 0
rpl_iswblank
#  else
iswblank
#  endif
         (wint_t wc)
{
  return wc == ' ' || wc == '\t';
}

_GL_WCTYPE_INLINE int
#  if 0
rpl_iswcntrl
#  else
iswcntrl
#  endif
        (wint_t wc)
{
  return (wc & ~0x1f) == 0 || wc == 0x7f;
}

_GL_WCTYPE_INLINE int
#  if 0
rpl_iswdigit
#  else
iswdigit
#  endif
         (wint_t wc)
{
  return wc >= '0' && wc <= '9';
}

_GL_WCTYPE_INLINE int
#  if 0
rpl_iswgraph
#  else
iswgraph
#  endif
         (wint_t wc)
{
  return wc >= '!' && wc <= '~';
}

_GL_WCTYPE_INLINE int
#  if 0
rpl_iswlower
#  else
iswlower
#  endif
         (wint_t wc)
{
  return wc >= 'a' && wc <= 'z';
}

_GL_WCTYPE_INLINE int
#  if 0
rpl_iswprint
#  else
iswprint
#  endif
         (wint_t wc)
{
  return wc >= ' ' && wc <= '~';
}

_GL_WCTYPE_INLINE int
#  if 0
rpl_iswpunct
#  else
iswpunct
#  endif
         (wint_t wc)
{
  return (wc >= '!' && wc <= '~'
          && !((wc >= '0' && wc <= '9')
               || ((wc & ~0x20) >= 'A' && (wc & ~0x20) <= 'Z')));
}

_GL_WCTYPE_INLINE int
#  if 0
rpl_iswspace
#  else
iswspace
#  endif
         (wint_t wc)
{
  return (wc == ' ' || wc == '\t'
          || wc == '\n' || wc == '\v' || wc == '\f' || wc == '\r');
}

_GL_WCTYPE_INLINE int
#  if 0
rpl_iswupper
#  else
iswupper
#  endif
         (wint_t wc)
{
  return wc >= 'A' && wc <= 'Z';
}

_GL_WCTYPE_INLINE int
#  if 0
rpl_iswxdigit
#  else
iswxdigit
#  endif
          (wint_t wc)
{
  return ((wc >= '0' && wc <= '9')
          || ((wc & ~0x20) >= 'A' && (wc & ~0x20) <= 'F'));
}

_GL_WCTYPE_INLINE wint_t
#  if 0
rpl_towlower
#  else
towlower
#  endif
         (wint_t wc)
{
  return (wc >= 'A' && wc <= 'Z' ? wc - 'A' + 'a' : wc);
}

_GL_WCTYPE_INLINE wint_t
#  if 0
rpl_towupper
#  else
towupper
#  endif
         (wint_t wc)
{
  return (wc >= 'a' && wc <= 'z' ? wc - 'a' + 'A' : wc);
}

# elif 0 && (! 1 || 0)
/* Only the iswblank function is missing.  */

#  if 0
#   if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#    define iswblank rpl_iswblank
#   endif
_GL_FUNCDECL_RPL (iswblank, int, (wint_t wc));
#  else
_GL_FUNCDECL_SYS (iswblank, int, (wint_t wc));
#  endif

# endif

# if defined __MINGW32__

/* On native Windows, wchar_t is uint16_t, and wint_t is uint32_t.
   The functions towlower and towupper are implemented in the MSVCRT library
   to take a wchar_t argument and return a wchar_t result.  mingw declares
   these functions to take a wint_t argument and return a wint_t result.
   This means that:
   1. When the user passes an argument outside the range 0x0000..0xFFFF, the
      function will look only at the lower 16 bits.  This is allowed according
      to POSIX.
   2. The return value is returned in the lower 16 bits of the result register.
      The upper 16 bits are random: whatever happened to be in that part of the
      result register.  We need to fix this by adding a zero-extend from
      wchar_t to wint_t after the call.  */

_GL_WCTYPE_INLINE wint_t
rpl_towlower (wint_t wc)
{
  return (wint_t) (wchar_t) towlower (wc);
}
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   define towlower rpl_towlower
#  endif

_GL_WCTYPE_INLINE wint_t
rpl_towupper (wint_t wc)
{
  return (wint_t) (wchar_t) towupper (wc);
}
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   define towupper rpl_towupper
#  endif

# endif /* __MINGW32__ */

# define GNULIB_defined_wctype_functions 1
#endif

#if 0
_GL_CXXALIAS_RPL (iswalnum, int, (wint_t wc));
_GL_CXXALIAS_RPL (iswalpha, int, (wint_t wc));
_GL_CXXALIAS_RPL (iswcntrl, int, (wint_t wc));
_GL_CXXALIAS_RPL (iswdigit, int, (wint_t wc));
_GL_CXXALIAS_RPL (iswgraph, int, (wint_t wc));
_GL_CXXALIAS_RPL (iswlower, int, (wint_t wc));
_GL_CXXALIAS_RPL (iswprint, int, (wint_t wc));
_GL_CXXALIAS_RPL (iswpunct, int, (wint_t wc));
_GL_CXXALIAS_RPL (iswspace, int, (wint_t wc));
_GL_CXXALIAS_RPL (iswupper, int, (wint_t wc));
_GL_CXXALIAS_RPL (iswxdigit, int, (wint_t wc));
#else
_GL_CXXALIAS_SYS (iswalnum, int, (wint_t wc));
_GL_CXXALIAS_SYS (iswalpha, int, (wint_t wc));
_GL_CXXALIAS_SYS (iswcntrl, int, (wint_t wc));
_GL_CXXALIAS_SYS (iswdigit, int, (wint_t wc));
_GL_CXXALIAS_SYS (iswgraph, int, (wint_t wc));
_GL_CXXALIAS_SYS (iswlower, int, (wint_t wc));
_GL_CXXALIAS_SYS (iswprint, int, (wint_t wc));
_GL_CXXALIAS_SYS (iswpunct, int, (wint_t wc));
_GL_CXXALIAS_SYS (iswspace, int, (wint_t wc));
_GL_CXXALIAS_SYS (iswupper, int, (wint_t wc));
_GL_CXXALIAS_SYS (iswxdigit, int, (wint_t wc));
#endif
_GL_CXXALIASWARN (iswalnum);
_GL_CXXALIASWARN (iswalpha);
_GL_CXXALIASWARN (iswcntrl);
_GL_CXXALIASWARN (iswdigit);
_GL_CXXALIASWARN (iswgraph);
_GL_CXXALIASWARN (iswlower);
_GL_CXXALIASWARN (iswprint);
_GL_CXXALIASWARN (iswpunct);
_GL_CXXALIASWARN (iswspace);
_GL_CXXALIASWARN (iswupper);
_GL_CXXALIASWARN (iswxdigit);

#if 0
# if 0 || 0
_GL_CXXALIAS_RPL (iswblank, int, (wint_t wc));
# else
_GL_CXXALIAS_SYS (iswblank, int, (wint_t wc));
# endif
_GL_CXXALIASWARN (iswblank);
#endif

#if !1
# if !GNULIB_defined_wctype_t
typedef void * wctype_t;
#  define GNULIB_defined_wctype_t 1
# endif
#endif

/* Get a descriptor for a wide character property.  */
#if 0
# if !1
_GL_FUNCDECL_SYS (wctype, wctype_t, (const char *name));
# endif
_GL_CXXALIAS_SYS (wctype, wctype_t, (const char *name));
_GL_CXXALIASWARN (wctype);
#elif defined GNULIB_POSIXCHECK
# undef wctype
# if HAVE_RAW_DECL_WCTYPE
_GL_WARN_ON_USE (wctype, "wctype is unportable - "
                 "use gnulib module wctype for portability");
# endif
#endif

/* Test whether a wide character has a given property.
   The argument WC must be either a wchar_t value or WEOF.
   The argument DESC must have been returned by the wctype() function.  */
#if 0
# if !1
_GL_FUNCDECL_SYS (iswctype, int, (wint_t wc, wctype_t desc));
# endif
_GL_CXXALIAS_SYS (iswctype, int, (wint_t wc, wctype_t desc));
_GL_CXXALIASWARN (iswctype);
#elif defined GNULIB_POSIXCHECK
# undef iswctype
# if HAVE_RAW_DECL_ISWCTYPE
_GL_WARN_ON_USE (iswctype, "iswctype is unportable - "
                 "use gnulib module iswctype for portability");
# endif
#endif

#if 0 || defined __MINGW32__
_GL_CXXALIAS_RPL (towlower, wint_t, (wint_t wc));
_GL_CXXALIAS_RPL (towupper, wint_t, (wint_t wc));
#else
_GL_CXXALIAS_SYS (towlower, wint_t, (wint_t wc));
_GL_CXXALIAS_SYS (towupper, wint_t, (wint_t wc));
#endif
_GL_CXXALIASWARN (towlower);
_GL_CXXALIASWARN (towupper);

#if !1
# if !GNULIB_defined_wctrans_t
typedef void * wctrans_t;
#  define GNULIB_defined_wctrans_t 1
# endif
#endif

/* Get a descriptor for a wide character case conversion.  */
#if 0
# if !1
_GL_FUNCDECL_SYS (wctrans, wctrans_t, (const char *name));
# endif
_GL_CXXALIAS_SYS (wctrans, wctrans_t, (const char *name));
_GL_CXXALIASWARN (wctrans);
#elif defined GNULIB_POSIXCHECK
# undef wctrans
# if HAVE_RAW_DECL_WCTRANS
_GL_WARN_ON_USE (wctrans, "wctrans is unportable - "
                 "use gnulib module wctrans for portability");
# endif
#endif

/* Perform a given case conversion on a wide character.
   The argument WC must be either a wchar_t value or WEOF.
   The argument DESC must have been returned by the wctrans() function.  */
#if 0
# if !1
_GL_FUNCDECL_SYS (towctrans, wint_t, (wint_t wc, wctrans_t desc));
# endif
_GL_CXXALIAS_SYS (towctrans, wint_t, (wint_t wc, wctrans_t desc));
_GL_CXXALIASWARN (towctrans);
#elif defined GNULIB_POSIXCHECK
# undef towctrans
# if HAVE_RAW_DECL_TOWCTRANS
_GL_WARN_ON_USE (towctrans, "towctrans is unportable - "
                 "use gnulib module towctrans for portability");
# endif
#endif

_GL_INLINE_HEADER_END

#endif /* _GL_WCTYPE_H */
#endif /* _GL_WCTYPE_H */
#endif
