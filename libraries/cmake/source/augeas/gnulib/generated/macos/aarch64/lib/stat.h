/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
/* Provide a more complete sys/stat.h header file.
   Copyright (C) 2005-2019 Free Software Foundation, Inc.

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

/* Written by Eric Blake, Paul Eggert, and Jim Meyering.  */

/* This file is supposed to be used on platforms where <sys/stat.h> is
   incomplete.  It is intended to provide definitions and prototypes
   needed by an application.  Start with what the system provides.  */

#if __GNUC__ >= 3
#pragma GCC system_header
#endif


#if defined __need_system_sys_stat_h
/* Special invocation convention.  */

#include_next <sys/stat.h>

#else
/* Normal invocation convention.  */

#ifndef _GL_SYS_STAT_H

/* Get nlink_t.
   May also define off_t to a 64-bit type on native Windows.  */
#include <sys/types.h>

/* Get struct timespec.  */
#include <time.h>

/* The include_next requires a split double-inclusion guard.  */
#include_next <sys/stat.h>

#ifndef _GL_SYS_STAT_H
#define _GL_SYS_STAT_H

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

/* Before doing "#define mknod rpl_mknod" below, we need to include all
   headers that may declare mknod().  OS/2 kLIBC declares mknod() in
   <unistd.h>, not in <sys/stat.h>.  */
#ifdef __KLIBC__
# include <unistd.h>
#endif

/* Before doing "#define mkdir rpl_mkdir" below, we need to include all
   headers that may declare mkdir().  Native Windows platforms declare mkdir
   in <io.h> and/or <direct.h>, not in <sys/stat.h>.  */
#if defined _WIN32 && ! defined __CYGWIN__
# include <io.h>     /* mingw32, mingw64 */
# include <direct.h> /* mingw64, MSVC 9 */
#endif

/* Native Windows platforms declare umask() in <io.h>.  */
#if 0 && (defined _WIN32 && ! defined __CYGWIN__)
# include <io.h>
#endif

/* Large File Support on native Windows.  */
#if 0
# define stat _stati64
#endif

/* Optionally, override 'struct stat' on native Windows.  */
#if 0

# undef stat
# if 1
#  define stat rpl_stat
# else
   /* Provoke a clear link error if stat() is used as a function and
      module 'stat' is not in use.  */
#  define stat stat_used_without_requesting_gnulib_module_stat
# endif

# if !GNULIB_defined_struct_stat
struct stat
{
  dev_t st_dev;
  ino_t st_ino;
  mode_t st_mode;
  nlink_t st_nlink;
#  if 0
  uid_t st_uid;
#  else /* uid_t is not defined by default on native Windows.  */
  short st_uid;
#  endif
#  if 0
  gid_t st_gid;
#  else /* gid_t is not defined by default on native Windows.  */
  short st_gid;
#  endif
  dev_t st_rdev;
  off_t st_size;
#  if 0
  blksize_t st_blksize;
  blkcnt_t st_blocks;
#  endif

#  if 0
  struct timespec st_atim;
  struct timespec st_mtim;
  struct timespec st_ctim;
#  else
  time_t st_atime;
  time_t st_mtime;
  time_t st_ctime;
#  endif
};
#  if 0
#   define st_atime st_atim.tv_sec
#   define st_mtime st_mtim.tv_sec
#   define st_ctime st_ctim.tv_sec
    /* Indicator, for gnulib internal purposes.  */
#   define _GL_WINDOWS_STAT_TIMESPEC 1
#  endif
#  define GNULIB_defined_struct_stat 1
# endif

/* Other possible values of st_mode.  */
# if 0
#  define _S_IFBLK  0x6000
# endif
# if 0
#  define _S_IFLNK  0xA000
# endif
# if 0
#  define _S_IFSOCK 0xC000
# endif

#endif

#ifndef S_IFIFO
# ifdef _S_IFIFO
#  define S_IFIFO _S_IFIFO
# endif
#endif

#ifndef S_IFMT
# define S_IFMT 0170000
#endif

#if STAT_MACROS_BROKEN
# undef S_ISBLK
# undef S_ISCHR
# undef S_ISDIR
# undef S_ISFIFO
# undef S_ISLNK
# undef S_ISNAM
# undef S_ISMPB
# undef S_ISMPC
# undef S_ISNWK
# undef S_ISREG
# undef S_ISSOCK
#endif

#ifndef S_ISBLK
# ifdef S_IFBLK
#  define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
# else
#  define S_ISBLK(m) 0
# endif
#endif

#ifndef S_ISCHR
# ifdef S_IFCHR
#  define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
# else
#  define S_ISCHR(m) 0
# endif
#endif

#ifndef S_ISDIR
# ifdef S_IFDIR
#  define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
# else
#  define S_ISDIR(m) 0
# endif
#endif

#ifndef S_ISDOOR /* Solaris 2.5 and up */
# define S_ISDOOR(m) 0
#endif

#ifndef S_ISFIFO
# ifdef S_IFIFO
#  define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
# else
#  define S_ISFIFO(m) 0
# endif
#endif

#ifndef S_ISLNK
# ifdef S_IFLNK
#  define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
# else
#  define S_ISLNK(m) 0
# endif
#endif

#ifndef S_ISMPB /* V7 */
# ifdef S_IFMPB
#  define S_ISMPB(m) (((m) & S_IFMT) == S_IFMPB)
#  define S_ISMPC(m) (((m) & S_IFMT) == S_IFMPC)
# else
#  define S_ISMPB(m) 0
#  define S_ISMPC(m) 0
# endif
#endif

#ifndef S_ISMPX /* AIX */
# define S_ISMPX(m) 0
#endif

#ifndef S_ISNAM /* Xenix */
# ifdef S_IFNAM
#  define S_ISNAM(m) (((m) & S_IFMT) == S_IFNAM)
# else
#  define S_ISNAM(m) 0
# endif
#endif

#ifndef S_ISNWK /* HP/UX */
# ifdef S_IFNWK
#  define S_ISNWK(m) (((m) & S_IFMT) == S_IFNWK)
# else
#  define S_ISNWK(m) 0
# endif
#endif

#ifndef S_ISPORT /* Solaris 10 and up */
# define S_ISPORT(m) 0
#endif

#ifndef S_ISREG
# ifdef S_IFREG
#  define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
# else
#  define S_ISREG(m) 0
# endif
#endif

#ifndef S_ISSOCK
# ifdef S_IFSOCK
#  define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
# else
#  define S_ISSOCK(m) 0
# endif
#endif


#ifndef S_TYPEISMQ
# define S_TYPEISMQ(p) 0
#endif

#ifndef S_TYPEISTMO
# define S_TYPEISTMO(p) 0
#endif


#ifndef S_TYPEISSEM
# ifdef S_INSEM
#  define S_TYPEISSEM(p) (S_ISNAM ((p)->st_mode) && (p)->st_rdev == S_INSEM)
# else
#  define S_TYPEISSEM(p) 0
# endif
#endif

#ifndef S_TYPEISSHM
# ifdef S_INSHD
#  define S_TYPEISSHM(p) (S_ISNAM ((p)->st_mode) && (p)->st_rdev == S_INSHD)
# else
#  define S_TYPEISSHM(p) 0
# endif
#endif

/* high performance ("contiguous data") */
#ifndef S_ISCTG
# define S_ISCTG(p) 0
#endif

/* Cray DMF (data migration facility): off line, with data  */
#ifndef S_ISOFD
# define S_ISOFD(p) 0
#endif

/* Cray DMF (data migration facility): off line, with no data  */
#ifndef S_ISOFL
# define S_ISOFL(p) 0
#endif

/* 4.4BSD whiteout */
#ifndef S_ISWHT
# define S_ISWHT(m) 0
#endif

/* If any of the following are undefined,
   define them to their de facto standard values.  */
#if !S_ISUID
# define S_ISUID 04000
#endif
#if !S_ISGID
# define S_ISGID 02000
#endif

/* S_ISVTX is a common extension to POSIX.  */
#ifndef S_ISVTX
# define S_ISVTX 01000
#endif

#if !S_IRUSR && S_IREAD
# define S_IRUSR S_IREAD
#endif
#if !S_IRUSR
# define S_IRUSR 00400
#endif
#if !S_IRGRP
# define S_IRGRP (S_IRUSR >> 3)
#endif
#if !S_IROTH
# define S_IROTH (S_IRUSR >> 6)
#endif

#if !S_IWUSR && S_IWRITE
# define S_IWUSR S_IWRITE
#endif
#if !S_IWUSR
# define S_IWUSR 00200
#endif
#if !S_IWGRP
# define S_IWGRP (S_IWUSR >> 3)
#endif
#if !S_IWOTH
# define S_IWOTH (S_IWUSR >> 6)
#endif

#if !S_IXUSR && S_IEXEC
# define S_IXUSR S_IEXEC
#endif
#if !S_IXUSR
# define S_IXUSR 00100
#endif
#if !S_IXGRP
# define S_IXGRP (S_IXUSR >> 3)
#endif
#if !S_IXOTH
# define S_IXOTH (S_IXUSR >> 6)
#endif

#if !S_IRWXU
# define S_IRWXU (S_IRUSR | S_IWUSR | S_IXUSR)
#endif
#if !S_IRWXG
# define S_IRWXG (S_IRGRP | S_IWGRP | S_IXGRP)
#endif
#if !S_IRWXO
# define S_IRWXO (S_IROTH | S_IWOTH | S_IXOTH)
#endif

/* S_IXUGO is a common extension to POSIX.  */
#if !S_IXUGO
# define S_IXUGO (S_IXUSR | S_IXGRP | S_IXOTH)
#endif

#ifndef S_IRWXUGO
# define S_IRWXUGO (S_IRWXU | S_IRWXG | S_IRWXO)
#endif

/* Macros for futimens and utimensat.  */
#ifndef UTIME_NOW
# define UTIME_NOW (-1)
# define UTIME_OMIT (-2)
#endif


#if 0
# if !1
_GL_FUNCDECL_SYS (fchmodat, int,
                  (int fd, char const *file, mode_t mode, int flag)
                  _GL_ARG_NONNULL ((2)));
# endif
_GL_CXXALIAS_SYS (fchmodat, int,
                  (int fd, char const *file, mode_t mode, int flag));
_GL_CXXALIASWARN (fchmodat);
#elif defined GNULIB_POSIXCHECK
# undef fchmodat
# if HAVE_RAW_DECL_FCHMODAT
_GL_WARN_ON_USE (fchmodat, "fchmodat is not portable - "
                 "use gnulib module openat for portability");
# endif
#endif


#if IN_AUGEAS_GNULIB_TESTS
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef fstat
#   define fstat rpl_fstat
#  endif
_GL_FUNCDECL_RPL (fstat, int, (int fd, struct stat *buf) _GL_ARG_NONNULL ((2)));
_GL_CXXALIAS_RPL (fstat, int, (int fd, struct stat *buf));
# else
_GL_CXXALIAS_SYS (fstat, int, (int fd, struct stat *buf));
# endif
_GL_CXXALIASWARN (fstat);
#elif 0
# undef fstat
# define fstat fstat_used_without_requesting_gnulib_module_fstat
#elif 0
/* Above, we define stat to _stati64.  */
# define fstat _fstati64
#elif defined GNULIB_POSIXCHECK
# undef fstat
# if HAVE_RAW_DECL_FSTAT
_GL_WARN_ON_USE (fstat, "fstat has portability problems - "
                 "use gnulib module fstat for portability");
# endif
#endif


#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef fstatat
#   define fstatat rpl_fstatat
#  endif
_GL_FUNCDECL_RPL (fstatat, int,
                  (int fd, char const *name, struct stat *st, int flags)
                  _GL_ARG_NONNULL ((2, 3)));
_GL_CXXALIAS_RPL (fstatat, int,
                  (int fd, char const *name, struct stat *st, int flags));
# else
#  if !1
_GL_FUNCDECL_SYS (fstatat, int,
                  (int fd, char const *name, struct stat *st, int flags)
                  _GL_ARG_NONNULL ((2, 3)));
#  endif
_GL_CXXALIAS_SYS (fstatat, int,
                  (int fd, char const *name, struct stat *st, int flags));
# endif
_GL_CXXALIASWARN (fstatat);
#elif 0
# undef fstatat
# define fstatat fstatat_used_without_requesting_gnulib_module_fstatat
#elif defined GNULIB_POSIXCHECK
# undef fstatat
# if HAVE_RAW_DECL_FSTATAT
_GL_WARN_ON_USE (fstatat, "fstatat is not portable - "
                 "use gnulib module openat for portability");
# endif
#endif


#if 0
/* Use the rpl_ prefix also on Solaris <= 9, because on Solaris 9 our futimens
   implementation relies on futimesat, which on Solaris 10 makes an invocation
   to futimens that is meant to invoke the libc's futimens(), not gnulib's
   futimens().  */
# if 0 || (!1 && defined __sun)
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef futimens
#   define futimens rpl_futimens
#  endif
_GL_FUNCDECL_RPL (futimens, int, (int fd, struct timespec const times[2]));
_GL_CXXALIAS_RPL (futimens, int, (int fd, struct timespec const times[2]));
# else
#  if !1
_GL_FUNCDECL_SYS (futimens, int, (int fd, struct timespec const times[2]));
#  endif
_GL_CXXALIAS_SYS (futimens, int, (int fd, struct timespec const times[2]));
# endif
# if 1
_GL_CXXALIASWARN (futimens);
# endif
#elif defined GNULIB_POSIXCHECK
# undef futimens
# if HAVE_RAW_DECL_FUTIMENS
_GL_WARN_ON_USE (futimens, "futimens is not portable - "
                 "use gnulib module futimens for portability");
# endif
#endif


#if 0
/* Change the mode of FILENAME to MODE, without dereferencing it if FILENAME
   denotes a symbolic link.  */
# if !1
/* The lchmod replacement follows symbolic links.  Callers should take
   this into account; lchmod should be applied only to arguments that
   are known to not be symbolic links.  On hosts that lack lchmod,
   this can lead to race conditions between the check and the
   invocation of lchmod, but we know of no workarounds that are
   reliable in general.  You might try requesting support for lchmod
   from your operating system supplier.  */
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   define lchmod chmod
#  endif
/* Need to cast, because on mingw, the second parameter of chmod is
                                                int mode.  */
_GL_CXXALIAS_RPL_CAST_1 (lchmod, chmod, int,
                         (const char *filename, mode_t mode));
# else
#  if 0 /* assume already declared */
_GL_FUNCDECL_SYS (lchmod, int, (const char *filename, mode_t mode)
                               _GL_ARG_NONNULL ((1)));
#  endif
_GL_CXXALIAS_SYS (lchmod, int, (const char *filename, mode_t mode));
# endif
# if 1
_GL_CXXALIASWARN (lchmod);
# endif
#elif defined GNULIB_POSIXCHECK
# undef lchmod
# if HAVE_RAW_DECL_LCHMOD
_GL_WARN_ON_USE (lchmod, "lchmod is unportable - "
                 "use gnulib module lchmod for portability");
# endif
#endif


#if 1
# if ! 1
/* mingw does not support symlinks, therefore it does not have lstat.  But
   without links, stat does just fine.  */
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   define lstat stat
#  endif
_GL_CXXALIAS_RPL_1 (lstat, stat, int, (const char *name, struct stat *buf));
# elif 1
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef lstat
#   define lstat rpl_lstat
#  endif
_GL_FUNCDECL_RPL (lstat, int, (const char *name, struct stat *buf)
                              _GL_ARG_NONNULL ((1, 2)));
_GL_CXXALIAS_RPL (lstat, int, (const char *name, struct stat *buf));
# else
_GL_CXXALIAS_SYS (lstat, int, (const char *name, struct stat *buf));
# endif
# if 1
_GL_CXXALIASWARN (lstat);
# endif
#elif 0
# undef lstat
# define lstat lstat_used_without_requesting_gnulib_module_lstat
#elif defined GNULIB_POSIXCHECK
# undef lstat
# if HAVE_RAW_DECL_LSTAT
_GL_WARN_ON_USE (lstat, "lstat is unportable - "
                 "use gnulib module lstat for portability");
# endif
#endif


#if 1
# if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#  undef mkdir
#  define mkdir rpl_mkdir
# endif
_GL_FUNCDECL_RPL (mkdir, int, (char const *name, mode_t mode)
                              _GL_ARG_NONNULL ((1)));
_GL_CXXALIAS_RPL (mkdir, int, (char const *name, mode_t mode));
#else
/* mingw's _mkdir() function has 1 argument, but we pass 2 arguments.
   Additionally, it declares _mkdir (and depending on compile flags, an
   alias mkdir), only in the nonstandard includes <direct.h> and <io.h>,
   which are included above.  */
# if defined _WIN32 && ! defined __CYGWIN__

#  if !GNULIB_defined_rpl_mkdir
static int
rpl_mkdir (char const *name, mode_t mode)
{
  return _mkdir (name);
}
#   define GNULIB_defined_rpl_mkdir 1
#  endif

#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   define mkdir rpl_mkdir
#  endif
_GL_CXXALIAS_RPL (mkdir, int, (char const *name, mode_t mode));
# else
_GL_CXXALIAS_SYS (mkdir, int, (char const *name, mode_t mode));
# endif
#endif
_GL_CXXALIASWARN (mkdir);


#if 0
# if !1
_GL_FUNCDECL_SYS (mkdirat, int, (int fd, char const *file, mode_t mode)
                                _GL_ARG_NONNULL ((2)));
# endif
_GL_CXXALIAS_SYS (mkdirat, int, (int fd, char const *file, mode_t mode));
_GL_CXXALIASWARN (mkdirat);
#elif defined GNULIB_POSIXCHECK
# undef mkdirat
# if HAVE_RAW_DECL_MKDIRAT
_GL_WARN_ON_USE (mkdirat, "mkdirat is not portable - "
                 "use gnulib module openat for portability");
# endif
#endif


#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef mkfifo
#   define mkfifo rpl_mkfifo
#  endif
_GL_FUNCDECL_RPL (mkfifo, int, (char const *file, mode_t mode)
                               _GL_ARG_NONNULL ((1)));
_GL_CXXALIAS_RPL (mkfifo, int, (char const *file, mode_t mode));
# else
#  if !1
_GL_FUNCDECL_SYS (mkfifo, int, (char const *file, mode_t mode)
                               _GL_ARG_NONNULL ((1)));
#  endif
_GL_CXXALIAS_SYS (mkfifo, int, (char const *file, mode_t mode));
# endif
_GL_CXXALIASWARN (mkfifo);
#elif defined GNULIB_POSIXCHECK
# undef mkfifo
# if HAVE_RAW_DECL_MKFIFO
_GL_WARN_ON_USE (mkfifo, "mkfifo is not portable - "
                 "use gnulib module mkfifo for portability");
# endif
#endif


#if 0
# if !1
_GL_FUNCDECL_SYS (mkfifoat, int, (int fd, char const *file, mode_t mode)
                                 _GL_ARG_NONNULL ((2)));
# endif
_GL_CXXALIAS_SYS (mkfifoat, int, (int fd, char const *file, mode_t mode));
_GL_CXXALIASWARN (mkfifoat);
#elif defined GNULIB_POSIXCHECK
# undef mkfifoat
# if HAVE_RAW_DECL_MKFIFOAT
_GL_WARN_ON_USE (mkfifoat, "mkfifoat is not portable - "
                 "use gnulib module mkfifoat for portability");
# endif
#endif


#if 0
# if 0
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef mknod
#   define mknod rpl_mknod
#  endif
_GL_FUNCDECL_RPL (mknod, int, (char const *file, mode_t mode, dev_t dev)
                              _GL_ARG_NONNULL ((1)));
_GL_CXXALIAS_RPL (mknod, int, (char const *file, mode_t mode, dev_t dev));
# else
#  if !1
_GL_FUNCDECL_SYS (mknod, int, (char const *file, mode_t mode, dev_t dev)
                              _GL_ARG_NONNULL ((1)));
#  endif
/* Need to cast, because on OSF/1 5.1, the third parameter is '...'.  */
_GL_CXXALIAS_SYS_CAST (mknod, int, (char const *file, mode_t mode, dev_t dev));
# endif
_GL_CXXALIASWARN (mknod);
#elif defined GNULIB_POSIXCHECK
# undef mknod
# if HAVE_RAW_DECL_MKNOD
_GL_WARN_ON_USE (mknod, "mknod is not portable - "
                 "use gnulib module mknod for portability");
# endif
#endif


#if 0
# if !1
_GL_FUNCDECL_SYS (mknodat, int,
                  (int fd, char const *file, mode_t mode, dev_t dev)
                  _GL_ARG_NONNULL ((2)));
# endif
_GL_CXXALIAS_SYS (mknodat, int,
                  (int fd, char const *file, mode_t mode, dev_t dev));
_GL_CXXALIASWARN (mknodat);
#elif defined GNULIB_POSIXCHECK
# undef mknodat
# if HAVE_RAW_DECL_MKNODAT
_GL_WARN_ON_USE (mknodat, "mknodat is not portable - "
                 "use gnulib module mkfifoat for portability");
# endif
#endif


#if 1
# if 1
#  if !0
    /* We can't use the object-like #define stat rpl_stat, because of
       struct stat.  This means that rpl_stat will not be used if the user
       does (stat)(a,b).  Oh well.  */
#   if defined _AIX && defined stat && defined _LARGE_FILES
     /* With _LARGE_FILES defined, AIX (only) defines stat to stat64,
        so we have to replace stat64() instead of stat(). */
#    undef stat64
#    define stat64(name, st) rpl_stat (name, st)
#   elif 0
     /* Above, we define stat to _stati64.  */
#    if defined __MINGW32__ && defined _stati64
#     ifndef _USE_32BIT_TIME_T
       /* The system headers define _stati64 to _stat64.  */
#      undef _stat64
#      define _stat64(name, st) rpl_stat (name, st)
#     endif
#    elif defined _MSC_VER && defined _stati64
#     ifdef _USE_32BIT_TIME_T
       /* The system headers define _stati64 to _stat32i64.  */
#      undef _stat32i64
#      define _stat32i64(name, st) rpl_stat (name, st)
#     else
       /* The system headers define _stati64 to _stat64.  */
#      undef _stat64
#      define _stat64(name, st) rpl_stat (name, st)
#     endif
#    else
#     undef _stati64
#     define _stati64(name, st) rpl_stat (name, st)
#    endif
#   elif defined __MINGW32__ && defined stat
#    ifdef _USE_32BIT_TIME_T
      /* The system headers define stat to _stat32i64.  */
#     undef _stat32i64
#     define _stat32i64(name, st) rpl_stat (name, st)
#    else
      /* The system headers define stat to _stat64.  */
#     undef _stat64
#     define _stat64(name, st) rpl_stat (name, st)
#    endif
#   elif defined _MSC_VER && defined stat
#    ifdef _USE_32BIT_TIME_T
      /* The system headers define stat to _stat32.  */
#     undef _stat32
#     define _stat32(name, st) rpl_stat (name, st)
#    else
      /* The system headers define stat to _stat64i32.  */
#     undef _stat64i32
#     define _stat64i32(name, st) rpl_stat (name, st)
#    endif
#   else /* !(_AIX || __MINGW32__ || _MSC_VER) */
#    undef stat
#    define stat(name, st) rpl_stat (name, st)
#   endif /* !_LARGE_FILES */
#  endif /* !0 */
_GL_EXTERN_C int stat (const char *name, struct stat *buf)
                      _GL_ARG_NONNULL ((1, 2));
# endif
#elif 0
/* see above:
  #define stat stat_used_without_requesting_gnulib_module_stat
 */
#elif defined GNULIB_POSIXCHECK
# undef stat
# if HAVE_RAW_DECL_STAT
_GL_WARN_ON_USE (stat, "stat is unportable - "
                 "use gnulib module stat for portability");
# endif
#endif


#if 0
/* Use the rpl_ prefix also on Solaris <= 9, because on Solaris 9 our utimensat
   implementation relies on futimesat, which on Solaris 10 makes an invocation
   to utimensat that is meant to invoke the libc's utimensat(), not gnulib's
   utimensat().  */
# if 0 || (!1 && defined __sun)
#  if !(defined __cplusplus && defined GNULIB_NAMESPACE)
#   undef utimensat
#   define utimensat rpl_utimensat
#  endif
_GL_FUNCDECL_RPL (utimensat, int, (int fd, char const *name,
                                   struct timespec const times[2], int flag)
                                  _GL_ARG_NONNULL ((2)));
_GL_CXXALIAS_RPL (utimensat, int, (int fd, char const *name,
                                   struct timespec const times[2], int flag));
# else
#  if !1
_GL_FUNCDECL_SYS (utimensat, int, (int fd, char const *name,
                                   struct timespec const times[2], int flag)
                                  _GL_ARG_NONNULL ((2)));
#  endif
_GL_CXXALIAS_SYS (utimensat, int, (int fd, char const *name,
                                   struct timespec const times[2], int flag));
# endif
# if 1
_GL_CXXALIASWARN (utimensat);
# endif
#elif defined GNULIB_POSIXCHECK
# undef utimensat
# if HAVE_RAW_DECL_UTIMENSAT
_GL_WARN_ON_USE (utimensat, "utimensat is not portable - "
                 "use gnulib module utimensat for portability");
# endif
#endif


#endif /* _GL_SYS_STAT_H */
#endif /* _GL_SYS_STAT_H */
#endif
