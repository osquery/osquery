// Copyright (c) 1999, Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// ---
//
// Revamped and reorganized by Craig Silverstein
//
// This is the file that should be included by any file which declares
// command line flag.

#ifndef GFLAGS_DECLARE_H_
#define GFLAGS_DECLARE_H_


// ---------------------------------------------------------------------------
// Namespace of gflags library symbols.
#define GFLAGS_NAMESPACE gflags

// ---------------------------------------------------------------------------
// Windows DLL import/export.

// Whether gflags library is a DLL.
//
// Set to 1 by default when the shared gflags library was built on Windows.
// Must be overwritten when this header file is used with the optionally also
// built static library instead; set by CMake's INTERFACE_COMPILE_DEFINITIONS.
#ifndef GFLAGS_IS_A_DLL
#  define GFLAGS_IS_A_DLL 0
#endif

// We always want to import the symbols of the gflags library.
#ifndef GFLAGS_DLL_DECL
#  if GFLAGS_IS_A_DLL && defined(_MSC_VER)
#    define GFLAGS_DLL_DECL __declspec(dllimport)
#  elif defined(__GNUC__) && __GNUC__ >= 4
#    define GFLAGS_DLL_DECL __attribute__((visibility("default")))
#  else
#    define GFLAGS_DLL_DECL
#  endif
#endif

// We always want to import variables declared in user code.
#ifndef GFLAGS_DLL_DECLARE_FLAG
#  if GFLAGS_IS_A_DLL && defined(_MSC_VER)
#    define GFLAGS_DLL_DECLARE_FLAG __declspec(dllimport)
#  elif defined(__GNUC__) && __GNUC__ >= 4
#    define GFLAGS_DLL_DECLARE_FLAG __attribute__((visibility("default")))
#  else
#    define GFLAGS_DLL_DECLARE_FLAG
#  endif
#endif

// ---------------------------------------------------------------------------
// Flag types
#include <string>
#if 1
#  include <stdint.h>                   // the normal place uint32_t is defined
#elif 1
#  include <sys/types.h>                // the normal place u_int32_t is defined
#elif 1
#  include <inttypes.h>                 // a third place for uint32_t or u_int32_t
#endif

namespace GFLAGS_NAMESPACE {

#if 1 // C99
typedef int32_t          int32;
typedef uint32_t         uint32;
typedef int64_t          int64;
typedef uint64_t         uint64;
#elif 0 // BSD
typedef int32_t          int32;
typedef u_int32_t        uint32;
typedef int64_t          int64;
typedef u_int64_t        uint64;
#elif 0 // Windows
typedef __int32          int32;
typedef unsigned __int32 uint32;
typedef __int64          int64;
typedef unsigned __int64 uint64;
#else
#  error Do not know how to define a 32-bit integer quantity on your system
#endif

} // namespace GFLAGS_NAMESPACE


namespace fLS {

// The meaning of "string" might be different between now and when the
// macros below get invoked (e.g., if someone is experimenting with
// other string implementations that get defined after this file is
// included).  Save the current meaning now and use it in the macros.
typedef std::string clstring;

} // namespace fLS


#define DECLARE_VARIABLE(type, shorttype, name) \
  /* We always want to import declared variables, dll or no */ \
  namespace fL##shorttype { extern GFLAGS_DLL_DECLARE_FLAG type FLAGS_##name; } \
  using fL##shorttype::FLAGS_##name

#define DECLARE_bool(name) \
  DECLARE_VARIABLE(bool, B, name)

#define DECLARE_int32(name) \
  DECLARE_VARIABLE(::GFLAGS_NAMESPACE::int32, I, name)

#define DECLARE_uint32(name) \
  DECLARE_VARIABLE(::GFLAGS_NAMESPACE::uint32, U, name)

#define DECLARE_int64(name) \
  DECLARE_VARIABLE(::GFLAGS_NAMESPACE::int64, I64, name)

#define DECLARE_uint64(name) \
  DECLARE_VARIABLE(::GFLAGS_NAMESPACE::uint64, U64, name)

#define DECLARE_double(name) \
  DECLARE_VARIABLE(double, D, name)

#define DECLARE_string(name) \
  /* We always want to import declared variables, dll or no */ \
  namespace fLS { \
  extern GFLAGS_DLL_DECLARE_FLAG ::fLS::clstring& FLAGS_##name; \
  } \
  using fLS::FLAGS_##name


#endif  // GFLAGS_DECLARE_H_
