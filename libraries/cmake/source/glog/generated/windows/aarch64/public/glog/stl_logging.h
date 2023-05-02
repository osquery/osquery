// Copyright (c) 2003, Google Inc.
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
//
// Stream output operators for STL containers; to be used for logging *only*.
// Inclusion of this file lets you do:
//
// list<string> x;
// LOG(INFO) << "data: " << x;
// vector<int> v1, v2;
// CHECK_EQ(v1, v2);
//
// If you want to use this header file with hash maps or slist, you
// need to define macros before including this file:
//
// - GLOG_STL_LOGGING_FOR_UNORDERED     - <unordered_map> and <unordered_set>
// - GLOG_STL_LOGGING_FOR_TR1_UNORDERED - <tr1/unordered_(map|set)>
// - GLOG_STL_LOGGING_FOR_EXT_HASH      - <ext/hash_(map|set)>
// - GLOG_STL_LOGGING_FOR_EXT_SLIST     - <ext/slist>
//

#ifndef UTIL_GTL_STL_LOGGING_INL_H_
#define UTIL_GTL_STL_LOGGING_INL_H_

#if !1
# error We do not support stl_logging for this compiler
#endif

#include <deque>
#include <list>
#include <map>
#include <ostream>
#include <set>
#include <utility>
#include <vector>

#ifdef GLOG_STL_LOGGING_FOR_UNORDERED
# include <unordered_map>
# include <unordered_set>
#endif

#ifdef GLOG_STL_LOGGING_FOR_TR1_UNORDERED
# include <tr1/unordered_map>
# include <tr1/unordered_set>
#endif

#ifdef GLOG_STL_LOGGING_FOR_EXT_HASH
# include <ext/hash_set>
# include <ext/hash_map>
#endif
#ifdef GLOG_STL_LOGGING_FOR_EXT_SLIST
# include <ext/slist>
#endif

// Forward declare these two, and define them after all the container streams
// operators so that we can recurse from pair -> container -> container -> pair
// properly.
template<class First, class Second>
std::ostream& operator<<(std::ostream& out, const std::pair<First, Second>& p);

namespace google {

template<class Iter>
void PrintSequence(std::ostream& out, Iter begin, Iter end);

}

#define OUTPUT_TWO_ARG_CONTAINER(Sequence) \
template<class T1, class T2> \
inline std::ostream& operator<<(std::ostream& out, \
                                const Sequence<T1, T2>& seq) { \
  google::PrintSequence(out, seq.begin(), seq.end()); \
  return out; \
}

OUTPUT_TWO_ARG_CONTAINER(std::vector)
OUTPUT_TWO_ARG_CONTAINER(std::deque)
OUTPUT_TWO_ARG_CONTAINER(std::list)
#ifdef GLOG_STL_LOGGING_FOR_EXT_SLIST
OUTPUT_TWO_ARG_CONTAINER(__gnu_cxx::slist)
#endif

#undef OUTPUT_TWO_ARG_CONTAINER

#define OUTPUT_THREE_ARG_CONTAINER(Sequence) \
template<class T1, class T2, class T3> \
inline std::ostream& operator<<(std::ostream& out, \
                                const Sequence<T1, T2, T3>& seq) { \
  google::PrintSequence(out, seq.begin(), seq.end()); \
  return out; \
}

OUTPUT_THREE_ARG_CONTAINER(std::set)
OUTPUT_THREE_ARG_CONTAINER(std::multiset)

#undef OUTPUT_THREE_ARG_CONTAINER

#define OUTPUT_FOUR_ARG_CONTAINER(Sequence) \
template<class T1, class T2, class T3, class T4> \
inline std::ostream& operator<<(std::ostream& out, \
                                const Sequence<T1, T2, T3, T4>& seq) { \
  google::PrintSequence(out, seq.begin(), seq.end()); \
  return out; \
}

OUTPUT_FOUR_ARG_CONTAINER(std::map)
OUTPUT_FOUR_ARG_CONTAINER(std::multimap)
#ifdef GLOG_STL_LOGGING_FOR_UNORDERED
OUTPUT_FOUR_ARG_CONTAINER(std::unordered_set)
OUTPUT_FOUR_ARG_CONTAINER(std::unordered_multiset)
#endif
#ifdef GLOG_STL_LOGGING_FOR_TR1_UNORDERED
OUTPUT_FOUR_ARG_CONTAINER(std::tr1::unordered_set)
OUTPUT_FOUR_ARG_CONTAINER(std::tr1::unordered_multiset)
#endif
#ifdef GLOG_STL_LOGGING_FOR_EXT_HASH
OUTPUT_FOUR_ARG_CONTAINER(__gnu_cxx::hash_set)
OUTPUT_FOUR_ARG_CONTAINER(__gnu_cxx::hash_multiset)
#endif

#undef OUTPUT_FOUR_ARG_CONTAINER

#define OUTPUT_FIVE_ARG_CONTAINER(Sequence) \
template<class T1, class T2, class T3, class T4, class T5> \
inline std::ostream& operator<<(std::ostream& out, \
                                const Sequence<T1, T2, T3, T4, T5>& seq) { \
  google::PrintSequence(out, seq.begin(), seq.end()); \
  return out; \
}

#ifdef GLOG_STL_LOGGING_FOR_UNORDERED
OUTPUT_FIVE_ARG_CONTAINER(std::unordered_map)
OUTPUT_FIVE_ARG_CONTAINER(std::unordered_multimap)
#endif
#ifdef GLOG_STL_LOGGING_FOR_TR1_UNORDERED
OUTPUT_FIVE_ARG_CONTAINER(std::tr1::unordered_map)
OUTPUT_FIVE_ARG_CONTAINER(std::tr1::unordered_multimap)
#endif
#ifdef GLOG_STL_LOGGING_FOR_EXT_HASH
OUTPUT_FIVE_ARG_CONTAINER(__gnu_cxx::hash_map)
OUTPUT_FIVE_ARG_CONTAINER(__gnu_cxx::hash_multimap)
#endif

#undef OUTPUT_FIVE_ARG_CONTAINER

template<class First, class Second>
inline std::ostream& operator<<(std::ostream& out,
                                const std::pair<First, Second>& p) {
  out << '(' << p.first << ", " << p.second << ')';
  return out;
}

namespace google {

template<class Iter>
inline void PrintSequence(std::ostream& out, Iter begin, Iter end) {
  // Output at most 100 elements -- appropriate if used for logging.
  for (int i = 0; begin != end && i < 100; ++i, ++begin) {
    if (i > 0) out << ' ';
    out << *begin;
  }
  if (begin != end) {
    out << " ...";
  }
}

}

// Note that this is technically undefined behavior! We are adding things into
// the std namespace for a reason though -- we are providing new operations on
// types which are themselves defined with this namespace. Without this, these
// operator overloads cannot be found via ADL. If these definitions are not
// found via ADL, they must be #included before they're used, which requires
// this header to be included before apparently independent other headers.
//
// For example, base/logging.h defines various template functions to implement
// CHECK_EQ(x, y) and stream x and y into the log in the event the check fails.
// It does so via the function template MakeCheckOpValueString:
//   template<class T>
//   void MakeCheckOpValueString(strstream* ss, const T& v) {
//     (*ss) << v;
//   }
// Because 'glog/logging.h' is included before 'glog/stl_logging.h',
// subsequent CHECK_EQ(v1, v2) for vector<...> typed variable v1 and v2 can only
// find these operator definitions via ADL.
//
// Even this solution has problems -- it may pull unintended operators into the
// namespace as well, allowing them to also be found via ADL, and creating code
// that only works with a particular order of includes. Long term, we need to
// move all of the *definitions* into namespace std, bet we need to ensure no
// one references them first. This lets us take that step. We cannot define them
// in both because that would create ambiguous overloads when both are found.
namespace std { using ::operator<<; }

#endif  // UTIL_GTL_STL_LOGGING_INL_H_
