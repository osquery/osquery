/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <limits.h>

#include <memory>
#include <string>

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>

#include <osquery/status.h>

#ifdef DARWIN
#include <CoreFoundation/CoreFoundation.h>
#endif

namespace osquery {

template <typename T>
void do_release_boost(typename boost::shared_ptr<T> const&, T*) {}

/**
 * @brief Convert a boost::shared_ptr to a std::shared_ptr
 */
template <typename T>
typename std::shared_ptr<T> boost_to_std_shared_ptr(
    typename boost::shared_ptr<T> const& p) {
  return std::shared_ptr<T>(p.get(), boost::bind(&do_release_boost<T>, p, _1));
}

template <typename T>
void do_release_std(typename std::shared_ptr<T> const&, T*) {}

/**
 * @brief Convert a std::shared_ptr to a boost::shared_ptr
 */
template <typename T>
typename boost::shared_ptr<T> std_to_boost_shared_ptr(
    typename std::shared_ptr<T> const& p) {
  return boost::shared_ptr<T>(p.get(), boost::bind(&do_release_std<T>, p, _1));
}

/**
 * @brief Decode a base64 encoded string.
 *
 * @param encoded The encode base64 string.
 * @return Decoded string.
 */
std::string base64Decode(const std::string& encoded);

/**
 * @brief Encode a  string.
 *
 * @param A string to encode.
 * @return Encoded string.
 */
std::string base64Encode(const std::string& unencoded);

/**
 * @brief Check if a string is ASCII printable
 *
 * @param A string to check.
 * @return If the string is printable.
 */
bool isPrintable(const std::string& check);

/// Safely convert a string representation of an integer base.
inline Status safeStrtol(const std::string& rep, size_t base, long int& out) {
  char* end{nullptr};
  out = strtol(rep.c_str(), &end, base);
  if (end == nullptr || end == rep.c_str() || *end != '\0' ||
      ((out == LONG_MIN || out == LONG_MAX) && errno == ERANGE)) {
    return Status(1);
  }
  return Status(0);
}

/// Safely convert a string representation of an integer base.
inline Status safeStrtoll(const std::string& rep, size_t base, long long& out) {
  char* end{nullptr};
  out = strtoll(rep.c_str(), &end, base);
  if (end == nullptr || end == rep.c_str() || *end != '\0' ||
      ((out == LLONG_MIN || out == LLONG_MAX) && errno == ERANGE)) {
    return Status(1);
  }
  return Status(0);
}

/// Safely convert unicode escaped ASCII.
inline std::string unescapeUnicode(const std::string& escaped) {
  if (escaped.size() < 6) {
    return escaped;
  }

  std::string unescaped;
  unescaped.reserve(escaped.size());
  for (size_t i = 0; i < escaped.size(); ++i) {
    if (i < escaped.size() - 5 && '\\' == escaped[i] && 'u' == escaped[i + 1]) {
      // Assume 2-byte wide unicode.
      long value{0};
      safeStrtol(escaped.substr(i + 2, i + 6), 16, value);
      if (value < 255) {
        unescaped += static_cast<char>(value);
        i += 5;
        continue;
      }
    }
    unescaped += escaped[i];
  }
  return unescaped;
}

#ifdef DARWIN
/**
 * @brief Convert a CFStringRef to a std::string.
 */
std::string stringFromCFString(const CFStringRef& cf_string);

/**
 * @brief Convert a CFNumberRef to a std::string.
 */
std::string stringFromCFNumber(const CFDataRef& cf_number);
std::string stringFromCFNumber(const CFDataRef& cf_number, CFNumberType type);

/**
 * @brief Convert a CFAbsoluteTime to a std::string.
 */
std::string stringFromCFAbsoluteTime(const CFDataRef& cf_abstime);

std::string stringFromCFData(const CFDataRef& cf_data);
#endif

}
