/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <limits.h>

#include <memory>
#include <set>
#include <string>
#include <vector>

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>

#include <osquery/logger.h>
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
 * @brief Split a given string based on an optional delimiter.
 *
 * If no delimiter is supplied, the string will be split based on whitespace.
 *
 * @param s the string that you'd like to split
 * @param delim the delimiter which you'd like to split the string by
 *
 * @return a vector of strings split by delim.
 */
std::vector<std::string> split(const std::string& s,
                               const std::string& delim = "\t ");

/**
 * @brief Split a given string based on an delimiter.
 *
 * @param s the string that you'd like to split.
 * @param delim the delimiter which you'd like to split the string by.
 * @param occurrences the number of times to split by delim.
 *
 * @return a vector of strings split by delim for occurrences.
 */
std::vector<std::string> split(const std::string& s,
                               char delim,
                               size_t occurences);

/**
 * @brief In-line replace all instances of from with to.
 *
 * @param str The input/output mutable string.
 * @param from Search string
 * @param to Replace string
 */
inline void replaceAll(std::string& str,
                       const std::string& from,
                       const std::string& to) {
  if (from.empty()) {
    return;
  }

  size_t start_pos = 0;
  while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
    str.replace(start_pos, from.length(), to);
    start_pos += to.length();
  }
}

/**
 * @brief Join a vector of strings inserting a token string between elements
 *
 * @param s the vector of strings to be joined.
 * @param tok a token glue string to be inserted between elements.
 *
 * @return the joined string.
 */
std::string join(const std::vector<std::string>& s, const std::string& tok);

/**
 * @brief Join a set of strings inserting a token string between elements
 *
 * @param s the set of strings to be joined.
 * @param tok a token glue string to be inserted between elements.
 *
 * @return the joined string.
 */
std::string join(const std::set<std::string>& s, const std::string& tok);

/**
 * @brief Decode a base64 encoded string.
 *
 * @param encoded The encode base64 string.
 * @return Decoded string.
 */
std::string base64Decode(std::string encoded);

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
  out = strtol(rep.c_str(), &end, static_cast<int>(base));
  if (end == nullptr || end == rep.c_str() || *end != '\0' ||
      ((out == LONG_MIN || out == LONG_MAX) && errno == ERANGE)) {
    out = 0;
    return Status(1);
  }
  return Status(0);
}

/// Safely convert a std::wstring to an integer
inline int safe_wstr_to_int(std::wstring str) {
  //std::stoi can throw, and std::stol doesn't support std::wstring
  try {
    return std::stoi(str);
  }
  catch (const std::out_of_range&) {
    return 0;
  }
  catch (const std::invalid_argument&) {
    return 0;
  }
}

/// Safely convert a string representation of an integer base.
inline Status safeStrtoul(const std::string& rep,
                          size_t base,
                          unsigned long int& out) {
  char* end{nullptr};
  out = strtoul(rep.c_str(), &end, static_cast<int>(base));
  if (end == nullptr || end == rep.c_str() || *end != '\0' || errno == ERANGE) {
    out = 0;
    return Status(1);
  }
  return Status(0);
}

/// Safely convert a string representation of an integer base.
inline Status safeStrtoll(const std::string& rep, size_t base, long long& out) {
  char* end{nullptr};
  out = strtoll(rep.c_str(), &end, static_cast<int>(base));
  if (end == nullptr || end == rep.c_str() || *end != '\0' ||
      ((out == LLONG_MIN || out == LLONG_MAX) && errno == ERANGE)) {
    out = 0;
    return Status(1);
  }
  return Status(0);
}

/// Safely convert a string representation of an integer base.
inline Status safeStrtoi(const std::string& rep, int base, int& out) {
  try {
    out = std::stoi(rep, 0, base);
  } catch (const std::invalid_argument& ia) {
    return Status(
        1, std::string("If no conversion could be performed. ") + ia.what());
  } catch (const std::out_of_range& oor) {
    return Status(1,
                  std::string("Value read is out of the range of representable "
                              "values by an int. ") +
                      oor.what());
  }
  return Status(0);
}

/// Safely convert a string representation of an integer base.
inline Status safeStrtoull(const std::string& rep,
                           size_t base,
                           unsigned long long& out) {
  char* end{nullptr};
  out = strtoull(rep.c_str(), &end, static_cast<int>(base));
  if (end == nullptr || end == rep.c_str() || *end != '\0' ||
      (out == ULLONG_MAX && errno == ERANGE)) {
    out = 0;
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
      Status stat = safeStrtol(escaped.substr(i + 2, 4), 16, value);
      if (!stat.ok()) {
        LOG(WARNING) << "Unescaping a string with length: " << escaped.size()
                     << " failed at: " << i;
        return "";
      }
      if (value < 255) {
        unescaped += static_cast<char>(value);
        i += 5;
        continue;
      }
    } else if (i < escaped.size() - 1 && '\\' == escaped[i] &&
               '\\' == escaped[i + 1]) {
      // In the case of \\users 'sers' is not a unicode character
      // If we see \\ we should skip them and we do this by adding
      // an extra jump forward.
      unescaped += escaped[i];
      ++i;
    }
    unescaped += escaped[i];
  }
  return unescaped;
}

/**
 * @brief In-line helper function for use with utf8StringSize
 */
template <typename _Iterator1, typename _Iterator2>
inline size_t incUtf8StringIterator(_Iterator1& it, const _Iterator2& last) {
  if (it == last) {
    return 0;
  }

  size_t res = 1;
  for (++it; last != it; ++it, ++res) {
    unsigned char c = *it;
    if (!(c & 0x80) || ((c & 0xC0) == 0xC0)) {
      break;
    }
  }

  return res;
}

/**
 * @brief Get the length of a UTF-8 string
 *
 * @param str The UTF-8 string
 *
 * @return the length of the string
 */
inline size_t utf8StringSize(const std::string& str) {
  size_t res = 0;
  std::string::const_iterator it = str.begin();
  for (; it != str.end(); incUtf8StringIterator(it, str.end())) {
    res++;
  }

  return res;
}

/*
 * @brief Request a SHA1 hash from the contents of a buffer.
 *
 * @param buffer A caller-controlled buffer (already allocated).
 * @param size The length of the controlled buffer.
 * @return A string (hex) representation of the hash digest.
 */
std::string getBufferSHA1(const char* buffer, size_t size);

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
