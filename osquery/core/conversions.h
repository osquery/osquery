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

#include <string>
#include <type_traits>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/core/demangle.hpp>

#include <osquery/expected.h>
#include <osquery/logger.h>
#include <osquery/status.h>

#ifdef DARWIN
#include <CoreFoundation/CoreFoundation.h>
#endif

namespace osquery {

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
 * @brief Join a vector of strings inserting a token string between elements
 *
 * @param s the vector of strings to be joined.
 * @param tok a token glue string to be inserted between elements.
 *
 * @return the joined string.
 */
template <typename SequenceType>
inline std::string join(const SequenceType& s, const std::string& tok) {
  return boost::algorithm::join(s, tok);
}

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

enum class ConversionError {
  InvalidArgument,
  OutOfRange,
  Unknown,
};

template <typename ToType, typename FromType>
inline typename std::enable_if<
    std::is_same<ToType,
                 typename std::remove_cv<typename std::remove_reference<
                     FromType>::type>::type>::value,
    Expected<ToType, ConversionError>>::type
tryTo(FromType&& from) {
  return std::forward<FromType>(from);
}

namespace impl {

template <typename Type>
struct IsStlString {
  static constexpr bool value = std::is_same<Type, std::string>::value ||
                                std::is_same<Type, std::wstring>::value;
};

template <typename Type>
struct IsInteger {
  static constexpr bool value =
      std::is_integral<Type>::value && !std::is_same<Type, bool>::value;
};

template <typename FromType,
          typename ToType,
          typename IntType,
          typename =
              typename std::enable_if<std::is_same<ToType, IntType>::value &&
                                          IsStlString<FromType>::value,
                                      IntType>::type>
struct IsConversionFromStringToIntEnabledFor {
  using type = IntType;
};

template <typename ToType, typename FromType>
inline
    typename IsConversionFromStringToIntEnabledFor<FromType, ToType, int>::type
    throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoi(from, &pos, base);
}

template <typename ToType, typename FromType>
inline typename IsConversionFromStringToIntEnabledFor<FromType,
                                                      ToType,
                                                      long int>::type
throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stol(from, &pos, base);
}

template <typename ToType, typename FromType>
inline typename IsConversionFromStringToIntEnabledFor<FromType,
                                                      ToType,
                                                      long long int>::type
throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoll(from, &pos, base);
}

template <typename ToType, typename FromType>
inline typename IsConversionFromStringToIntEnabledFor<FromType,
                                                      ToType,
                                                      unsigned int>::type
throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoul(from, &pos, base);
}

template <typename ToType, typename FromType>
inline typename IsConversionFromStringToIntEnabledFor<FromType,
                                                      ToType,
                                                      unsigned long int>::type
throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoul(from, &pos, base);
}

template <typename ToType, typename FromType>
inline
    typename IsConversionFromStringToIntEnabledFor<FromType,
                                                   ToType,
                                                   unsigned long long int>::type
    throwingStringToInt(const FromType& from, const int base) {
  auto pos = std::size_t{};
  return std::stoull(from, &pos, base);
}

Expected<bool, ConversionError> stringToBool(std::string from);

} // namespace impl

/**
 * Template tryTo for [w]string to integer conversion
 */
template <typename ToType, typename FromType>
inline typename std::enable_if<impl::IsInteger<ToType>::value &&
                                   impl::IsStlString<FromType>::value,
                               Expected<ToType, ConversionError>>::type
tryTo(const FromType& from, const int base = 10) noexcept {
  try {
    return impl::throwingStringToInt<ToType>(from, base);
  } catch (const std::invalid_argument& ia) {
    return createError(ConversionError::InvalidArgument,
                       "If no conversion could be performed. ")
           << ia.what();
  } catch (const std::out_of_range& oor) {
    return createError(ConversionError::OutOfRange,
                       "Value read is out of the range of representable values "
                       "by an int. ")
           << oor.what();
  } catch (...) {
    return createError(ConversionError::Unknown,
                       "Unknown error during conversion ")
           << boost::core::demangle(typeid(FromType).name()) << " to "
           << boost::core::demangle(typeid(ToType).name()) << " base " << base;
  }
}

/**
 * Parsing general representation of boolean value in string.
 *     "1" : true
 *     "0" : false
 *     "y" : true
 *   "yes" : true
 *     "n" : false
 *    "no" : false
 *   ... and so on
 *   For the full list of possible valid values @see stringToBool definition
 */
template <typename ToType>
inline typename std::enable_if<std::is_same<ToType, bool>::value,
                               Expected<ToType, ConversionError>>::type
tryTo(std::string from) {
  return impl::stringToBool(std::move(from));
}
}
