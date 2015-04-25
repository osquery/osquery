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

#include <memory>

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>

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

std::string stringFromCFData(const CFDataRef& cf_data);
#endif
}
