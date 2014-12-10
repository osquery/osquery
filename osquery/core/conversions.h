// Copyright 2004-present Facebook. All Rights Reserved.

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

#ifdef DARWIN
/// Get a std::string from a CStringRef.
std::string stringFromCFString(const CFStringRef cf_string);
std::string stringFromCFNumber(const CFDataRef& cf_number);
#endif

}
