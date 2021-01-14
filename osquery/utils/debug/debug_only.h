/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#ifndef NDEBUG
#include <cassert>
#include <iostream>
#endif

#include <boost/core/ignore_unused.hpp>

namespace osquery {
namespace debug_only {

/**
 * Use it for unconditional abort with message only in debug mode
 */
inline void fail(const char* msg) {
#ifndef NDEBUG
  std::cerr << "Failure in debug mode: \"" << msg << "\"\n";
  assert(false && "Failure in debug mode");
#endif
  boost::ignore_unused(msg);
}

/**
 * To verify something vital only in debug mode
 * See examples of usage in tests osquery/debug/tests/debug_only_tests.cpp
 */
template <typename FunctionType>
inline void verify(FunctionType checker, const char* msg) {
#ifndef NDEBUG
  if (!checker()) {
    fail(msg);
  }
#endif
  boost::ignore_unused(checker);
  boost::ignore_unused(msg);
}

/**
 * Pretty much the same as verify, but for the simple boolean condition
 */
inline void verifyTrue(bool expected_true, const char* msg) {
#ifndef NDEBUG
  if (!expected_true) {
    fail(msg);
  }
#endif
  boost::ignore_unused(expected_true);
  boost::ignore_unused(msg);
}

/**
 * Class for debug variables and verifications regarding to it.
 * It is designed to contain a value of given type and perform some
 * verifications and updates to it in debug build.
 * In release build objects are empty; verifications and updates do nothing.
 *
 * See examples of usage in tests osquery/debug/tests/debug_only_tests.cpp
 */
template <typename VarType>
class Var final {
 public:
  explicit Var()
#ifndef NDEBUG
      : value_(VarType{})
#endif
  {
  }

  Var(VarType value)
#ifndef NDEBUG
      : value_(std::move(value))
#endif
  {
    boost::ignore_unused(value);
  }

  inline void verify(const char* msg) const {
#ifndef NDEBUG
    if (!value_) {
      fail(msg);
    }
#endif
    boost::ignore_unused(msg);
  }

  template <typename FunctionType>
  inline void verify(FunctionType checker, const char* msg) const {
#ifndef NDEBUG
    if (!checker(value_)) {
      fail(msg);
    }
#endif
    boost::ignore_unused(checker);
    boost::ignore_unused(msg);
  }

  inline void verifyEqual(const VarType& other, const char* msg) const {
#ifndef NDEBUG
    if (value_ != other) {
      fail(msg);
    }
#endif
    boost::ignore_unused(other);
    boost::ignore_unused(msg);
  }

  inline void set(const VarType& newValue) const {
#ifndef NDEBUG
    value_ = newValue;
#endif
    boost::ignore_unused(newValue);
  }

  template <typename FunctionType>
  inline void update(FunctionType modifier) const {
#ifndef NDEBUG
    value_ = modifier(value_);
#endif
    boost::ignore_unused(modifier);
  }

#ifndef NDEBUG
  mutable VarType value_;
#endif
};

} // namespace debug_only
} // namespace osquery
