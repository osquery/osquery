/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <memory>
#include <osquery/error.h>
#include <string>
#include <type_traits>
#include <utility>

/** Utility class that should be used in function that return
 * either error or value. Expected enforce developer to test for success and
 * check error if any.
 *
 * ExpectedValue:
 * ExpectedValue<std::string> function() {
 *   if (test) {
 *    return "ok";
 *   } else {
 *    return std::make_shared<Error>(error_domain, error_code);
 *   }
 * }
 *
 * Expected:
 * Expected<PlatformProcess> function() {
 *   if (test) {
 *    return std::make_unique<PlatformProcess>(pid);
 *   } else {
 *    return std::make_shared<Error>(error_domain, error_code);
 *   }
 * }
 *
 * auto result = function();
 * if (result) {
 *   ...use *result
 * } else {
 *   auto error = result->getError();
 * }
 */

namespace osquery {

class ExpectedBase {
 public:
  ExpectedBase(Error* error) = delete;
  ExpectedBase(Error error) = delete;
  ExpectedBase() : error_(nullptr), hasError_(false) {}
  ExpectedBase(std::shared_ptr<Error> error)
      : error_(std::move(error)), hasError_(true) {}
  ExpectedBase(std::unique_ptr<Error> error)
      : error_(std::move(error)), hasError_(true) {}

  virtual ~ExpectedBase() {
    assert(errorChecked_ && (!hasError_ || errorUsed_));
  }

  std::shared_ptr<Error> getError() {
    errorUsed_ = true;
    errorChecked_ = true;
    return error_;
  }

  explicit operator bool() {
    errorChecked_ = true;
    return !hasError_;
  }

 private:
  std::shared_ptr<Error> error_;
  bool hasError_;
  bool errorChecked_;
  bool errorUsed_;
};

template <class T>
class ExpectedValue : public ExpectedBase {
 private:
  static const bool isPointer = std::is_pointer<T>::value;
  static_assert(!isPointer, "Use Expected class for pointers");

 public:
  using ExpectedBase::ExpectedBase;

  ExpectedValue(T object) : ExpectedBase(), object_(std::move(object)) {}

  T& get() {
    return object_;
  }

  const T& get() const {
    return object_;
  }

  T take() {
    return std::move(object_);
  }

  T* operator->() {
    return object_;
  }

  const T* operator->() const {
    return object_;
  }

  T& operator*() {
    return object_;
  }

  const T& operator*() const {
    return object_;
  }

 private:
  T object_;
};

template <class T>
class Expected : public ExpectedBase {
 private:
  using value_type = typename std::remove_pointer<T>::type;

 public:
  using ExpectedBase::ExpectedBase;

  Expected(std::shared_ptr<value_type> object)
      : ExpectedBase(), object_(std::move(object)) {}
  Expected(std::unique_ptr<value_type> object)
      : ExpectedBase(), object_(std::move(object)) {}

  T& get() {
    return object_;
  }

  const T& get() const {
    return object_;
  }

  T* operator->() {
    return *object_;
  }

  const T* operator->() const {
    return *object_;
  }

  value_type& operator*() {
    return *object_;
  }

  const value_type& operator*() const {
    return *object_;
  }

 private:
  std::shared_ptr<value_type> object_;
};

} // namespace osquery
