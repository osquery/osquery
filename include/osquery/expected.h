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
 * enum class TestError { SomeError = 1, AnotherError = 2 };
 * Expected<std::string> function() {
 *   if (test) {
 *    return "ok";
 *   } else {
 *    return std::make_shared<Error<TestError>>(TestError::SomeError);
 *   }
 * }
 *
 * Expected:
 * ExpectedUnique<PlatformProcess> function() {
 *   if (test) {
 *    return std::make_unique<PlatformProcess>(pid);
 *   } else {
 *    return std::make_shared<Error<TestError>>(TestError::AnotherError);
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

template <class T>
class Expected {
 public:
  Expected(T object) : object_(std::move(object)), hasError_(false) {}
  Expected(ErrorBase* error) = delete;
  Expected(ErrorBase error) = delete;
  Expected() : error_(nullptr), hasError_(false) {}
  Expected(std::shared_ptr<ErrorBase> error)
      : error_(std::move(error)), hasError_(true) {}
  Expected(std::unique_ptr<ErrorBase> error)
      : error_(std::move(error)), hasError_(true) {}
  template <class ErrorT>
  Expected(std::shared_ptr<Error<ErrorT>> error)
      : error_(std::static_pointer_cast<ErrorBase>(error)), hasError_(true){};

  Expected(const Expected&) = delete;

  ~Expected() {
    assert(errorChecked_ && "Error was not checked");
  }

  Expected& operator=(Expected&& other) {
    if (this != &other) {
      object_ = std::move(other.object_);
      error_ = std::move(other.error_);
      hasError_ = other.hasError_;
    }
    return *this;
  }

  Expected(Expected&& other) {
    object_ = std::move(other.object_);
    error_ = std::move(other.error_);
    hasError_ = other.hasError_;
  }

  std::shared_ptr<ErrorBase> getError() const {
    return error_;
  }

  explicit operator bool() const {
    errorChecked_ = true;
    return !hasError_;
  }

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
  static const bool isPointer = std::is_pointer<T>::value;
  static_assert(!isPointer, "Use shared/unique pointer");

  T object_;
  std::shared_ptr<ErrorBase> error_;
  bool hasError_;
  mutable bool errorChecked_ = false;
};

template <class T>
using ExpectedShared = Expected<std::shared_ptr<T>>;
template <class T>
using ExpectedUnique = Expected<std::unique_ptr<T>>;

} // namespace osquery
