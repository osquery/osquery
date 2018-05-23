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
 * Expected<std::string> function() {
 *   if (test) {
 *    return "ok";
 *   } else {
 *    return std::make_shared<Error>(error_domain, error_code);
 *   }
 * }
 *
 * Expected:
 * ExpectedUnique<PlatformProcess> function() {
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

template <class T>
class Expected {
 public:
  Expected(T object) : object_(std::move(object)), hasError_(false) {}
  Expected(Error* error) = delete;
  Expected(Error error) = delete;
  Expected() : error_(nullptr), hasError_(false) {}
  Expected(std::shared_ptr<Error> error)
      : error_(std::move(error)), hasError_(true) {}
  Expected(std::unique_ptr<Error> error)
      : error_(std::move(error)), hasError_(true) {}

  Expected(const Expected&) = delete;

  ~Expected() {
    assert(errorChecked_ || "Error was not checked");
  }

  Expected& operator=(Expected&& other) {
    object_ = std::move(other.object_);
    error_ = std::move(other.error_);
    hasError_ = other.hasError_;
    return *this;
  }

  Expected(Expected&& other) {
    object_ = std::move(other.object_);
    error_ = std::move(other.error_);
    hasError_ = other.hasError_;
  }

  std::shared_ptr<Error> getError() const {
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
  std::shared_ptr<Error> error_;
  bool hasError_;
  mutable bool errorChecked_;
};

template <class T>
using ExpectedShared = Expected<std::shared_ptr<T>>;
template <class T>
using ExpectedUnique = Expected<std::unique_ptr<T>>;

} // namespace osquery
