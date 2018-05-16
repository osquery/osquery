//
//  expected.hpp
//  gmock
//
//  Created by Max Kareta on 5/15/18.
//

#pragma once

#include <include/osquery/error.h>

/** Utility class that should be used in function that return
 * either error or value. Expected enforce developer to test for success and
 * check error if any.
 *
 * ExpectedValue:
 * ExpectedValue<std::string> function() {
 *   if (test) {
 *    return "ok";
 *   } else {
 *    return std::shared_prt(new Error(error_domain, error_code));
 *   }
 * }
 *
 * Expected:
 * Expected<PlatformProcess> function() {
 *   if (test) {
 *    return std::unique_prt(new PlatformProcess(pid));
 *   } else {
 *    return std::shared_prt(new Error(error_domain, error_code));
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

  ~ExpectedBase() {
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

 protected:
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
  using reference = typename std::remove_reference<T>::type&;
  using const_reference = const typename std::remove_reference<T>::type&;
  using pointer = typename std::remove_reference<T>::type*;
  using const_pointer = const typename std::remove_reference<T>::type*;

 public:
  using ExpectedBase::ExpectedBase;

  ExpectedValue(T object) : ExpectedBase(), object_(std::move(object)) {}

  reference get() {
    return object_;
  }

  T take() {
    return std::move(object_);
  }

  pointer operator->() {
    return object_;
  }

  const_pointer operator->() const {
    return object_;
  }

  reference operator*() {
    return object_;
  }

  const_reference operator*() const {
    return object_;
  }

 private:
  T object_;
};

template <class T>
class Expected : public ExpectedBase {
 private:
  static const bool isPointer = std::is_pointer<T>::value;
  using value_type = typename std::remove_pointer<T>::type;
  using storage_type = std::shared_ptr<value_type>;

  using reference = typename std::remove_reference<value_type>::type&;
  using const_reference =
      const typename std::remove_reference<value_type>::type&;
  using pointer = typename std::remove_reference<value_type>::type*;
  using const_pointer = const typename std::remove_reference<value_type>::type*;

 public:
  using ExpectedBase::ExpectedBase;

  Expected(std::shared_ptr<value_type> object)
      : ExpectedBase(), object_(std::move(object)) {}
  Expected(std::unique_ptr<value_type> object)
      : ExpectedBase(), object_(std::move(object)) {}

  reference get() {
    return object_;
  }

  pointer operator->() {
    return *object_;
  }

  const_pointer operator->() const {
    return *object_;
  }

  reference operator*() {
    return *object_;
  }

  const_reference operator*() const {
    return *object_;
  }

 private:
  storage_type object_;
};

} // namespace osquery
