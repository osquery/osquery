/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <type_traits>

namespace osquery {
namespace schemer {

/**
 * @brief Serialization framework
 *
 * @details This is a framework to declare a serialization and deserialization
 * schema for C++ classes. The schema can be used by different implementations
 * to represent C++ object as data-interchange format or to parse an object from
 * formatted representation.
 *
 * It works without macro or any verbose transformation code. All you need to
 * do to be able to serialize and deserialize some C++ class is to define a
 * template static method discloseSchema in the class. Which describe all
 * members that have to be read by serializer and written by deserializer.
 * Everything else is a job of schemer formatters.
 *
 * Support of specific types, including nested types support depends on the
 * formatter implementation.
 *
 * Why:
 *  - One place to describe class members instead of two different methods for
 * serializer and deserializer.
 *  - One way do describe schema for many formatters (JSON, TOML, hasher, etc).
 *  - Schemer also sets the order of elements of class, therefore even binary
 * formatters can use it, just ignoring the names.
 *  - It is simple - just one method, nothing more. Therefore there is zero
 * dependencies. Everything is in formatters.
 *
 * @code{.cpp}
 * class JudgmentDay {
 *  public:
 *   template <typename Archive, typename ValueType>
 *   static inline void discloseSchema(Archive& a, ValueType& value) {
 *     schemer::record(a, "Year", value.year_);
 *     schemer::record(a, "Month", value.month_);
 *     schemer::record(a, "Day", value.day_);
 *   }
 *  private:
 *   int year_ = 1997;
 *   std::string month_ = "August";
 *   unsigned short day_ = 29;
 * };
 * @endcode
 *
 * For more descriptive example see `schemer/tests/schemer.cpp`
 */

/**
 * @brief Declare member of a class serializable
 */
template <typename Archive, typename KeyType, typename ValueType>
inline void record(Archive& a, KeyType const& key, ValueType& value) {
  a.template record<KeyType, ValueType>(key, value);
};

namespace impl {

class DummyArchive {
 public:
  template <typename KeyType, typename ValueType>
  void record(KeyType const& key, ValueType& value);
};

} // namespace impl

/**
 * @brief Type trait to check if a type has a defined schema
 */
template <typename Type>
class has_schema {
 private:
  template <typename T>
  static constexpr bool test(
      decltype(&T::template discloseSchema<impl::DummyArchive, Type>)) {
    return true;
  }
  template <typename T>
  static constexpr bool test(...) {
    return false;
  }

 public:
  static constexpr bool value = test<Type>(nullptr);
};

} // namespace schemer
} // namespace osquery
