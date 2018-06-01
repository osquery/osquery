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

#include <osquery/core.h>
// Make sure system is included to work around the GetObject problem on Windows
#include <osquery/system.h>

#ifdef WIN32
#pragma warning(push, 3)
#pragma warning(disable : 4715)
#endif

#define RAPIDJSON_HAS_STDSTRING 1

#define RAPIDJSON_NO_SIZETYPEDEFINE
namespace rapidjson {
using SizeType = ::std::size_t;
} // namespace rapidjson

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#ifdef WIN32
#pragma warning(pop)

#endif

namespace osquery {
/**
 * @brief This provides a small wrapper around constructing JSON objects.
 *
 * Constructing RapidJSON objects can be slightly tricky. In our original
 * refactoring we found several opportunities to leak memory and cause faults.
 * This was mostly causes by setting allocators incorrectly.
 */
class JSON : private only_movable {
 private:
  explicit JSON(decltype(rapidjson::kObjectType) type);

 public:
  JSON();
  JSON(JSON&&) = default;
  JSON& operator=(JSON&&) = default;

  /// Create a JSON wrapper for an Object (map).
  static JSON newObject();

  /// Create a JSON wrapper for an Array (list).
  static JSON newArray();

  /// Create a JSON wrapper from an existing value.
  static JSON newFromValue(const rapidjson::Value& value);

 public:
  /// Make a JSON object (map).
  rapidjson::Document getObject() const;

  /// Make a JSON array (list).
  rapidjson::Document getArray() const;

  /// Add a JSON object or array to a list.
  void push(rapidjson::Value& value);

  /// Add a JSON object or array to a list.
  void push(rapidjson::Value& value, rapidjson::Value& arr);

  /// Add a size_t to a JSON array.
  void push(size_t value);

  /// Add a size_t to a JSON array.
  void push(size_t value, rapidjson::Value& arr);

  /// Add a copy of a string to a JSON array.
  void pushCopy(const std::string& value);

  /// Add a reference to a string to a JSON array.
  void pushCopy(const std::string& value, rapidjson::Value& arr);

  /**
   * @brief Add a string value to a JSON object by copying the contents.
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void addCopy(const std::string& key,
               const std::string& value,
               rapidjson::Value& obj);

  /**
   * @brief Add a string value to a JSON object by copying the contents.
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The document must be an object type.
   */
  void addCopy(const std::string& key, const std::string& value);

  /**
   * @brief Add a string value to a JSON object by referencing the contents.
   *
   * The string value must live longer than the document's use.
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void addRef(const std::string& key,
              const std::string& value,
              rapidjson::Value& obj);

  /**
   * @brief Add a string value to a JSON object by referencing the contents.
   *
   * The string value must live longer than the document's use.
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void addRef(const std::string& key, const std::string& value);

  /**
   * @brief Add a string value to a JSON object by copying the contents.
   *
   * This is basically and alias for addCopy()
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void add(const std::string& key,
           const std::string& value,
           rapidjson::Value& obj);

  /**
   * @brief Add a string value to a JSON object by copying the contents.
   *
   * This is basically and alias for addCopy().
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The document must be an object type.
   */
  void add(const std::string& key, const std::string& value);

  /**
   * @brief Add a char* value to a JSON object by copying the contents.
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void add(const std::string& key, const char* value, rapidjson::Value& obj);

  /**
   * @brief Add a char* value to a JSON object by copying the contents.
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The document must be an object type.
   */
  void add(const std::string& key, const char* value);

  /**
   * @brief Add a size_t value to a JSON object by copying the contents.
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void add(const std::string& key, size_t value, rapidjson::Value& obj);

  /**
   * @brief Add a size_t value to a JSON object by copying the contents.
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The document must be an object type.
   */
  void add(const std::string& key, size_t value);

  /**
   * @brief Add an int value to a JSON object by copying the contents.
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void add(const std::string& key, int value, rapidjson::Value& obj);

  /**
   * @brief Add an int value to a JSON object by copying the contents.
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The document must be an object type.
   */
  void add(const std::string& key, int value);

  /**
   * @brief Add a bool value to a JSON object by copying the contents.
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void add(const std::string& key, bool value, rapidjson::Value& obj);

  /**
   * @brief Add a bool value to a JSON object by copying the contents.
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The document must be an object type.
   */
  void add(const std::string& key, bool value);

  /// Add a JSON document as a member.
  void add(const std::string& key, const rapidjson::Value& value);

  /// Add a JSON document as a member of another document.
  void add(const std::string& key,
           const rapidjson::Value& value,
           rapidjson::Value& obj);

  /**
   * @brief Copy a JSON object/array into the document.
   *
   * The type of the base document may change, be careful.
   */
  void copyFrom(const rapidjson::Value& value, rapidjson::Value& target);

  /**
   * @brief Copy a JSON object/array into the document.
   *
   * The type of the base document may change, be careful.
   */
  void copyFrom(const rapidjson::Value& value);

  /// Convert this document to a JSON string.
  Status toString(std::string& str) const;

  /// Helper to convert a string into JSON.
  Status fromString(const std::string& str);

  /// Merge members of source into target, must both be objects.
  void mergeObject(rapidjson::Value& target_obj, rapidjson::Value& source_obj);

  void mergeArray(rapidjson::Value& target_arr, rapidjson::Value& source_arr);

  /// Access the internal document containing the allocator.
  rapidjson::Document& doc();

  /// Access the internal document containing the allocator.
  const rapidjson::Document& doc() const;

 public:
  /// Get the value as a 'size' or 0.
  static size_t valueToSize(const rapidjson::Value& value);

  /// Get the value as a 'bool' or false.
  static bool valueToBool(const rapidjson::Value& value);

 private:
  rapidjson::Document doc_;
  decltype(rapidjson::kObjectType) type_;
};
} // namespace osquery
