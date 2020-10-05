/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstddef>

#include <osquery/utils/only_movable.h>
#include <osquery/utils/status/status.h>
#include <osquery/utils/system/system.h>

#ifdef WIN32
#pragma warning(push, 3)
#pragma warning(disable : 4715)
#endif

/**
 * This protects parsing from overflowing the stack.
 * See http://rapidjson.org/md_doc_features.html for more details.
 *
 * This must be defined before including RapidJSON headers.
 */
#define RAPIDJSON_PARSE_DEFAULT_FLAGS (kParseIterativeFlag)

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/prettywriter.h>
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
  explicit JSON(rapidjson::Type type);

 public:
  enum class ParseMode { Iterative, Recursive };

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
   * @brief Add a int value to a JSON object by copying the contents.
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void add(const std::string& key, int value, rapidjson::Value& obj);

  /**
   * @brief Add a int value to a JSON object by copying the contents.
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The document must be an object type.
   */
  void add(const std::string& key, int value);

  /**
   * @brief Add a long value to a JSON object by copying the contents.
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void add(const std::string& key, long value, rapidjson::Value& obj);

  /**
   * @brief Add a long value to a JSON object by copying the contents.
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The document must be an object type.
   */
  void add(const std::string& key, long value);

  /**
   * @brief Add a long long to a JSON object by copying the
   * contents.
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void add(const std::string& key, long long value, rapidjson::Value& obj);
  /**
   * @brief Add a long long to a JSON object by copying the
   * contents.
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The document must be an object type.
   */
  void add(const std::string& key, long long value);

  /**
   * @brief Add an unsigned int value to a JSON object by copying the contents.
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void add(const std::string& key, unsigned int value, rapidjson::Value& obj);

  /**
   * @brief Add an unsigned int value to a JSON object by copying the contents.
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The document must be an object type.
   */
  void add(const std::string& key, unsigned int value);

  /**
   * @brief Add an unsigned long value to a JSON object by copying the contents.
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void add(const std::string& key, unsigned long value, rapidjson::Value& obj);

  /**
   * @brief Add an unsigned long value to a JSON object by copying the contents.
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The document must be an object type.
   */
  void add(const std::string& key, unsigned long value);

  /**
   * @brief Add an unsigned long long to a JSON object by copying the
   * contents.
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void add(const std::string& key,
           unsigned long long value,
           rapidjson::Value& obj);
  /**
   * @brief Add an unsigned long long to a JSON object by copying the
   * contents.
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The document must be an object type.
   */
  void add(const std::string& key, unsigned long long value);

  /**
   * @brief Add a double value to a JSON object by copying the contents.
   *
   * This will add the key and value to an input document. If the key exists
   * the value will be replaced.
   * The input document must be an object type.
   */
  void add(const std::string& key, double value, rapidjson::Value& obj);
  /**
   * @brief Add an double value to a JSON object by copying the contents.
   *
   * This will add the key and value to the JSON document. If the key exists
   * the value will be replaced.
   * The document must be an object type.
   */
  void add(const std::string& key, double value);

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

  /// Convert this document to a formatted JSON string.
  Status toPrettyString(std::string& str, size_t indentCharCount = 2) const;

  /// Helper to convert a string into JSON.
  Status fromString(const std::string& str,
                    ParseMode parse_mode = ParseMode::Recursive);

  /// Merge members of source into target, must both be objects.
  void mergeObject(rapidjson::Value& target_obj, rapidjson::Value& source_obj);

  void mergeArray(rapidjson::Value& target_arr, rapidjson::Value& source_arr);

  /// Access the internal document containing the allocator.
  rapidjson::Document& doc();

  /// Access the internal document containing the allocator.
  const rapidjson::Document& doc() const;

 public:
  /// Get the value as a 'size' or 0.
  static std::uint64_t valueToSize(const rapidjson::Value& value);

  /// Get the value as a 'bool' or false.
  static bool valueToBool(const rapidjson::Value& value);

 private:
  rapidjson::Document doc_;
  decltype(rapidjson::kObjectType) type_;
};
} // namespace osquery
