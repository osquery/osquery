/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#pragma once

#include <osquery/core.h>

#ifdef WIN32
#pragma warning(push, 3)
#pragma warning(disable : 4715)
#endif

#include <boost/property_tree/json_parser.hpp>

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

// We need to reinclude this to re-enable boost's warning suppression
#include <boost/config/compiler/visualc.hpp>
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
  JSON(JSON&&) = default;
  JSON& operator=(JSON&&) = default;

  /// Create a JSON wrapper for an Object (map).
  static JSON newObject();

  /// Create a JSON wrapper for an Array (list).
  static JSON newArray();

 public:
  /// Make a JSON object (map).
  rapidjson::Document getObject() const;

  /// Make a JSON array (list).
  rapidjson::Document getArray() const;

  /// Add a JSON object or array to a list.
  void push(rapidjson::Document& line);

  /**
   * @brief Add a string value to a JSON object by copying the contents.
   *
   * This will add the key and value to an input document.
   * The input document must be an object type.
   */
  void addCopy(const std::string& key,
               const std::string& value,
               rapidjson::Document& line);

  /**
   * @brief Add a string value to a JSON object by copying the contents.
   *
   * This will add the key and value to the JSON document.
   * The document must be an object type.
   */
  void addCopy(const std::string& key, const std::string& value);

  /**
   * @brief Add a string value to a JSON object by referencing the contents.
   *
   * The string value must live longer than the document's use.
   *
   * This will add the key and value to an input document.
   * The input document must be an object type.
   */
  void addRef(const std::string& key,
              const std::string& value,
              rapidjson::Document& line);

  /**
   * @brief Add a string value to a JSON object by referencing the contents.
   *
   * The string value must live longer than the document's use.
   *
   * This will add the key and value to the JSON document.
   * The input document must be an object type.
   */
  void addRef(const std::string& key, const std::string& value);

  /**
   * @brief Add a size_t value to a JSON object by copying the contents.
   *
   * This will add the key and value to an input document.
   * The input document must be an object type.
   */
  void add(const std::string& key, size_t value, rapidjson::Document& line);

  /**
   * @brief Add a size_t value to a JSON object by copying the contents.
   *
   * This will add the key and value to the JSON document.
   * The document must be an object type.
   */
  void add(const std::string& key, size_t value);

  /**
   * @brief Add a int value to a JSON object by copying the contents.
   *
   * This will add the key and value to an input document.
   * The input document must be an object type.
   */
  void add(const std::string& key, int value, rapidjson::Document& line);

  /**
   * @brief Add a int value to a JSON object by copying the contents.
   *
   * This will add the key and value to the JSON document.
   * The document must be an object type.
   */
  void add(const std::string& key, int value);

  /// Convert this document to a JSON string.
  Status toString(std::string& str) const;

  /// Access the internal document containing the allocator.
  rapidjson::Document& doc();

 private:
  rapidjson::Document doc_;
  decltype(rapidjson::kObjectType) type_;
};
} // namespace osquery
