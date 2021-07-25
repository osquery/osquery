/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/utils/schemer/json/schemer_json_error.h>
#include <osquery/utils/schemer/json/schemer_json_impl.h>

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/schemer/schemer.h>

#include <boost/core/demangle.hpp>

#include <string>

namespace osquery {
namespace schemer {

/**
 * @brief Schemer formatter implementing serialisation to JSON objects.
 *
 * Transform objects of a class with defined schema into JSON objects.
 *
 * Support only simple types as a members:
 *  - boolean;
 *  - integral types (int, short, long, long long, unsigned etc);
 *  - floating point numbers (float, double);
 *  - std::string;
 *  - C-string - only for serialisation;
 *  - types with defined schema, @see schemer::has_schema type trait.
 *
 * Not implemented yet, but coming soon:
 *  - Standard sontainers support
 */

/**
 * @brief Serialize object of class with defined schema to JSON object printed
 * to rapidjson stream
 */
template <typename Type, typename RapidJsonOutStream>
ExpectedSuccess<JsonError> toJson(RapidJsonOutStream& os, Type const& value) {
  rapidjson::Writer<RapidJsonOutStream> json_writer(os);
  auto writer =
      impl::JsonWriter<rapidjson::Writer<RapidJsonOutStream>>(json_writer);
  Type::discloseSchema(writer, value);
  return Success{};
}

/**
 * @brief Serialize object of class with defined schema to JSON object printed
 * to std::string
 */
template <typename Type>
Expected<std::string, JsonError> toJson(Type const& value) {
  auto buf = rapidjson::StringBuffer{};
  auto exp = toJson(buf, value);
  if (exp.isError()) {
    return exp.takeError();
  }
  return std::string{buf.GetString(), buf.GetSize()};
}

/**
 * @brief Deserialize object of class with defined schema from JSON object in
 * rapidjson input stream
 */
template <typename Type, typename RapidJsonInStream>
ExpectedSuccess<JsonError> fromJson(Type& value, RapidJsonInStream& is) {
  auto dom = rapidjson::Document{};
  dom.ParseStream<rapidjson::kParseFullPrecisionFlag>(is);
  if (dom.HasParseError()) {
    return createError(JsonError::Syntax)
           << "Can not parse value of type "
           << boost::core::demangle(typeid(Type).name()) << " from JSON. "
           << GetParseError_En(dom.GetParseError())
           << " Offset: " << dom.GetErrorOffset();
  }
  auto reader = impl::JsonReader{dom};
  if (reader.status.isValue()) {
    Type::discloseSchema(reader, value);
  }
  if (reader.status.isError()) {
    return createError(JsonError::IncorrectFormat, reader.status.takeError())
           << "Can not parse value of type "
           << boost::core::demangle(typeid(Type).name()) << " from JSON";
  }
  return Success{};
}

/**
 * @brief Deserialize object of class with defined schema from JSON object in
 * C-string
 */
template <
    typename Type,
    typename CharType,
    typename std::enable_if<std::is_same<CharType, char>::value, int>::type = 0>
ExpectedSuccess<JsonError> fromJson(Type& value, CharType const* c_str) {
  auto buf = rapidjson::StringStream{c_str};
  return fromJson(value, buf);
}

} // namespace schemer
} // namespace osquery
