/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/utils/schemer/json/schemer_json_error.h>
#include <osquery/utils/schemer/json/schemer_json_impl.h>

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/schemer/schemer.h>

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
 *  - floating point nubmers (float, double);
 *  - std::string;
 *  - C-string - only for serialisation.
 *
 * Not implemented yet, but comming soon:
 *  - Nested types support
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

} // namespace schemer
} // namespace osquery
