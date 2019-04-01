/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/utils/schemer/json/schemer_json_error.h>

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/schemer/schemer.h>

#include <string>

namespace osquery {
namespace schemer {
namespace impl {

template <typename WriterType,
          typename ValueType,
          typename std::enable_if<std::is_same<ValueType, bool>::value,
                                  int>::type = 0>
void writeValue(WriterType& writer, ValueType value) {
  writer.Bool(value);
}

template <
    typename WriterType,
    typename ValueType,
    typename std::enable_if<std::is_same<ValueType, std::int8_t>::value ||
                                std::is_same<ValueType, std::int16_t>::value ||
                                std::is_same<ValueType, std::int32_t>::value,
                            int>::type = 0>
void writeValue(WriterType& writer, ValueType value) {
  writer.Int(value);
}

template <typename WriterType,
          typename ValueType,
          typename std::enable_if<std::is_same<ValueType, std::int64_t>::value,
                                  int>::type = 0>
void writeValue(WriterType& writer, ValueType const& value) {
  writer.Int64(value);
}

template <
    typename WriterType,
    typename ValueType,
    typename std::enable_if<std::is_same<ValueType, std::uint8_t>::value ||
                                std::is_same<ValueType, std::uint16_t>::value ||
                                std::is_same<ValueType, std::uint32_t>::value,
                            int>::type = 0>
void writeValue(WriterType& writer, ValueType value) {
  writer.Uint(value);
}

template <typename WriterType,
          typename ValueType,
          typename std::enable_if<std::is_same<ValueType, std::uint64_t>::value,
                                  int>::type = 0>
void writeValue(WriterType& writer, ValueType const& value) {
  writer.Uint64(value);
}

template <typename WriterType,
          typename ValueType,
          typename std::enable_if<std::is_floating_point<ValueType>::value,
                                  int>::type = 0>
void writeValue(WriterType& writer, ValueType const& value) {
  writer.Double(value);
}

template <typename WriterType,
          typename ValueType,
          typename std::enable_if<std::is_same<ValueType, std::string>::value,
                                  int>::type = 0>
void writeValue(WriterType& writer, ValueType const& value) {
  writer.String(value);
}

template <typename WriterType>
class JsonWriter final {
 public:
  explicit JsonWriter(WriterType& writer) : writer_(writer) {
    writer_.StartObject();
  }

  ~JsonWriter() {
    writer_.EndObject();
  }

  template <typename KeyType, typename ValueType>
  void record(const KeyType& key, ValueType const& value) {
    writer_.Key(key);
    writeValue(writer_, value);
  }

 private:
  WriterType& writer_;
};

} // namespace impl
} // namespace schemer
} // namespace osquery
