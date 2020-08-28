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

#include <osquery/utils/expected/expected.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/schemer/schemer.h>

#include <algorithm>
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
class JsonWriter;

template <typename WriterType,
          typename ValueType,
          typename std::enable_if<has_schema<ValueType>::value, int>::type = 0>
void writeValue(WriterType& writer, ValueType const& value) {
  auto next_writer = impl::JsonWriter<WriterType>(writer);
  ValueType::discloseSchema(next_writer, value);
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

class JsonReader final {
 public:
  explicit JsonReader(rapidjson::Value const& jObject) : jObject_(jObject) {
    status.ignoreResult();
    if (!jObject_.IsObject()) {
      status =
          createError(JsonError::TypeMismatch)
          << "Wrong type of value: " << jValueToStringForErrorMessage(jObject_)
          << ", expected object";
    }
  }

  template <typename KeyType, typename ValueType>
  void record(const KeyType& key, ValueType& value) {
    if (status.isError()) {
      return;
    }
    auto const it = jObject_.FindMember(key);
    if (it == jObject_.MemberEnd()) {
      status = createError(JsonError::MissedKey)
               << "Missed mandatory key " << key;
    } else {
      copyValueFromJValue(key, value, it->value);
    }
  }

  static inline std::string jValueToStringForErrorMessage(
      rapidjson::Value const& jObject) {
    auto buf = rapidjson::StringBuffer{};
    rapidjson::Writer<rapidjson::StringBuffer> writer(buf);
    jObject.Accept(writer);
    // make sure string representation of value is not too long
    std::size_t const kMaxLength = 22u;
    if (buf.GetSize() < kMaxLength) {
      return std::string{buf.GetString(), buf.GetSize()};
    } else {
      return std::string{buf.GetString(), kMaxLength - 3} + "...";
    }
  }

  template <typename KeyType,
            typename ValueType,
            typename std::enable_if<std::is_same<ValueType, std::string>::value,
                                    int>::type = 0>
  void copyValueFromJValue(const KeyType& key,
                           ValueType& value,
                           rapidjson::Value const& jValue) {
    if (jValue.IsString()) {
      value.assign(jValue.GetString(), jValue.GetStringLength());
    } else {
      status = createError(JsonError::TypeMismatch)
               << "Wrong type of value in pair {\"" << key
               << "\":" << jValueToStringForErrorMessage(jValue)
               << "}, expected string";
    }
  }

  template <typename KeyType,
            typename ValueType,
            typename std::enable_if<std::is_same<ValueType, double>::value,
                                    int>::type = 0>
  void copyValueFromJValue(const KeyType& key,
                           ValueType& value,
                           rapidjson::Value const& jValue) {
    if (jValue.IsNumber()) {
      value = jValue.GetDouble();
    } else {
      status = createError(JsonError::TypeMismatch)
               << "Wrong type of value in pair {\"" << key
               << "\":" << jValueToStringForErrorMessage(jValue)
               << "}, expected floating point number";
    }
  }

  template <typename KeyType,
            typename ValueType,
            typename std::enable_if<std::is_integral<ValueType>::value,
                                    int>::type = 0>
  void copyValueFromJValue(const KeyType& key,
                           ValueType& value,
                           rapidjson::Value const& jValue) {
    if (jValue.template Is<ValueType>()) {
      value = jValue.template Get<ValueType>();
    } else {
      status = createError(JsonError::TypeMismatch)
               << "Wrong type of value in pair {\"" << key
               << "\":" << jValueToStringForErrorMessage(jValue)
               << "}, expected "
               << boost::core::demangle(typeid(ValueType).name());
    }
  }

  template <
      typename KeyType,
      typename ValueType,
      typename std::enable_if<has_schema<ValueType>::value, int>::type = 0>
  void copyValueFromJValue(const KeyType& key,
                           ValueType& value,
                           rapidjson::Value const& jValue) {
    auto next_reader = impl::JsonReader{jValue};
    if (next_reader.status.isError()) {
      status = std::move(next_reader.status);
    } else {
      ValueType::discloseSchema(next_reader, value);
      if (next_reader.status.isError()) {
        status = std::move(next_reader.status);
      }
    }
  }

 public:
  ExpectedSuccess<JsonError> status = Success{};

 private:
  rapidjson::Value const& jObject_;
};

} // namespace impl
} // namespace schemer
} // namespace osquery
