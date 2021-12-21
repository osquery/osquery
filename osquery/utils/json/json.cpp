/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "json.h"

#include <osquery/utils/conversions/tryto.h>

#include <algorithm>

namespace rj = rapidjson;

namespace osquery {

JSON::JSON(rj::Type type) : type_(type) {
  if (type_ == rj::kObjectType) {
    doc_.SetObject();
  } else {
    doc_.SetArray();
  }
}

JSON::JSON() {
  type_ = rj::kObjectType;
  doc_.SetObject();
}

JSON JSON::newObject() {
  return JSON(rj::kObjectType);
}

JSON JSON::newArray() {
  return JSON(rj::kArrayType);
}

rj::Document JSON::getObject() const {
  rj::Document line;
  line.SetObject();
  return line;
}

rj::Document JSON::getArray() const {
  rj::Document line;
  line.SetArray();
  return line;
}

void JSON::push(rj::Value& value) {
  assert(type_ == rj::kArrayType);
  push(value, doc());
}

void JSON::push(rj::Value& value, rj::Value& arr) {
  arr.PushBack(rj::Value(value, doc_.GetAllocator()).Move(),
               doc_.GetAllocator());
}

void JSON::push(size_t value) {
  push(value, doc());
}

void JSON::push(size_t value, rj::Value& arr) {
  arr.PushBack(rj::Value(static_cast<uint64_t>(value)).Move(),
               doc_.GetAllocator());
}

void JSON::pushCopy(const std::string& value) {
  pushCopy(value, doc());
}

void JSON::pushCopy(const std::string& value, rj::Value& arr) {
  rj::Value sc;
  sc.SetString(value.c_str(), value.size(), doc_.GetAllocator());
  arr.PushBack(sc.Move(), doc_.GetAllocator());
}

void JSON::add(const std::string& key, const rj::Value& value) {
  add(key, value, doc());
}

void JSON::add(const std::string& key, const rj::Value& value, rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }

  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                rj::Value(value, doc_.GetAllocator()).Move(),
                doc_.GetAllocator());
}

void JSON::addCopy(const std::string& key,
                   const std::string& value,
                   rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }

  rj::Value sc;
  sc.SetString(value.c_str(), value.size(), doc_.GetAllocator());
  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                sc.Move(),
                doc_.GetAllocator());
}

void JSON::addCopy(const std::string& key, const std::string& value) {
  addCopy(key, value, doc());
}

void JSON::addRef(const std::string& key,
                  const std::string& value,
                  rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }

  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                rj::Value(rj::StringRef(value), doc_.GetAllocator()).Move(),
                doc_.GetAllocator());
}

void JSON::addRef(const std::string& key, const std::string& value) {
  addRef(key, value, doc());
}

void JSON::add(const std::string& key, const std::string& value) {
  addCopy(key, value);
}

void JSON::add(const std::string& key,
               const std::string& value,
               rj::Value& obj) {
  addCopy(key, value, obj);
}

void JSON::add(const std::string& key, const char* value, rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }

  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                rj::Value(value, strlen(value)).Move(),
                doc_.GetAllocator());
}
void JSON::add(const std::string& key, const char* value) {
  add(key, value, doc());
}

void JSON::add(const std::string& key, int value, rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }

  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                rj::Value(static_cast<int64_t>(value)).Move(),
                doc_.GetAllocator());
}

void JSON::add(const std::string& key, int value) {
  add(key, value, doc());
}

void JSON::add(const std::string& key, long value, rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }

  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                rj::Value(static_cast<int64_t>(value)).Move(),
                doc_.GetAllocator());
}

void JSON::add(const std::string& key, long value) {
  add(key, value, doc());
}

void JSON::add(const std::string& key, long long value, rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }
  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                rj::Value(static_cast<int64_t>(value)).Move(),
                doc_.GetAllocator());
}
void JSON::add(const std::string& key, long long value) {
  add(key, value, doc());
}

void JSON::add(const std::string& key, unsigned int value, rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }

  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                rj::Value(static_cast<uint64_t>(value)).Move(),
                doc_.GetAllocator());
}

void JSON::add(const std::string& key, unsigned int value) {
  add(key, value, doc());
}

void JSON::add(const std::string& key, unsigned long value, rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }

  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                rj::Value(static_cast<uint64_t>(value)).Move(),
                doc_.GetAllocator());
}

void JSON::add(const std::string& key, unsigned long value) {
  add(key, value, doc());
}

void JSON::add(const std::string& key,
               unsigned long long value,
               rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }
  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                rj::Value(static_cast<uint64_t>(value)).Move(),
                doc_.GetAllocator());
}
void JSON::add(const std::string& key, unsigned long long value) {
  add(key, value, doc());
}
void JSON::add(const std::string& key, double value, rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }
  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                rj::Value(value).Move(),
                doc_.GetAllocator());
}
void JSON::add(const std::string& key, double value) {
  add(key, value, doc());
}

void JSON::add(const std::string& key, bool value, rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }

  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                rj::Value(value).Move(),
                doc_.GetAllocator());
}

void JSON::add(const std::string& key, bool value) {
  add(key, value, doc());
}

Status JSON::toString(std::string& str) const {
  rj::StringBuffer sb;
  rj::Writer<rj::StringBuffer> writer(sb);
  doc_.Accept(writer);
  str = sb.GetString();
  return Status::success();
}

Status JSON::toPrettyString(std::string& str, size_t indentCharCount) const {
  rj::StringBuffer sb;
  rj::PrettyWriter<rj::StringBuffer> writer(sb);
  writer.SetIndent(' ', indentCharCount);
  doc_.Accept(writer);
  str = sb.GetString();
  return Status::success();
}

Status JSON::fromString(const std::string& str, ParseMode mode) {
  rj::ParseResult pr;
  switch (mode) {
  case ParseMode::Iterative: {
    pr = doc_.Parse<rj::kParseIterativeFlag>(str.c_str());
    break;
  }
  case ParseMode::Recursive: {
    pr = doc_.Parse(str.c_str());
    break;
  }
  }

  if (!pr) {
    std::string message{"Cannot parse JSON: "};
    message += GetParseError_En(pr.Code());
    message += " Offset: ";
    message += std::to_string(pr.Offset());
    return Status(1, message);
  }
  return Status::success();
}

void JSON::mergeObject(rj::Value& target_obj, rj::Value& source_obj) {
  assert(target_obj.IsObject());
  assert(source_obj.IsObject());
  for (auto itr = source_obj.MemberBegin(); itr != source_obj.MemberEnd();
       ++itr) {
    auto titr = target_obj.FindMember(itr->name);
    if (titr != target_obj.MemberEnd()) {
      target_obj.RemoveMember(titr);
    }

    target_obj.AddMember(itr->name, itr->value, doc_.GetAllocator());
  }
}

void JSON::mergeArray(rj::Value& target_arr, rj::Value& source_arr) {
  assert(target_arr.IsArray());
  assert(source_arr.IsArray());
  for (auto itr = source_arr.Begin(); itr != source_arr.End(); ++itr) {
    target_arr.PushBack(*itr, doc_.GetAllocator());
  }
}

JSON JSON::newFromValue(const rj::Value& value) {
  assert(value.IsObject() || value.IsArray());

  JSON doc;
  doc.type_ = (value.IsArray()) ? rj::kArrayType : rj::kObjectType;
  doc.copyFrom(value, doc.doc());
  return doc;
}

void JSON::copyFrom(const rapidjson::Value& value, rj::Value& target) {
  target.CopyFrom(value, doc().GetAllocator());
}

void JSON::copyFrom(const rj::Value& value) {
  copyFrom(value, doc());
}

rj::Document& JSON::doc() {
  return doc_;
}

const rj::Document& JSON::doc() const {
  return doc_;
}

std::uint64_t JSON::valueToSize(const rj::Value& value) {
  if (value.IsString()) {
    return tryTo<std::uint64_t>(std::string{value.GetString()}).takeOr(0_sz);
  } else if (value.IsNumber()) {
    return static_cast<size_t>(value.GetUint64());
  }
  return 0_sz;
}

bool JSON::valueToBool(const rj::Value& value) {
  if (value.IsBool()) {
    return value.GetBool();
  } else if (value.IsString()) {
    auto b = std::string(value.GetString());
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);

    return (b == "true" || b == "t");
  } else if (value.IsNumber()) {
    return (value.GetInt() != 0);
  }
  return false;
}

} // namespace osquery
