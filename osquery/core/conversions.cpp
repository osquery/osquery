/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iomanip>
#include <locale>
#include <sstream>

#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/uuid/sha1.hpp>

#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"

namespace bai = boost::archive::iterators;
namespace rj = rapidjson;

namespace osquery {

typedef bai::binary_from_base64<const char*> base64_str;
typedef bai::transform_width<base64_str, 8, 6> base64_dec;
typedef bai::transform_width<std::string::const_iterator, 6, 8> base64_enc;
typedef bai::base64_from_binary<base64_enc> it_base64;

JSON::JSON(decltype(rj::kObjectType) type) : type_(type) {
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

void JSON::add(const std::string& key, size_t value, rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }

  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                rj::Value(static_cast<uint64_t>(value)).Move(),
                doc_.GetAllocator());
}

void JSON::add(const std::string& key, size_t value) {
  add(key, value, doc());
}

void JSON::add(const std::string& key, int value, rj::Value& obj) {
  assert(obj.IsObject());
  auto itr = obj.FindMember(key);
  if (itr != obj.MemberEnd()) {
    obj.RemoveMember(itr);
  }

  obj.AddMember(rj::Value(rj::StringRef(key), doc_.GetAllocator()).Move(),
                rj::Value(value).Move(),
                doc_.GetAllocator());
}

void JSON::add(const std::string& key, int value) {
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
  return Status();
}

Status JSON::fromString(const std::string& str) {
  rj::ParseResult pr = doc_.Parse(str.c_str());
  if (!pr) {
    std::string message{"Cannot parse JSON: "};
    message += GetParseError_En(pr.Code());
    message += " Offset: ";
    message += std::to_string(pr.Offset());
    return Status(1, message);
  }
  return Status();
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

size_t JSON::valueToSize(const rj::Value& value) {
  unsigned long long i = 0;
  if (value.IsString()) {
    if (!safeStrtoull(value.GetString(), 10, i)) {
      return 0_sz;
    }
    return static_cast<size_t>(i);
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

std::string base64Decode(std::string is) {
  std::stringstream os;

  boost::replace_all(is, "\r\n", "");
  boost::replace_all(is, "\n", "");

  // Remove the padding characters
  for (int i = 0; i < 2; i++) {
    if (is.size() && is.back() == '=') {
      is.pop_back();
    }
  }

  if (is.size() == 0) {
    return "";
  }

  try {
    std::copy(base64_dec(is.data()),
              base64_dec(is.data() + is.size()),
              std::ostream_iterator<char>(os));
  } catch (const boost::archive::iterators::dataflow_exception& e) {
    LOG(INFO) << "Could not base64 decode string: " << e.what();
    return "";
  }
  return os.str();
}

std::string base64Encode(const std::string& unencoded) {
  std::stringstream os;

  if (unencoded.size() == 0) {
    return std::string();
  }

  size_t writePaddChars = (3U - unencoded.length() % 3U) % 3U;
  try {
    std::copy(it_base64(unencoded.begin()),
              it_base64(unencoded.end()),
              std::ostream_iterator<char>(os));
  } catch (const boost::archive::iterators::dataflow_exception& e) {
    LOG(INFO) << "Could not base64 decode string: " << e.what();
    return "";
  }
  os << std::string(writePaddChars, '=');
  return os.str();
}

bool isPrintable(const std::string& check) {
  for (const unsigned char ch : check) {
    if (ch >= 0x7F || ch <= 0x1F) {
      return false;
    }
  }
  return true;
}

std::vector<std::string> split(const std::string& s, const std::string& delim) {
  std::vector<std::string> elems;
  boost::split(elems, s, boost::is_any_of(delim));
  auto start =
      std::remove_if(elems.begin(), elems.end(), [](const std::string& t) {
        return t.size() == 0;
      });
  elems.erase(start, elems.end());
  for (auto& each : elems) {
    boost::algorithm::trim(each);
  }
  return elems;
}

std::vector<std::string> split(const std::string& s,
                               const std::string& delim,
                               size_t occurences) {
  // Split the string normally with the required delimiter.
  auto content = split(s, delim);
  // While the result split exceeds the number of requested occurrences, join.
  std::vector<std::string> accumulator;
  std::vector<std::string> elems;
  for (size_t i = 0; i < content.size(); i++) {
    if (i < occurences) {
      elems.push_back(content.at(i));
    } else {
      accumulator.push_back(content.at(i));
    }
  }
  // Join the optional accumulator.
  if (accumulator.size() > 0) {
    elems.push_back(join(accumulator, delim));
  }
  return elems;
}

std::string join(const std::vector<std::string>& s, const std::string& tok) {
  return boost::algorithm::join(s, tok);
}

std::string join(const std::set<std::string>& s, const std::string& tok) {
  std::vector<std::string> toJoin;
  toJoin.insert(toJoin.end(), s.begin(), s.end());
  return boost::algorithm::join(toJoin, tok);
}

std::string getBufferSHA1(const char* buffer, size_t size) {
  // SHA1 produces 160-bit digests, so allocate (5 * 32) bits.
  uint32_t digest[5] = {0};
  boost::uuids::detail::sha1 sha1;
  sha1.process_bytes(buffer, size);
  sha1.get_digest(digest);

  // Convert digest to desired hex string representation.
  std::stringstream result;
  result << std::hex << std::setfill('0');
  for (size_t i = 0; i < 5; ++i) {
    result << std::setw(sizeof(uint32_t) * 2) << digest[i];
  }
  return result.str();
}

size_t operator"" _sz(unsigned long long int x) {
  return x;
}
}
