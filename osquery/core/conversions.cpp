/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iomanip>
#include <sstream>

#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/uuid/sha1.hpp>

#include <osquery/logger.h>

#include "osquery/core/conversions.h"

namespace bai = boost::archive::iterators;

namespace osquery {

typedef bai::binary_from_base64<const char*> base64_str;
typedef bai::transform_width<base64_str, 8, 6> base64_dec;
typedef bai::transform_width<std::string::const_iterator, 6, 8> base64_enc;
typedef bai::base64_from_binary<base64_enc> it_base64;

std::string base64Decode(const std::string& encoded) {
  std::string is;
  std::stringstream os;

  is = encoded;
  boost::replace_all(is, "\r\n", "");
  boost::replace_all(is, "\n", "");
  size_t size = is.size();

  // Remove the padding characters
  if (size && is[size - 1] == '=') {
    --size;
    if (size && is[size - 1] == '=') {
      --size;
    }
  }

  if (size == 0) {
    return "";
  }
  try {
    std::copy(base64_dec(is.data()),
              base64_dec(is.data() + size),
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
  std::string base64(it_base64(unencoded.begin()), it_base64(unencoded.end()));
  base64.append(writePaddChars, '=');
  os << base64;
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
}
