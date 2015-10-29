/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>

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

  std::copy(base64_dec(is.data()),
            base64_dec(is.data() + size),
            std::ostream_iterator<char>(os));

  return os.str();
}

std::string base64Encode(const std::string& unencoded) {
  std::stringstream os;

  if (unencoded.size() == 0) {
    return std::string();
  }

  size_t writePaddChars = (3U-unencoded.length()%3U)%3U;
  std::string base64(it_base64(unencoded.begin()), it_base64(unencoded.end()));
  base64.append(writePaddChars,'=');
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
}
