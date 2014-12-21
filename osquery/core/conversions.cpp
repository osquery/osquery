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

#include "osquery/core/conversions.h"

namespace bai = boost::archive::iterators;

namespace osquery {

typedef bai::binary_from_base64<const char*> base64_str;
typedef bai::transform_width<base64_str, 8, 6> base64_dec;

std::string base64Decode(const std::string& encoded) {
  std::string is;
  std::stringstream os;

  is = encoded;
  boost::replace_all(is, "\r\n", "");
  boost::replace_all(is, "\n", "");
  uint32_t size = is.size();

  // Remove the padding characters
  if (size && is[size - 1] == '=') {
    --size;
    if (size && is[size - 1] == '=') {
      --size;
    }
  }

  if (size == 0) {
    return std::string();
  }

  std::copy(base64_dec(is.data()),
            base64_dec(is.data() + size),
            std::ostream_iterator<char>(os));

  return os.str();
}
}
