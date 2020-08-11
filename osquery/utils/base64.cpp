/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "base64.h"

#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>

#include <osquery/logger/logger.h>

namespace bai = boost::archive::iterators;

namespace osquery {

namespace base64 {

namespace {

typedef bai::binary_from_base64<const char*> base64_str;
typedef bai::transform_width<base64_str, 8, 6> base64_dec;
typedef bai::transform_width<std::string::const_iterator, 6, 8> base64_enc;
typedef bai::base64_from_binary<base64_enc> it_base64;

} // namespace

std::string decode(std::string encoded) {
  boost::erase_all(encoded, "\r\n");
  boost::erase_all(encoded, "\n");
  boost::trim_right_if(encoded, boost::is_any_of("="));

  if (encoded.empty()) {
    return encoded;
  }

  try {
    return std::string(base64_dec(encoded.data()),
                       base64_dec(encoded.data() + encoded.size()));
  } catch (const boost::archive::iterators::dataflow_exception& e) {
    LOG(INFO) << "Could not base64 decode string: " << e.what();
    return "";
  }
}

std::string encode(const std::string& unencoded) {
  if (unencoded.empty()) {
    return unencoded;
  }

  size_t writePaddChars = (3U - unencoded.length() % 3U) % 3U;
  try {
    auto encoded =
        std::string(it_base64(unencoded.begin()), it_base64(unencoded.end()));
    encoded.append(std::string(writePaddChars, '='));
    return encoded;
  } catch (const boost::archive::iterators::dataflow_exception& e) {
    LOG(INFO) << "Could not base64 encode string: " << e.what();
    return "";
  }
}

} // namespace base64
} // namespace osquery
