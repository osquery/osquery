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

#include <boost/uuid/sha1.hpp>

#include <osquery/sha1.h>

namespace osquery {

std::string getBufferSHA1(const void* buffer, size_t size) {
  // SHA1 produces 160-bit digests, so allocate (5 * 32) bits.
  uint32_t digest[5];
  boost::uuids::detail::sha1 sha1;
  sha1.process_bytes(buffer, size);
  sha1.get_digest(digest);

  // Convert digest to desired hex string representation.
  std::stringstream result;
  result << std::hex << std::setfill('0');
  for (int i = 0; i < 5; i++) {
    result << std::setw(sizeof(uint32_t) * 2) << digest[i];
  }
  return result.str();
}
}
