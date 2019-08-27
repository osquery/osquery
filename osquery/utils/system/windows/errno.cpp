/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/system/errno.h>

#include <string.h>
#include <vector>

#define MAX_BUFFER_SIZE 256

namespace osquery {

std::string platformStrerr(int errnum) {
  std::vector<char> buffer;
  buffer.assign(MAX_BUFFER_SIZE, '\0');

  auto status = ::strerror_s(buffer.data(), buffer.size(), errnum);
  if (status != 0) {
    return "";
  }

  return std::string(buffer.data());
}

}
