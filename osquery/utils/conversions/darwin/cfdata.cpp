/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include "cfdata.h"

#include <iomanip>
#include <sstream>

namespace osquery {

std::string stringFromCFData(const CFDataRef& cf_data) {
  CFRange range = CFRangeMake(0, CFDataGetLength(cf_data));

  char* buffer = (char*)malloc(range.length + 1);
  if (buffer == nullptr) {
    return "";
  }
  memset(buffer, 0, range.length + 1);

  std::stringstream result;
  CFDataGetBytes(cf_data, range, (UInt8*)buffer);
  for (CFIndex i = 0; i < range.length; ++i) {
    uint8_t byte = buffer[i];
    if (isprint(byte)) {
      result << byte;
    } else if (buffer[i] == 0) {
      result << ' ';
    } else {
      result << '%' << std::setfill('0') << std::setw(2) << std::hex
             << (int)byte;
    }
  }

  // Cleanup allocations.
  free(buffer);
  return result.str();
}


}
