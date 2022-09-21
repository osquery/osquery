/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iostream>
#include <optional>
#include <string>

#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/system/boottime.h>

namespace osquery {
std::uint64_t getBootTime() {
  std::string content;
  auto status = readFile("/proc/stat", content);

  if (!status.ok()) {
    return 0;
  }

  auto btime_start = content.find("btime");

  if (btime_start == std::string::npos) {
    return 0;
  }

  btime_start += 6;

  auto btime_end = content.find("\n", btime_start);

  if (btime_end == std::string::npos) {
    return 0;
  }

  auto btime = content.substr(btime_start, btime_end - btime_start);

  auto btime_res = tryTo<std::uint64_t>(btime);

  if (btime_res.isError()) {
    return 0;
  }

  return btime_res.take();
}
} // namespace osquery
