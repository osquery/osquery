/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fcntl.h>
#include <sys/ioctl.h>

#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/intel_me.hpp>

namespace osquery {
namespace tables {

/// The Linux device node added by the mei driver.
const std::string kIntelME{"/dev/mei0"};


void genIntelMEVersion(int mei_fd, QueryData& results) {
  uint8_t buffer[18] = {0};
  memcpy(buffer, kMEIUpdateGUID.data(), kMEIUpdateGUID.size());

  if (ioctl(mei_fd, INTEL_ME_LINUX_IOCTL, buffer) == -1) {
    VLOG(1) << "Intel MEI is not accessible";
    return;
  }

  // The IOCTL response includes the maxsize for API calls.
  struct mei_response response;
  memcpy(&response, buffer, sizeof(response));

  if (response.version != 0x1) {
    VLOG(1) << "Intel MEI version is unsupported";
    return;
  }

  // The GetFirmwareVersion command is 0x0.
  memset(buffer, 0, sizeof(buffer));
  write(mei_fd, buffer, 4);

  struct mei_version version;
  auto bytes = read(mei_fd, &version, sizeof(version));
  if (bytes != sizeof(version)) {
    // Problem reading the MEI version.
    return;
  }

  Row r;
  r["version"] = std::to_string(version.major) + '.' +
                 std::to_string(version.minor) + '.' +
                 std::to_string(version.hotfix) + '.' +
                 std::to_string(version.build);

  results.push_back(r);
}

QueryData getIntelMEInfo(QueryContext& context) {
  QueryData results;

  // Open the Intel MEI driver (mei must be loaded).
  auto mei_fd = open(kIntelME.c_str(), O_RDWR);
  if (mei_fd == -1) {
    VLOG(1) << "Cannot open MEI device";
    return {};
  }

  genIntelMEVersion(mei_fd, results);

  close(mei_fd);
  return results;
}
}
}
