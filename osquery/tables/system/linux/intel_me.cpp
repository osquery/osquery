/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sys/ioctl.h>

#include <vector>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

/// The Linux device node added by the mei driver.
const std::string kIntelME{"/dev/mei0"};

struct mei_response {
  uint32_t maxlen;
  uint8_t version;
};

struct mei_version {
  uint32_t important_details[7];
  uint16_t major;
  uint16_t minor;
  uint16_t hotfix;
  uint16_t build;
  uint16_t r_major;
  uint16_t r_minor;
  uint16_t r_hotfix;
  uint16_t r_build;
  uint16_t codes[6];
};

std::vector<uint8_t> kMEIUpdateGUID{
    232, 205, 157, 48, 177, 204, 98, 64, 143, 120, 96, 1, 21, 163, 67, 39,
};

void genIntelMEVersion(int mei_fd, QueryData& results) {
  uint8_t buffer[18] = {0};
  memcpy(buffer, kMEIUpdateGUID.data(), kMEIUpdateGUID.size());

  if (ioctl(mei_fd, 0xc0104801, buffer) == -1) {
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
                 std::to_string(version.build) + '.' +
                 std::to_string(version.hotfix);

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
