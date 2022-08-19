/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/filesystem.hpp>
#include <osquery/utils/info/firmware.h>

namespace osquery {

namespace {

const std::string kEfiDirectory{"/sys/firmware/efi"};

}

boost::optional<FirmwareKind> getFirmwareKind() {
  if (boost::filesystem::is_directory(kEfiDirectory)) {
    return FirmwareKind::Uefi;
  } else {
    return FirmwareKind::Bios;
  }
}

} // namespace osquery
