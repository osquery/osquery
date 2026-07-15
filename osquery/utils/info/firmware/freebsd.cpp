/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sys/sysctl.h>
#include <sys/types.h>

#include <osquery/utils/info/firmware.h>

namespace osquery {

boost::optional<FirmwareKind> getFirmwareKind() {
  // FreeBSD's loader stores how the kernel was booted in
  // machdep.bootmethod; the value is "UEFI" or "BIOS".
  char buf[16] = {0};
  size_t buflen = sizeof(buf) - 1;
  if (sysctlbyname("machdep.bootmethod", buf, &buflen, nullptr, 0) != 0) {
    return boost::none;
  }

  std::string method(buf);
  if (method == "UEFI") {
    return FirmwareKind::Uefi;
  } else if (method == "BIOS") {
    return FirmwareKind::Bios;
  }

  return boost::none;
}

} // namespace osquery
