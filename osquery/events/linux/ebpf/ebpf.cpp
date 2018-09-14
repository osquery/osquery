/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "osquery/events/linux/ebpf/ebpf.h"
#include "osquery/events/linux/ebpf/system.h"

namespace osquery {
namespace ebpf {

bool isSupportedBySystem() {
  auto const version = impl::getKernelReleaseVersion();
  return kMinimalLinuxVersionCode <=
         KERNEL_VERSION(version.major, version.minor, version.patches);
}

} // namespace ebpf
} // namespace osquery
