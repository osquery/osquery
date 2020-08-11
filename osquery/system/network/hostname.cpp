/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/system/network/hostname.h>

#include <osquery/core/system.h>
#include <osquery/utils/status/status.h>

namespace osquery {

HostIdentity HostIdentity::localhost() {
  auto inst = HostIdentity{};
  inst.fqdn = getFqdn();
  getHostUUID(inst.uuid);
  return inst;
}

} // namespace osquery
