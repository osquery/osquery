/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/system/network/hostname.h>

#include <osquery/system.h>
#include <osquery/utils/status/status.h>

namespace osquery {

HostIdentity HostIdentity::localhost() {
  auto inst = HostIdentity{};
  inst.fqdn = getFqdn();
  getHostUUID(inst.uuid);
  return inst;
}

} // namespace osquery
