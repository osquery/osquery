/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/linux/block_device_enumeration.h>

namespace osquery {
namespace tables {
QueryData genBlockDevs(QueryContext& context) {
  if (getuid() || geteuid()) {
    VLOG(1) << "Not running as root, LVM and other column data not available";
  }

  QueryData results;
  auto query_context = context.constraints["name"].getAll(EQUALS);
  auto block_devices = enumerateBlockDevices(query_context, false);

  for (const auto& block_device : block_devices) {
    Row r;
    r["name"] = block_device.name;
    r["parent"] = block_device.parent;
    r["vendor"] = block_device.vendor;
    r["model"] = block_device.model;
    r["serial"] = block_device.serial;
    r["size"] = block_device.size;
    r["block_size"] = block_device.block_size;
    r["uuid"] = block_device.uuid;
    r["type"] = block_device.type;
    r["label"] = block_device.label;

    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
