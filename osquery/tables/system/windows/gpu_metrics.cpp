/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace tables {

QueryData genGpuMetrics(QueryContext& context) {
  QueryData results;

  const auto wmiReq =
      WmiRequest::CreateWmiRequest("SELECT * FROM Win32_VideoController");
  if (!wmiReq || wmiReq->results().empty()) {
    LOG(WARNING) << "Failed to retrieve GPU information via WMI";
    return results;
  }

  int gpu_index = 0;
  for (const auto& item : wmiReq->results()) {
    Row r;
    r["gpu_index"] = INTEGER(gpu_index++);

    // PNPDeviceID format: PCI\VEN_10DE&DEV_2204&...\<location>
    // The location segment (last field) encodes the bus/device/function but is
    // not a standard slot string, so we leave pci_bus empty on Windows.

    item.GetString("AdapterCompatibility", r["vendor_name"]);
    item.GetString("Name", r["device_name"]);
    item.GetString("DriverVersion", r["driver_version"]);

    // AdapterRAM is a UINT32 in WMI (capped at ~4 GB for large GPUs).
    long adapterRam = 0;
    if (item.GetLong("AdapterRAM", adapterRam) && adapterRam > 0) {
      // Cast via unsigned to avoid sign-extension of the raw 32-bit value.
      r["vram_total_bytes"] = BIGINT(
          static_cast<long long>(static_cast<unsigned long>(adapterRam)));
    }

    results.push_back(r);
  }

  return results;
}

} // namespace tables
} // namespace osquery
