/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace tables {

namespace {

// Resolve the same PCI address used by gpu_info for the device_id join key.
std::map<std::string, std::string> pciAddressByPnpId() {
  std::map<std::string, std::string> addresses;

  const auto wmiReq = WmiRequest::CreateWmiRequest(
      "SELECT PNPDeviceID, LocationInformation FROM Win32_PnPEntity");
  if (!wmiReq) {
    return addresses;
  }

  for (const auto& item : wmiReq->results()) {
    std::string pnp_id;
    if (!item.GetString("PNPDeviceID", pnp_id).ok() || pnp_id.empty()) {
      continue;
    }

    std::string location;
    if (!item.GetString("LocationInformation", location).ok() ||
        location.empty()) {
      continue;
    }

    unsigned long bus = 0;
    unsigned long device = 0;
    unsigned long function = 0;
    if (std::sscanf(location.c_str(),
                    "PCI bus %lu, device %lu, function %lu",
                    &bus,
                    &device,
                    &function) != 3) {
      continue;
    }

    char address[16];
    std::snprintf(address,
                  sizeof(address),
                  "0000:%02lx:%02lx.%lu",
                  bus,
                  device,
                  function);
    addresses[pnp_id] = address;
  }

  return addresses;
}

// Collect 3D engine utilization per physical GPU index.
// Name format: pid_PPPP_luid_0xHH_0xHH_phys_N_eng_E_engtype_3D
// Sums UtilizationPercentage across all entries for each phys_N, capped at 100.
std::map<int, double> collectGpuUtilizationPct() {
  std::map<int, double> util_map;

  const auto perfReq = WmiRequest::CreateWmiRequest(
      "SELECT Name, UtilizationPercentage "
      "FROM Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine");
  if (!perfReq || perfReq->results().empty()) {
    return util_map;
  }

  for (const auto& item : perfReq->results()) {
    std::string name;
    if (!item.GetString("Name", name).ok()) {
      continue;
    }
    if (name.find("engtype_3D") == std::string::npos) {
      continue;
    }

    const auto phys_pos = name.find("_phys_");
    if (phys_pos == std::string::npos) {
      continue;
    }
    const std::size_t num_start = phys_pos + 6;
    const auto num_end = name.find('_', num_start);
    if (num_end == std::string::npos) {
      continue;
    }
    const auto phys_result =
        tryTo<int>(name.substr(num_start, num_end - num_start));
    if (phys_result.isError()) {
      continue;
    }
    const int phys_idx = phys_result.get();

    unsigned long long util = 0;
    if (item.GetUnsignedLongLong("UtilizationPercentage", util).ok()) {
      util_map[phys_idx] += static_cast<double>(util);
    }
  }

  for (auto& kv : util_map) {
    kv.second = std::min(kv.second, 100.0);
  }

  return util_map;
}

} // namespace

QueryData genGpuMetrics(QueryContext& context) {
  QueryData results;

  const auto wmiReq = WmiRequest::CreateWmiRequest(
      "SELECT PNPDeviceID FROM Win32_VideoController");
  if (!wmiReq || wmiReq->results().empty()) {
    LOG(WARNING) << "Failed to retrieve GPU information via WMI";
    return results;
  }

  const auto util_map = collectGpuUtilizationPct();
  const auto address_by_pnp_id = pciAddressByPnpId();

  int device_id = 0;
  const auto single_gpu_utilization = util_map.find(0);
  const bool has_unambiguous_utilization =
      wmiReq->results().size() == 1 && util_map.size() == 1 &&
      single_gpu_utilization != util_map.end();
  for (const auto& item : wmiReq->results()) {
    Row r;

    std::string pnp_device_id;
    item.GetString("PNPDeviceID", pnp_device_id);
    const auto slot_it = address_by_pnp_id.find(pnp_device_id);
    if (slot_it == address_by_pnp_id.end()) {
      r["device_id"] = "GPU" + std::to_string(device_id++);
    } else {
      r["device_id"] = "GPU" + slot_it->second;
    }

    // The WMI controller and performance-counter enumerations expose no shared
    // identity here. Only report utilization when both identify one adapter.
    if (has_unambiguous_utilization) {
      r["gpu_utilization_pct"] = DOUBLE(single_gpu_utilization->second);
    }

    results.push_back(r);
  }

  return results;
}

} // namespace tables
} // namespace osquery
