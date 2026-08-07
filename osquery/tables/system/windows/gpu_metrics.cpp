/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <algorithm>
#include <map>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace tables {

namespace {

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
    item.GetUnsignedLongLong("UtilizationPercentage", util);
    util_map[phys_idx] += static_cast<double>(util);
  }

  for (auto& kv : util_map) {
    kv.second = std::min(kv.second, 100.0);
  }

  return util_map;
}

} // namespace

QueryData genGpuMetrics(QueryContext& context) {
  QueryData results;

  const auto wmiReq =
      WmiRequest::CreateWmiRequest("SELECT * FROM Win32_VideoController");
  if (!wmiReq || wmiReq->results().empty()) {
    LOG(WARNING) << "Failed to retrieve GPU information via WMI";
    return results;
  }

  const auto util_map = collectGpuUtilizationPct();

  int gpu_index = 0;
  for (const auto& item : wmiReq->results()) {
    Row r;
    r["gpu_index"] = INTEGER(gpu_index);

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

    // phys_N in GPUEngine perf counters is assumed to match enumeration order.
    const auto it = util_map.find(gpu_index);
    if (it != util_map.end()) {
      r["gpu_utilization_pct"] = DOUBLE(it->second);
    }

    results.push_back(r);
    ++gpu_index;
  }

  return results;
}

} // namespace tables
} // namespace osquery
