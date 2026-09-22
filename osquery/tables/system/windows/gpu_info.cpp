/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

#include <osquery/core/windows/wmi.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/conversions/windows/strings.h>

namespace osquery {
namespace tables {

namespace {

// Parse a PNPDeviceID like "PCI\VEN_10DE&DEV_1B81&SUBSYS_..." to extract the
// vendor and device (model) IDs.
void parsePnpDeviceId(const std::string& pnp_id,
                      std::string& vendor_id,
                      std::string& model_id) {
  vendor_id.clear();
  model_id.clear();

  // The PNPDeviceID is of the form: PCI\VEN_xxxx&DEV_xxxx&SUBSYS_...
  // VEN_ and DEV_ values are fixed-width (4 hex digits), so read them directly
  // rather than searching for a terminating '&', which fails when the ID ends
  // the string.
  auto vpos = pnp_id.find("VEN_");
  if (vpos != std::string::npos && vpos + 8 <= pnp_id.size()) {
    vendor_id = "0x" + pnp_id.substr(vpos + 4, 4);
  }

  auto dpos = pnp_id.find("DEV_");
  if (dpos != std::string::npos && dpos + 8 <= pnp_id.size()) {
    model_id = "0x" + pnp_id.substr(dpos + 4, 4);
  }
}

// Build a map of PNPDeviceID -> PCI bus address ("0000:bb:dd.f") from
// Win32_PnPEntity.LocationInformation, so pci_slot carries the same bus
// address format as the Linux implementation instead of the full PNP string.
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

    // LocationInformation for PCI devices reads
    // "PCI bus X, device Y, function Z"; non-PCI adapters report other
    // strings ("Location Bus Number..." or empty), which are skipped.
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
    item.GetUnsignedLongLong("UtilizationPercentage", util);
    util_map[phys_idx] += static_cast<double>(util);
  }

  for (auto& kv : util_map) {
    kv.second = std::min(kv.second, 100.0);
  }

  return util_map;
}

// Collect 64-bit VRAM sizes from the display adapter registry class.
// Indexed by enumeration order of numeric subkeys (0000, 0001, ...).
// This avoids the 4 GB wrap of Win32_VideoController.AdapterRAM (uint32).
std::map<int, unsigned long long> collectVramSizes() {
  std::map<int, unsigned long long> vram_map;

  const std::string kDisplayClassKey =
      "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
      "{4d36e968-e325-11ce-bfc1-08002be10318}";

  QueryData classResults;
  queryKey(kDisplayClassKey, classResults);

  int idx = 0;
  for (const auto& row : classResults) {
    const auto type_it = row.find("type");
    const auto name_it = row.find("name");
    if (type_it == row.end() || type_it->second != "subkey") {
      continue;
    }

    // Skip non-numeric subkeys (e.g. "Properties").
    const std::string& subkeyName = name_it->second;
    bool numeric = !subkeyName.empty();
    for (char c : subkeyName) {
      if (!isdigit(static_cast<unsigned char>(c))) {
        numeric = false;
        break;
      }
    }
    if (!numeric) {
      continue;
    }

    QueryData adapterResults;
    queryKey(kDisplayClassKey + kRegSep + subkeyName, adapterResults);
    for (const auto& val : adapterResults) {
      const auto vname_it = val.find("name");
      const auto vtype_it = val.find("type");
      const auto vdata_it = val.find("data");
      if (vname_it == val.end() || vtype_it == val.end() ||
          vdata_it == val.end()) {
        continue;
      }
      if (vname_it->second == "HardwareInformation.qwMemorySize" &&
          vtype_it->second == "REG_QWORD") {
        const auto result = tryTo<unsigned long long>(vdata_it->second);
        if (!result.isError() && result.get() > 0) {
          vram_map[idx] = result.get();
        }
        break;
      }
    }
    ++idx;
  }

  return vram_map;
}

} // namespace

QueryData genGpuInfo(QueryContext& context) {
  QueryData results;

  const auto wmiReq =
      WmiRequest::CreateWmiRequest("SELECT * FROM Win32_VideoController");
  if (!wmiReq || wmiReq->results().empty()) {
    LOG(WARNING) << "Failed to retrieve GPU information";
    return results;
  }

  const auto address_by_pnp_id = pciAddressByPnpId();
  const auto util_map = collectGpuUtilizationPct();
  const auto vram_map = collectVramSizes();

  std::int32_t device_id = 0;
  int gpu_index = 0;
  for (const auto& wmiResult : wmiReq->results()) {
    Row r;

    std::string pnp_device_id;
    wmiResult.GetString("PNPDeviceID", pnp_device_id);

    std::string vendor_id;
    std::string model_id;
    parsePnpDeviceId(pnp_device_id, vendor_id, model_id);

    if (!vendor_id.empty()) {
      r["vendor_id"] = vendor_id;
    }
    if (!model_id.empty()) {
      r["model_id"] = model_id;
    }

    // pci_slot: the PCI bus address in the same format as Linux
    // (e.g. "0000:01:00.0"), resolved via Win32_PnPEntity.LocationInformation.
    // Non-PCI adapters (ROOT\BasicDisplay, virtual adapters) have no PCI
    // location and leave the column empty.
    auto slot_it = address_by_pnp_id.find(pnp_device_id);
    if (slot_it != address_by_pnp_id.end()) {
      r["pci_slot"] = slot_it->second;
    }

    // device_id: derived from the PCI address so it is stable across reboots;
    // WMI enumeration order is not guaranteed. The counter is only a fallback
    // for devices without a slot.
    if (r["pci_slot"].empty()) {
      r["device_id"] = "GPU" + std::to_string(device_id++);
    } else {
      r["device_id"] = "GPU" + r["pci_slot"];
    }

    wmiResult.GetString("Name", r["name"]);
    wmiResult.GetString("AdapterCompatibility", r["vendor"]);
    wmiResult.GetString("VideoProcessor", r["model"]);
    wmiResult.GetString("InstalledDisplayDrivers", r["driver"]);

    // VRAM: prefer the 64-bit registry value (HardwareInformation.qwMemorySize)
    // to avoid the 4 GB wrap of Win32_VideoController.AdapterRAM (uint32).
    // Fall back to AdapterRAM when the registry value is unavailable.
    const auto vram_it = vram_map.find(gpu_index);
    if (vram_it != vram_map.end()) {
      r["vram"] = BIGINT(static_cast<long long>(vram_it->second));
    } else {
      unsigned long long adapter_ram = 0;
      if (wmiResult.GetUnsignedLongLong("AdapterRAM", adapter_ram).ok() &&
          adapter_ram > 0) {
        r["vram"] = BIGINT(adapter_ram);
      } else {
        unsigned long ram = 0;
        if (wmiResult.GetUnsignedLong("AdapterRAM", ram).ok() && ram > 0) {
          r["vram"] = BIGINT(ram);
        }
      }
    }

    // GPU utilization: phys_N in GPUEngine perf counters is assumed to match
    // enumeration order.
    const auto util_it = util_map.find(gpu_index);
    if (util_it != util_map.end()) {
      r["gpu_utilization_pct"] = DOUBLE(util_it->second);
    }

    // Only PCI adapters carry a PCI class: Win32_VideoController also
    // enumerates non-PCI adapters (ROOT\... devices, virtual video
    // adapters).
    if (pnp_device_id.rfind("PCI\\", 0) == 0) {
      r["pci_class_id"] = "0x030000";
    }

    // Windows-specific extended schema columns.
    wmiResult.GetString("DriverVersion", r["driver_version"]);
    std::string cim_driver_date;
    wmiResult.GetString("DriverDate", cim_driver_date);
    if (!cim_driver_date.empty()) {
      r["driver_date"] = BIGINT(cimDatetimeToUnixtime(cim_driver_date));
    }

    results.push_back(r);
    ++gpu_index;
  }

  return results;
}

} // namespace tables
} // namespace osquery