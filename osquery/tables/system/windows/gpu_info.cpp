/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>

#include <cstdio>
#include <map>
#include <string>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>

#include <osquery/core/windows/wmi.h>
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

  std::int32_t device_id = 0;
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

    // VRAM: AdapterRAM is a uint32 and wraps at 4 GB. Try the registry-backed
    // WMI property first; fall back to AdapterRAM.
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
  }

  return results;
}

} // namespace tables
} // namespace osquery