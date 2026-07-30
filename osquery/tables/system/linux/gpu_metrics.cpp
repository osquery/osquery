/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream>
#include <memory>
#include <optional>
#include <string>

#include <boost/algorithm/string.hpp>

#include <osquery/core/tables.h>
#include <osquery/events/linux/udev.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/linux/pci_devices.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace tables {

namespace {

// PCI class IDs for display controllers (high byte of PCI class code).
const std::string kPCIDisplayClass = "03";

// udev property keys reused from pci_devices.
const std::string kGpuPCIKeySlot = "PCI_SLOT_NAME";
const std::string kGpuPCIKeyVendor = "ID_VENDOR_FROM_DATABASE";
const std::string kGpuPCIKeyModel = "ID_MODEL_FROM_DATABASE";
const std::string kGpuPCIKeyID = "PCI_ID";
const std::string kGpuPCISubsysID = "PCI_SUBSYS_ID";
const std::string kGpuPCIClassID = "PCI_CLASS";
const std::string kGpuPCIKeyDriver = "DRIVER";

// Read a single-line sysfs attribute. Returns empty string on failure.
std::string readSysfsAttr(const std::string& syspath, const std::string& attr) {
  std::string content;
  if (!readFile(syspath + "/" + attr, content, false).ok()) {
    return "";
  }
  // sysfs files are single-line; drop everything after the first newline.
  auto nl = content.find('\n');
  if (nl != std::string::npos) {
    content.resize(nl);
  }
  boost::algorithm::trim(content);
  return content;
}

// Try to read VRAM size (in bytes) from sysfs for the device at syspath.
// AMD GPUs expose mem_info_vram_total; other drivers generally do not.
long long readVramBytes(const std::string& syspath) {
  return tryTo<long long>(readSysfsAttr(syspath, "mem_info_vram_total"))
      .takeOr(-1LL);
}

// Try to read the NVIDIA driver version from /sys/module/nvidia/version.
std::string readNvidiaDriverVersion() {
  return readSysfsAttr("/sys/module/nvidia", "version");
}

// Read the kernel module version from the driver bound to the PCI device.
std::string readGenericDriverVersion(const std::string& pci_syspath) {
  return readSysfsAttr(pci_syspath + "/driver/module", "version");
}

// Returns true when the PCI_CLASS value indicates a display controller.
// udev reports PCI_CLASS as a hex string with the leading zero stripped when
// the class byte is < 0x10, so both 5-char ("30200") and 6-char ("030200")
// forms must be handled.
bool isDisplayClass(const std::string& pci_class_attr) {
  std::string norm = pci_class_attr;
  boost::algorithm::to_lower(norm);
  std::string class_byte;
  if (norm.size() == 5) {
    class_byte = "0" + norm.substr(0, 1);
  } else if (norm.size() == 6) {
    class_byte = norm.substr(0, 2);
  } else {
    return false;
  }
  return class_byte == kPCIDisplayClass;
}

// Returns the path to the first hwmon directory under {pci_syspath}/hwmon/,
// or empty string if none found.
std::string findHwmonPath(const std::string& pci_syspath) {
  std::vector<std::string> matches;
  resolveFilePattern(pci_syspath + "/hwmon/hwmon*", matches, GLOB_FOLDERS);
  return matches.empty() ? "" : matches.front();
}

struct HwmonData {
  std::optional<double> temp_celsius;
  std::optional<double> power_draw_watts;
  std::optional<double> power_limit_watts;
  std::optional<double> fan_speed_pct;
};

// Read hardware-monitor telemetry from the kernel hwmon interface for the
// given PCI device syspath. Works for AMD (amdgpu) and NVIDIA (nouveau/nvidia)
// drivers that expose standard hwmon attributes.
HwmonData readHwmonData(const std::string& pci_syspath) {
  HwmonData data;
  const std::string hwmon_path = findHwmonPath(pci_syspath);
  if (hwmon_path.empty()) {
    return data;
  }

  // Temperature: temp1_input is in millidegrees Celsius.
  const std::string temp = readSysfsAttr(hwmon_path, "temp1_input");
  if (!temp.empty()) {
    try {
      data.temp_celsius = std::stod(temp) / 1000.0;
    } catch (...) {
    }
  }

  // Power draw: prefer time-averaged value, fall back to instantaneous.
  for (const auto* power_file : {"power1_average", "power1_input"}) {
    const std::string power = readSysfsAttr(hwmon_path, power_file);
    if (!power.empty()) {
      try {
        // Kernel reports in microwatts.
        data.power_draw_watts = std::stod(power) / 1000000.0;
      } catch (...) {
      }
      break;
    }
  }

  // Power limit (cap): in microwatts.
  const std::string power_cap = readSysfsAttr(hwmon_path, "power1_cap");
  if (!power_cap.empty()) {
    try {
      data.power_limit_watts = std::stod(power_cap) / 1000000.0;
    } catch (...) {
    }
  }

  // Fan speed: derive percentage from RPM / max_RPM.
  const std::string fan_input = readSysfsAttr(hwmon_path, "fan1_input");
  const std::string fan_max = readSysfsAttr(hwmon_path, "fan1_max");
  if (!fan_input.empty() && !fan_max.empty()) {
    try {
      const double input = std::stod(fan_input);
      const double max_rpm = std::stod(fan_max);
      if (max_rpm > 0.0) {
        data.fan_speed_pct = (input / max_rpm) * 100.0;
      }
    } catch (...) {
    }
  }

  return data;
}

// Read GPU engine busy percentage from sysfs. AMD (amdgpu) exposes this as
// gpu_busy_percent directly on the PCI device node.
std::optional<double> readGpuBusyPercent(const std::string& pci_syspath) {
  const std::string raw = readSysfsAttr(pci_syspath, "gpu_busy_percent");
  if (raw.empty()) {
    return std::nullopt;
  }
  try {
    return std::stod(raw);
  } catch (...) {
    return std::nullopt;
  }
}

} // namespace

QueryData genGpuMetrics(QueryContext& context) {
  QueryData results;

  auto del_udev = [](udev* u) { udev_unref(u); };
  std::unique_ptr<udev, decltype(del_udev)> udev_handle(udev_new(), del_udev);
  if (udev_handle.get() == nullptr) {
    VLOG(1) << "Could not get udev handle";
    return results;
  }

  auto del_udev_enum = [](udev_enumerate* e) { udev_enumerate_unref(e); };
  std::unique_ptr<udev_enumerate, decltype(del_udev_enum)> enumerate(
      udev_enumerate_new(udev_handle.get()), del_udev_enum);
  if (enumerate.get() == nullptr) {
    VLOG(1) << "Could not get udev_enumerate handle";
    return results;
  }

  // Open pci.ids for vendor/model name resolution.
  std::ifstream pciids_stream;
  for (const std::string& path : kPciidsPathList) {
    if (pathExists(path).ok()) {
      pciids_stream.open(path);
      if (pciids_stream) {
        break;
      }
    }
  }
  if (!pciids_stream.is_open()) {
    VLOG(1) << "Could not open pci.ids at: "
            << osquery::join(kPciidsPathList, " ");
  }
  PciDB pcidb(pciids_stream);

  // Cache the NVIDIA driver version so we look it up at most once.
  std::string nvidia_driver_ver;
  bool nvidia_driver_checked = false;

  udev_enumerate_add_match_subsystem(enumerate.get(), "pci");
  udev_enumerate_scan_devices(enumerate.get());

  struct udev_list_entry *device_entries, *entry;
  device_entries = udev_enumerate_get_list_entry(enumerate.get());

  int gpu_index = 0;
  udev_list_entry_foreach(entry, device_entries) {
    const char* path = udev_list_entry_get_name(entry);

    std::unique_ptr<udev_device, decltype(&udev_device_unref)> device(
        udev_device_new_from_syspath(udev_handle.get(), path),
        udev_device_unref);
    if (device.get() == nullptr) {
      continue;
    }

    std::string pci_class =
        UdevEventPublisher::getValue(device.get(), kGpuPCIClassID);
    if (!isDisplayClass(pci_class)) {
      continue;
    }

    Row r;
    r["gpu_index"] = INTEGER(gpu_index++);
    r["pci_bus"] = UdevEventPublisher::getValue(device.get(), kGpuPCIKeySlot);

    // Prefer pci.ids names; fall back to udev database strings.
    r["vendor_name"] =
        UdevEventPublisher::getValue(device.get(), kGpuPCIKeyVendor);
    r["device_name"] =
        UdevEventPublisher::getValue(device.get(), kGpuPCIKeyModel);

    auto status = extractVendorModelFromPciDBIfPresent(
        r,
        UdevEventPublisher::getValue(device.get(), kGpuPCIKeyID),
        UdevEventPublisher::getValue(device.get(), kGpuPCISubsysID),
        pcidb);
    if (status.ok()) {
      auto it_vendor = r.find("vendor");
      if (it_vendor != r.end() && !it_vendor->second.empty()) {
        r["vendor_name"] = it_vendor->second;
        r.erase(it_vendor);
      }
      auto it_model = r.find("model");
      if (it_model != r.end() && !it_model->second.empty()) {
        r["device_name"] = it_model->second;
        r.erase(it_model);
      }
    }
    // Remove pci.ids helper columns that may have been inserted.
    for (const auto* key : {"vendor_id",
                            "model_id",
                            "subsystem_vendor_id",
                            "subsystem_model_id",
                            "subsystem_vendor",
                            "subsystem_model"}) {
      r.erase(key);
    }

    // Driver version: NVIDIA uses /sys/module/nvidia/version; others use the
    // generic driver/module/version sysfs path.
    std::string driver =
        UdevEventPublisher::getValue(device.get(), kGpuPCIKeyDriver);
    const char* syspath_c = udev_device_get_syspath(device.get());
    const std::string syspath(syspath_c != nullptr ? syspath_c : "");
    std::string driver_ver;
    if (driver == "nvidia") {
      if (!nvidia_driver_checked) {
        nvidia_driver_ver = readNvidiaDriverVersion();
        nvidia_driver_checked = true;
      }
      driver_ver = nvidia_driver_ver;
    } else if (!driver.empty() && !syspath.empty()) {
      driver_ver = readGenericDriverVersion(syspath);
    }
    if (!driver_ver.empty()) {
      r["driver_version"] = driver_ver;
    }

    if (!syspath.empty()) {
      // VRAM: AMD exposes mem_info_vram_total in sysfs.
      const long long vram = readVramBytes(syspath);
      if (vram > 0) {
        r["vram_total_bytes"] = BIGINT(vram);
      }

      // GPU utilization: AMD exposes gpu_busy_percent.
      const auto busy = readGpuBusyPercent(syspath);
      if (busy.has_value()) {
        r["gpu_utilization_pct"] = DOUBLE(*busy);
      }

      // Hardware-monitor telemetry (temperature, power, fan).
      const HwmonData hwmon = readHwmonData(syspath);
      if (hwmon.temp_celsius.has_value()) {
        r["temperature_gpu_celsius"] = DOUBLE(*hwmon.temp_celsius);
      }
      if (hwmon.power_draw_watts.has_value()) {
        r["power_draw_watts"] = DOUBLE(*hwmon.power_draw_watts);
      }
      if (hwmon.power_limit_watts.has_value()) {
        r["power_limit_watts"] = DOUBLE(*hwmon.power_limit_watts);
      }
      if (hwmon.fan_speed_pct.has_value()) {
        r["fan_speed_pct"] = DOUBLE(*hwmon.fan_speed_pct);
      }
    }

    results.emplace_back(std::move(r));
  }

  return results;
}

} // namespace tables
} // namespace osquery
