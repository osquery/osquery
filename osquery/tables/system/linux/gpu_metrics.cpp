/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <dirent.h>
#include <fstream>
#include <optional>
#include <string>

#include <boost/algorithm/string.hpp>

#include <osquery/core/tables.h>
#include <osquery/events/linux/udev.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/linux/pci_devices.h>
#include <osquery/utils/conversions/join.h>

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
  std::ifstream f(syspath + "/" + attr);
  if (!f.is_open()) {
    return "";
  }
  std::string value;
  std::getline(f, value);
  boost::algorithm::trim(value);
  return value;
}

// Try to read VRAM size (in bytes) from sysfs for the device at syspath.
// AMD GPUs expose mem_info_vram_total; other drivers generally do not.
long long readVramBytes(const std::string& syspath) {
  std::string raw = readSysfsAttr(syspath, "mem_info_vram_total");
  if (raw.empty()) {
    return -1;
  }
  try {
    return std::stoll(raw);
  } catch (...) {
    return -1;
  }
}

// Try to read the NVIDIA driver version from /sys/module/nvidia/version.
std::string readNvidiaDriverVersion() {
  std::ifstream f("/sys/module/nvidia/version");
  if (!f.is_open()) {
    return "";
  }
  std::string ver;
  std::getline(f, ver);
  boost::algorithm::trim(ver);
  return ver;
}

// Returns true when the 6-hex-digit PCI_CLASS value indicates a display
// controller (class code 0x03xx).
bool isDisplayClass(const std::string& pci_class_attr) {
  if (pci_class_attr.size() < 2) {
    return false;
  }
  // PCI_CLASS is reported as a hex string without "0x" prefix, e.g. "030200".
  // The high byte is the base class; 0x03 == Display Controller.
  std::string high = pci_class_attr.substr(0, 2);
  boost::algorithm::to_lower(high);
  return high == kPCIDisplayClass;
}

// Returns the path to the first hwmon directory under {pci_syspath}/hwmon/,
// or empty string if none found.
std::string findHwmonPath(const std::string& pci_syspath) {
  const std::string hwmon_base = pci_syspath + "/hwmon";
  DIR* dir = opendir(hwmon_base.c_str());
  if (dir == nullptr) {
    return "";
  }

  std::string result;
  struct dirent* entry = nullptr;
  while ((entry = readdir(dir)) != nullptr) {
    const std::string name(entry->d_name);
    // hwmon subdirectories are named "hwmonN" where N is one or more digits.
    if (name.size() > 5 && name.rfind("hwmon", 0) == 0) {
      result = hwmon_base + "/" + name;
      break;
    }
  }
  closedir(dir);
  return result;
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
  std::ifstream raw;
  for (const std::string& path : kPciidsPathList) {
    if (pathExists(path)) {
      raw.open(path);
      if (raw) {
        break;
      }
    }
  }
  if (!raw.is_open()) {
    LOG(WARNING) << "Could not open pci.ids at: "
                 << osquery::join(kPciidsPathList, " ");
  }
  PciDB pcidb(raw);

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

    // Driver version: for NVIDIA read the module version file.
    std::string driver =
        UdevEventPublisher::getValue(device.get(), kGpuPCIKeyDriver);
    if (driver == "nvidia") {
      if (!nvidia_driver_checked) {
        nvidia_driver_ver = readNvidiaDriverVersion();
        nvidia_driver_checked = true;
      }
      if (!nvidia_driver_ver.empty()) {
        r["driver_version"] = nvidia_driver_ver;
      }
    }

    const char* syspath_c = udev_device_get_syspath(device.get());
    if (syspath_c != nullptr) {
      const std::string syspath(syspath_c);

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

