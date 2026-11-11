/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include <boost/algorithm/string.hpp>

#include <osquery/core/tables.h>
#include <osquery/events/linux/udev.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace tables {

namespace {

// PCI class IDs for display controllers (high byte of PCI class code).
const std::string kPCIDisplayClass = "03";

// udev property keys for GPU discovery and stable device IDs.
const std::string kGpuPCIKeySlot = "PCI_SLOT_NAME";
const std::string kGpuPCIClassID = "PCI_CLASS";

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
  if (const auto val = tryTo<double>(temp); !val.isError()) {
    data.temp_celsius = val.get() / 1000.0;
  }

  // Power draw: prefer time-averaged value, fall back to instantaneous.
  for (const auto* power_file : {"power1_average", "power1_input"}) {
    const std::string power = readSysfsAttr(hwmon_path, power_file);
    if (!power.empty()) {
      // Kernel reports in microwatts.
      if (const auto val = tryTo<double>(power); !val.isError()) {
        data.power_draw_watts = val.get() / 1000000.0;
      }
      break;
    }
  }

  // Power limit (cap): in microwatts.
  const std::string power_cap = readSysfsAttr(hwmon_path, "power1_cap");
  if (const auto val = tryTo<double>(power_cap); !val.isError()) {
    data.power_limit_watts = val.get() / 1000000.0;
  }

  // Fan speed: derive percentage from RPM / max_RPM.
  const std::string fan_input = readSysfsAttr(hwmon_path, "fan1_input");
  const std::string fan_max = readSysfsAttr(hwmon_path, "fan1_max");
  const auto fan_in_val = tryTo<double>(fan_input);
  const auto fan_max_val = tryTo<double>(fan_max);
  if (!fan_in_val.isError() && !fan_max_val.isError() &&
      fan_max_val.get() > 0.0) {
    data.fan_speed_pct = (fan_in_val.get() / fan_max_val.get()) * 100.0;
  }

  return data;
}

// Read GPU engine busy percentage from sysfs. AMD (amdgpu) exposes this as
// gpu_busy_percent directly on the PCI device node.
std::optional<double> readGpuBusyPercent(const std::string& pci_syspath) {
  const auto val =
      tryTo<double>(readSysfsAttr(pci_syspath, "gpu_busy_percent"));
  if (val.isError()) {
    return std::nullopt;
  }
  return val.get();
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

  udev_enumerate_add_match_subsystem(enumerate.get(), "pci");
  udev_enumerate_scan_devices(enumerate.get());

  struct udev_list_entry *device_entries, *entry;
  device_entries = udev_enumerate_get_list_entry(enumerate.get());

  std::int32_t device_id = 0;
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
    const std::string pci_slot =
        UdevEventPublisher::getValue(device.get(), kGpuPCIKeySlot);
    if (pci_slot.empty()) {
      r["device_id"] = "GPU" + std::to_string(device_id++);
    } else {
      r["device_id"] = "GPU" + pci_slot;
    }

    const char* syspath_c = udev_device_get_syspath(device.get());
    const std::string syspath(syspath_c != nullptr ? syspath_c : "");

    if (!syspath.empty()) {
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
