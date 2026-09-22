/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <memory>
#include <optional>
#include <string_view>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/events/linux/udev.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/linux/pci_devices.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace tables {

namespace {

const std::string kDrmSysfsPath = "/sys/class/drm";

// udev property names for PCI device attributes; these mirror the constants
// in pci_devices.cpp, which are not exported through a header.
const std::string kPCIClassID = "PCI_CLASS";
const std::string kPCIKeySlot = "PCI_SLOT_NAME";
const std::string kPCIKeyDriver = "DRIVER";
const std::string kPCIKeyID = "PCI_ID";
const std::string kPCISubsysID = "PCI_SUBSYS_ID";
const std::string kPCIKeyVendor = "ID_VENDOR_FROM_DATABASE";
const std::string kPCIKeyModel = "ID_MODEL_FROM_DATABASE";

std::string readSysFile(const std::string& path) {
  std::string content;
  if (!readFile(path, content).ok()) {
    return {};
  }
  boost::trim(content);
  return content;
}

std::string drmCardNameToDevicePath(const std::string& drm_dir,
                                    const std::string& card_name) {
  auto target = drm_dir + "/" + card_name + "/device";
  boost::filesystem::path resolved;
  if (!boost::filesystem::exists(target)) {
    return {};
  }
  try {
    resolved = boost::filesystem::canonical(target);
  } catch (const boost::filesystem::filesystem_error&) {
    return {};
  }
  return resolved.string();
}

void collectVramFromDrm(std::map<std::string, std::uint64_t>& vram_by_slot) {
  std::vector<std::string> drm_entries;
  if (!listDirectoriesInDirectory(kDrmSysfsPath, drm_entries).ok()) {
    return;
  }

  for (const auto& entry : drm_entries) {
    // listDirectoriesInDirectory returns full paths; only the entry name
    // (card0, card1, ...) identifies the DRM device.
    const auto card_name = boost::filesystem::path(entry).filename().string();

    // Select card0, card1, ... only: the prefix match excludes renderD*
    // siblings and the hyphen check excludes connector entries
    // (card0-eDP-1).
    if (card_name.rfind("card", 0) != 0 ||
        card_name.find("-") != std::string::npos) {
      continue;
    }

    auto device_path = drmCardNameToDevicePath(kDrmSysfsPath, card_name);
    if (device_path.empty()) {
      continue;
    }

    std::string vram;
    auto mem_info_vram_total =
        readSysFile(device_path + "/mem_info_vram_total");
    if (!mem_info_vram_total.empty()) {
      vram = mem_info_vram_total;
    }

    if (vram.empty()) {
      continue;
    }

    auto vram_exp = tryTo<std::uint64_t>(vram, 10);
    if (vram_exp.isError()) {
      continue;
    }

    std::string slot;
    auto slot_path = device_path + "/uevent";
    auto uevent = readSysFile(slot_path);
    for (const auto& line : split(uevent, "\n")) {
      if (line.find("PCI_SLOT_NAME=") == 0) {
        slot = line.substr(std::string_view("PCI_SLOT_NAME=").size());
        boost::trim(slot);
        break;
      }
    }

    if (!slot.empty()) {
      vram_by_slot[slot] = vram_exp.take();
    }
  }
}

void enrichVram(Row& row,
                const std::map<std::string, std::uint64_t>& vram_by_slot) {
  auto slot_it = row.find("pci_slot");
  if (slot_it == row.end() || slot_it->second.empty()) {
    return;
  }

  auto vram_it = vram_by_slot.find(slot_it->second);
  if (vram_it != vram_by_slot.end()) {
    row["vram"] = BIGINT(vram_it->second);
  }
}

// NVML is the NVIDIA Management Library, the interface behind nvidia-smi.
// The proprietary driver exposes no sysfs file with the video memory size, so
// the fixed capacity of NVIDIA GPUs is read from NVML instead. The library is
// part of the driver userland, ships with no stable header to build against
// and is absent on non-NVIDIA systems, so it is opened dynamically at query
// time and every failure is tolerated: the vram column stays empty.
const std::vector<std::string> kNvmlLibraryNames{"libnvidia-ml.so.1",
                                                 "libnvidia-ml.so"};

// Mirrors nvmlMemory_t from NVIDIA's nvml.h. Only the layout matters, and
// only the first field is consumed: total is the physical VRAM capacity.
struct NvmlMemory {
  std::uint64_t total;
  std::uint64_t free;
  std::uint64_t used;
};

// The two nvmlReturn_t values compared directly; every other result is only
// passed to nvmlErrorString. NVML_SUCCESS has been 0 in every NVML release.
enum NvmlResult {
  kNvmlSuccess = 0,
  kNvmlErrorNotFound = 6,
};

extern "C" {
typedef int (*NvmlInitFn)();
typedef int (*NvmlShutdownFn)();
typedef const char* (*NvmlErrorStringFn)(int result);
typedef int (*NvmlGetHandleByPciBusIdFn)(const char* pci_bus_id, void** device);
typedef int (*NvmlGetMemoryInfoFn)(void* device, NvmlMemory* memory);
}

// The NVML symbols resolved from the dynamically opened library, plus the
// dlopen handle they came from.
struct NvmlApi {
  void* library{nullptr};

  NvmlInitFn init{nullptr};
  NvmlShutdownFn shutdown{nullptr};
  NvmlErrorStringFn error_string{nullptr};
  NvmlGetHandleByPciBusIdFn get_handle_by_pci_bus_id{nullptr};
  NvmlGetMemoryInfoFn get_memory_info{nullptr};
};

struct NvmlApiCloser {
  void operator()(NvmlApi* api) const {
    if (api != nullptr && api->library != nullptr) {
      dlclose(api->library);
    }
    delete api;
  }
};

using NvmlApiPtr = std::unique_ptr<NvmlApi, NvmlApiCloser>;

NvmlApiPtr loadNvmlApi() {
  for (const auto& library_name : kNvmlLibraryNames) {
    auto library = dlopen(library_name.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (library == nullptr) {
      VLOG(1) << "NVML is not available: " << dlerror();
      continue;
    }

    auto api = NvmlApiPtr(new NvmlApi());
    api->library = library;
    api->init = reinterpret_cast<NvmlInitFn>(dlsym(library, "nvmlInit_v2"));
    api->shutdown =
        reinterpret_cast<NvmlShutdownFn>(dlsym(library, "nvmlShutdown"));
    api->error_string =
        reinterpret_cast<NvmlErrorStringFn>(dlsym(library, "nvmlErrorString"));
    api->get_handle_by_pci_bus_id = reinterpret_cast<NvmlGetHandleByPciBusIdFn>(
        dlsym(library, "nvmlDeviceGetHandleByPciBusId_v2"));
    api->get_memory_info = reinterpret_cast<NvmlGetMemoryInfoFn>(
        dlsym(library, "nvmlDeviceGetMemoryInfo"));

    if (api->init == nullptr || api->shutdown == nullptr ||
        api->error_string == nullptr ||
        api->get_handle_by_pci_bus_id == nullptr ||
        api->get_memory_info == nullptr) {
      VLOG(1) << "NVML at " << library_name
              << " is missing required symbols, NVIDIA GPUs cannot be queried";
      continue;
    }

    return api;
  }

  return nullptr;
}

// Fills the vram column of the rows that could not be read from sysfs and
// that have a PCI address NVML can be queried with. NVML addresses GPUs by
// PCI bus id in the same domain:bus:device.function form udev reports in
// PCI_SLOT_NAME, so each row is looked up by its own slot and identical GPUs
// cannot be confused.
void enrichVramFromNvml(QueryData& results) {
  std::vector<Row*> gpus_without_vram;
  for (auto& row : results) {
    auto vram_it = row.find("vram");
    bool has_vram = vram_it != row.end() && !vram_it->second.empty();
    auto slot_it = row.find("pci_slot");
    bool has_slot = slot_it != row.end() && !slot_it->second.empty();

    if (!has_vram && has_slot) {
      gpus_without_vram.push_back(&row);
    }
  }

  if (gpus_without_vram.empty()) {
    return;
  }

  auto nvml = loadNvmlApi();
  if (nvml == nullptr) {
    return;
  }

  auto result = nvml->init();
  if (result != kNvmlSuccess) {
    VLOG(1) << "Cannot initialize NVML: " << nvml->error_string(result);
    return;
  }

  for (auto* row : gpus_without_vram) {
    const auto& pci_slot = row->at("pci_slot");

    void* device = nullptr;
    result = nvml->get_handle_by_pci_bus_id(pci_slot.c_str(), &device);
    if (result == kNvmlErrorNotFound) {
      // No NVIDIA GPU at this slot.
      continue;
    }
    if (result != kNvmlSuccess) {
      VLOG(1) << "NVML cannot access the GPU at PCI slot " << pci_slot << ": "
              << nvml->error_string(result);
      continue;
    }

    NvmlMemory memory{};
    result = nvml->get_memory_info(device, &memory);
    if (result != kNvmlSuccess) {
      VLOG(1) << "NVML cannot read the memory of the GPU at PCI slot "
              << pci_slot << ": " << nvml->error_string(result);
      continue;
    }

    if (memory.total > 0) {
      (*row)["vram"] = BIGINT(memory.total);
    }
  }

  nvml->shutdown();
}

// udev reports PCI_CLASS as the 24-bit class code in hex without the 0x
// prefix and with insignificant leading zeroes stripped (e.g. display
// controllers report "30000", i.e. 0x030000). The other platforms publish
// the full code, so normalize to the fixed "0xrrccss" form to keep the
// shared column identical across platforms. Returns an empty string for
// values that are not valid class codes.
std::string normalizePciClassId(const std::string& pci_class_attr) {
  std::string lowered = pci_class_attr;
  boost::algorithm::to_lower(lowered);
  boost::trim(lowered);

  // Strip an optional 0x prefix.
  if (lowered.rfind("0x", 0) == 0) {
    lowered = lowered.substr(2);
  }

  if (lowered.empty()) {
    return {};
  }

  auto class_exp = tryTo<std::uint32_t>(lowered, 16);
  if (class_exp.isError()) {
    return {};
  }

  char class_id[16];
  std::snprintf(class_id, sizeof(class_id), "0x%06x", class_exp.take());
  return class_id;
}

bool isDisplayControllerClass(const std::string& pci_class_id) {
  // pci_class_id is the normalized 0xrrccss form; the display controller
  // base class is 0x03.
  return pci_class_id.size() >= 4 && pci_class_id.compare(2, 2, "03") == 0;
}

// Read a single-line sysfs attribute from a device path. Returns empty string
// on failure. Used for telemetry attributes that live on the PCI device node
// or its hwmon child.
std::string readSysfsAttr(const std::string& syspath, const std::string& attr) {
  std::string content;
  if (!readFile(syspath + "/" + attr, content, false).ok()) {
    return "";
  }
  auto nl = content.find('\n');
  if (nl != std::string::npos) {
    content.resize(nl);
  }
  boost::trim(content);
  return content;
}

// Try to read the NVIDIA driver version from /sys/module/nvidia/version.
std::string readNvidiaDriverVersion() {
  return readSysfsAttr("/sys/module/nvidia", "version");
}

// Read the kernel module version from the driver bound to the PCI device.
std::string readGenericDriverVersion(const std::string& pci_syspath) {
  return readSysfsAttr(pci_syspath + "/driver/module", "version");
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
  const auto val = tryTo<double>(readSysfsAttr(pci_syspath, "gpu_busy_percent"));
  if (val.isError()) {
    return std::nullopt;
  }
  return val.get();
}

} // namespace

QueryData genGpuInfo(QueryContext& context) {
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

  std::ifstream raw;
  for (const std::string& pci_ids_path : kPciidsPathList) {
    if (pathExists(pci_ids_path)) {
      raw.open(pci_ids_path);
      if (raw) {
        break;
      }
    }
  }

  std::unique_ptr<PciDB> pcidb;
  if (raw.is_open()) {
    pcidb = std::make_unique<PciDB>(raw);
  } else {
    VLOG(1) << "Unexpected error attempting to read pci.ids at path: "
            << osquery::join(kPciidsPathList, " ");
  }

  std::map<std::string, std::uint64_t> vram_by_slot;
  collectVramFromDrm(vram_by_slot);

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

    auto pci_class_id = normalizePciClassId(
        UdevEventPublisher::getValue(device.get(), kPCIClassID));
    if (!isDisplayControllerClass(pci_class_id)) {
      continue;
    }

    Row r;
    r["pci_slot"] = UdevEventPublisher::getValue(device.get(), kPCIKeySlot);
    // device_id: derived from the PCI address so it is stable across reboots;
    // udev enumeration order is not guaranteed. The counter is only a fallback
    // for devices without a slot.
    if (r["pci_slot"].empty()) {
      r["device_id"] = "GPU" + std::to_string(device_id++);
    } else {
      r["device_id"] = "GPU" + r["pci_slot"];
    }
    r["pci_class_id"] = pci_class_id;
    r["driver"] = UdevEventPublisher::getValue(device.get(), kPCIKeyDriver);

    // Driver version: NVIDIA uses /sys/module/nvidia/version; others use the
    // generic driver/module/version sysfs path.
    std::string driver =
        UdevEventPublisher::getValue(device.get(), kPCIKeyDriver);
    const char* syspath_c = udev_device_get_syspath(device.get());
    const std::string syspath(syspath_c != nullptr ? syspath_c : "");
    std::string driver_ver;
    if (driver == "nvidia") {
      driver_ver = readNvidiaDriverVersion();
    } else if (!driver.empty() && !syspath.empty()) {
      driver_ver = readGenericDriverVersion(syspath);
    }
    if (!driver_ver.empty()) {
      r["driver_version"] = driver_ver;
    }

    if (pcidb != nullptr) {
      auto status = extractVendorModelFromPciDBIfPresent(
          r,
          UdevEventPublisher::getValue(device.get(), kPCIKeyID),
          UdevEventPublisher::getValue(device.get(), kPCISubsysID),
          *pcidb);
      if (!status.ok()) {
        VLOG(1) << "Unexpected error extracting GPU PCI info: "
                << status.getMessage();
      }
    }

    auto vendor_db = UdevEventPublisher::getValue(device.get(), kPCIKeyVendor);
    auto model_db = UdevEventPublisher::getValue(device.get(), kPCIKeyModel);
    if (r["vendor"].empty() && !vendor_db.empty()) {
      r["vendor"] = vendor_db;
    }
    if (r["model"].empty() && !model_db.empty()) {
      r["model"] = model_db;
    }

    if (!r["model"].empty()) {
      r["name"] = r["model"];
    }

    enrichVram(r, vram_by_slot);

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

  // The DRM sysfs files only cover AMD GPUs; NVML fills in NVIDIA ones.
  enrichVramFromNvml(results);

  return results;
}

} // namespace tables
} // namespace osquery