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
#include <osquery/sql/sql.h>
#include <osquery/utils/conversions/darwin/iokit.h>

namespace osquery {
namespace tables {

// rootless configuration flags
// https://opensource.apple.com/source/xnu/xnu-3248.20.55/bsd/sys/csr.h
const std::map<std::string, uint32_t> kRootlessConfigFlags = {
    // CSR_ALLOW_UNTRUSTED_KEXTS
    {"allow_untrusted_kexts", (1 << 0)},
    // CSR_ALLOW_UNRESTRICTED_FS
    {"allow_unrestricted_fs", (1 << 1)},
    // CSR_ALLOW_TASK_FOR_PID
    {"allow_task_for_pid", (1 << 2)},
    // CSR_ALLOW_KERNEL_DEBUGGER
    {"allow_kernel_debugger", (1 << 3)},
    // CSR_ALLOW_APPLE_INTERNAL
    {"allow_apple_internal", (1 << 4)},
    // CSR_ALLOW_UNRESTRICTED_DTRACE
    {"allow_unrestricted_dtrace", (1 << 5)},
    // CSR_ALLOW_UNRESTRICTED_NVRAM
    {"allow_unrestricted_nvram", (1 << 6)},
    // CSR_ALLOW_DEVICE_CONFIGURATION
    {"allow_device_configuration", (1 << 7)},
};

#define kIODeviceTreeChosenPath_ "IODeviceTree:/options"
typedef uint32_t csr_config_t;

extern "C" {
int csr_check(csr_config_t mask);
int csr_get_active_config(csr_config_t* config);
};

Status genCsrConfigFromNvram(uint32_t& config) {
  auto chosen =
      IORegistryEntryFromPath(kIOMasterPortDefault, kIODeviceTreeChosenPath_);
  if (chosen == MACH_PORT_NULL) {
    return Status(1, "Could not open IOKit DeviceTree");
  }

  CFMutableDictionaryRef properties = nullptr;
  auto kr = IORegistryEntryCreateCFProperties(
      chosen, &properties, kCFAllocatorDefault, kNilOptions);
  IOObjectRelease(chosen);

  if (kr != KERN_SUCCESS) {
    return Status(1, "Could not get IOKit options");
  }

  if (properties == nullptr) {
    return Status(1, "Could not load IOKit properties");
  }

  CFTypeRef csr_config = nullptr;
  if (CFDictionaryGetValueIfPresent(
          properties, CFSTR("csr-active-config"), &csr_config)) {
    if (CFGetTypeID(csr_config) != CFDataGetTypeID()) {
      CFRelease(properties);
      return Status(1, "Unexpected data type for csr-active-config");
    }

    unsigned char buffer[4] = {0};
    CFDataGetBytes((CFDataRef)csr_config,
                   CFRangeMake(0, CFDataGetLength((CFDataRef)csr_config)),
                   (UInt8*)buffer);
    CFRelease(properties);
    memcpy(&config, buffer, sizeof(uint32_t));
    return Status{0};
  } else {
    CFRelease(properties);
    // The case where csr-active-config is cleared or not set is not an error
    return Status::success();
  }
}

QueryData genSIPConfig(QueryContext& context) {
  auto os_version = SQL::selectAllFrom("os_version");
  if (os_version.size() != 1) {
    VLOG(1) << "Could not determine OS version";
    return {};
  }

  // bail out if running on OS X < 10.11
  if (os_version.front().at("major") == "10" &&
      std::stoi(os_version.front().at("minor")) < 11) {
    VLOG(1) << "Not running on OS X 10.11 or higher";
    return {};
  }

  QueryData results;
  csr_config_t config = 0;
  csr_get_active_config(&config);

  csr_config_t valid_allowed_flags = 0;
  for (const auto& kv : kRootlessConfigFlags) {
    valid_allowed_flags |= kv.second;
  }

  Row r;
  r["config_flag"] = "sip";
  if (config == 0) {
    // SIP is enabled (default)
    r["enabled"] = INTEGER(1);
    r["enabled_nvram"] = INTEGER(1);
  } else if ((config | valid_allowed_flags) == valid_allowed_flags) {
    // mark SIP as NOT enabled (i.e. disabled) if
    // any of the valid_allowed_flags is set
    r["enabled"] = INTEGER(0);
    r["enabled_nvram"] = INTEGER(0);
  }
  results.push_back(r);

  uint32_t nvram_config = 0;
  auto nvram_status = genCsrConfigFromNvram(nvram_config);
  for (const auto& kv : kRootlessConfigFlags) {
    r["config_flag"] = kv.first;
    // csr_check returns zero if the config flag is allowed
    r["enabled"] = (csr_check(kv.second) == 0) ? INTEGER(1) : INTEGER(0);
    if (nvram_status.ok()) {
      r["enabled_nvram"] = (nvram_config & kv.second) ? INTEGER(1) : INTEGER(0);
    } else {
      r["enabled_nvram"] = INTEGER(-1);
    }
    results.push_back(r);
  }

  return results;
}
}
}
