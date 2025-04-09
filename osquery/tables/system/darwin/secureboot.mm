/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <memory>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/darwin/system_profiler.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach_error.h>

namespace osquery::tables {

namespace {

enum class SecureBootMode {
  NoSecurity,
  FullSecurity,
  MediumSecurity,
};

struct IoRegistryEntryDeleter final {
  using pointer = io_registry_entry_t;

  void operator()(pointer p) {
    if (p == 0) {
      return;
    }

    IOObjectRelease(p);
  }
};

template <typename Type>
struct TypeDeleter final {
  using pointer = Type;

  void operator()(pointer p) {
    CFRelease(p);
  }
};

using UniqueIoRegistryEntry =
    std::unique_ptr<io_registry_entry_t, IoRegistryEntryDeleter>;

using UniqueCFStringRef =
    std::unique_ptr<CFStringRef, TypeDeleter<CFStringRef>>;

using UniqueCFTypeRef = std::unique_ptr<CFTypeRef, TypeDeleter<CFTypeRef>>;

const std::string kOptionsRegistryEntryPath{"IODeviceTree:/options"};

const std::string kVariableName{
    "94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy"};

bool openRegistryEntry(UniqueIoRegistryEntry& entry, const std::string& path) {
  static mach_port_t master_port{};
  if (master_port == 0 &&
      IOMasterPort(bootstrap_port, &master_port) != KERN_SUCCESS) {
    return false;
  }

  auto entry_ref = IORegistryEntryFromPath(master_port, path.c_str());
  if (entry_ref == 0) {
    return false;
  }

  entry.reset(entry_ref);
  return true;
}

bool createCFStringVariable(UniqueCFStringRef& name,
                            const std::string& variable) {
  auto name_ref = CFStringCreateWithCString(
      kCFAllocatorDefault, kVariableName.c_str(), kCFStringEncodingUTF8);
  if (name_ref == nullptr) {
    return false;
  }

  name.reset(name_ref);
  return true;
}

bool createIORegisteryEntry(UniqueIoRegistryEntry& options,
                            UniqueCFStringRef& name,
                            UniqueCFTypeRef& value) {
  auto value_ref =
      IORegistryEntryCreateCFProperty(options.get(), name.get(), 0, 0);
  if (value_ref == nullptr) {
    return false;
  }

  value.reset(value_ref);
  return true;
}

Status getSecureBootModeFromValue(UniqueCFTypeRef& value,
                                  SecureBootMode& mode) {
  if (CFGetTypeID(value.get()) != CFDataGetTypeID()) {
    return Status::failure("Mismatch type ID for the variable: " +
                           kVariableName);
  }

  auto data_length = CFDataGetLength(static_cast<CFDataRef>(value.get()));
  if (data_length != 1) {
    return Status::failure("Cannot get data length for the variable: " +
                           kVariableName);
  }

  auto data_ptr = CFDataGetBytePtr(static_cast<CFDataRef>(value.get()));
  switch (*data_ptr) {
  case 2:
    mode = SecureBootMode::FullSecurity;
    break;

  case 1:
    mode = SecureBootMode::MediumSecurity;
    break;

  case 0:
    mode = SecureBootMode::NoSecurity;
    break;

  default:
    return Status::failure("Invalid SecureBootMode value");
  }

  return Status::success();
}

Status getIntelSecureBootSetting(Row& row) {
  SecureBootMode mode{SecureBootMode::NoSecurity};

  UniqueIoRegistryEntry options_entry;
  if (!openRegistryEntry(options_entry, kOptionsRegistryEntryPath.c_str())) {
    return Status::failure("Cannot open registry entry: " +
                           kOptionsRegistryEntryPath);
  }

  UniqueCFStringRef name;
  if (!createCFStringVariable(name, kVariableName)) {
    return Status::failure("Cannot create CFString for NVRAM variable: " +
                           kVariableName);
  }

  // NOTE: Create CF representation of the registry entry's property. This
  //       creates instantaneous snapshot for the NVRAM variable.
  //       Secure boot feature is available with Apple T2 chip-set onward and
  //       NMRAM variable may not be available as one of the registry property
  //       if secure boot is not supported. Set secure boot flag to 0 in such
  //       case and return.

  UniqueCFTypeRef value;
  if (!createIORegisteryEntry(options_entry, name, value)) {
    LOG(INFO) << "Unable to create snapshot of NVRAM variable: "
              << kVariableName << ". Secureboot feature does not exist!";
    return Status::success();
  }

  auto status = getSecureBootModeFromValue(value, mode);
  if (!status.ok()) {
    return status;
  }

  row["secure_boot"] = BIGINT(mode != SecureBootMode::NoSecurity);
  row["secure_mode"] = BIGINT(static_cast<int>(mode));
  return Status::success();
}

Status getAarch64SecureBootSetting(Row& r) {
  @autoreleasepool {
    NSDictionary* __autoreleasing result;
    Status status = getSystemProfilerReport("SPiBridgeDataType", result);
    if (!status.ok()) {
      return Status::failure("failed to get secureboot config: " +
                             status.getMessage());
    }

    NSDictionary* report = [[result objectForKey:@"_items"] lastObject];

    if ([report valueForKey:@"ibridge_secure_boot"]) {
      r["description"] =
          SQL_TEXT([[report valueForKey:@"ibridge_secure_boot"] UTF8String]);
      if (r["description"] == "Full Security" ||
          r["description"] == "Reduced Security") {
        r["secure_boot"] = INTEGER(1);
      } else if (r["description"] == "Permissive Security") {
        r["secure_boot"] = INTEGER(0);
      }
    }

    if ([report valueForKey:@"ibridge_sb_other_kext"]) {
      auto value = std::string(
          [[report valueForKey:@"ibridge_sb_other_kext"] UTF8String]);
      if (value == "Yes") {
        r["kernel_extensions"] = INTEGER(1);
      } else if (value == "No") {
        r["kernel_extensions"] = INTEGER(0);
      }
    }

    // Combine both MDM values into a single column (since devices should be in
    // *either* DEP or Manual enrollment)
    if ([report valueForKey:@"ibridge_sb_manual_mdm"] ||
        [report valueForKey:@"ibridge_sb_device_mdm"]) {
      r["mdm_operations"] = INTEGER(0);

      if ([report valueForKey:@"ibridge_sb_manual_mdm"]) {
        auto value = std::string(
            [[report valueForKey:@"ibridge_sb_manual_mdm"] UTF8String]);
        if (value == "Yes") {
          r["mdm_operations"] = INTEGER(1);
        }
      }

      if ([report valueForKey:@"ibridge_sb_device_mdm"]) {
        auto value = std::string(
            [[report valueForKey:@"ibridge_sb_device_mdm"] UTF8String]);
        if (value == "Yes") {
          r["mdm_operations"] = INTEGER(1);
        }
      }
    }
  }

  return Status::success();
}

} // namespace

QueryData genSecureBoot(QueryContext& context) {
  Row row;

#ifdef __aarch64__
  auto status = getAarch64SecureBootSetting(row);
#else
  auto status = getIntelSecureBootSetting(row);
#endif
  if (!status.ok()) {
    LOG(ERROR) << "secureboot error: " << status.toString();
    return {};
  }

  return {row};
}

} // namespace osquery::tables
