
/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/tables/system/smbios_utils.h>

namespace osquery {
namespace tables {

/**
 * @brief A flexible SMBIOS parser for Linux.
 *
 * The parsing work is within SMBIOSParser and is shared between platforms.
 * Each OS should implement a discover and set method that implements the
 * OS-specific SMBIOS facilities.
 *
 * On Linux SMBIOS is 'discovered' by reading from known locations in
 * virtual memory or on newer systems, through the sysfs.
 */
class LinuxSMBIOSParser : public SMBIOSParser {
 public:
  /// Attempt to read the system table and SMBIOS from an address.
  void readFromAddress(size_t address, size_t length);

  /// Parse the SMBIOS address from an EFI systab file.
  void readFromSystab(const std::string& systab);

  /// Parse the SMBIOS content from sysfs.
  void readFromSysfs(const std::string& sysfs_dmi);

  /// Cross version/boot read initializer.
  bool discover();

  /// Check if the read was successful.
  bool valid() {
    return (table_data_ != nullptr);
  }

 public:
  virtual ~LinuxSMBIOSParser() {
    if (data_ != nullptr) {
      free(data_);
      data_ = nullptr;
    }
    if (table_data_ != nullptr) {
      free(table_data_);
      table_data_ = nullptr;
    }
  }

 private:
  bool discoverTables(size_t address, size_t length);

  /// Hold the raw SMBIOS memory read.
  uint8_t* data_{nullptr};
};

} // namespace tables
} // namespace osquery
