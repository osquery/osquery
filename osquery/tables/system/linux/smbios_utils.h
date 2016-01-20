/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include "osquery/tables/system/smbios_utils.h"

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

  /// Cross version/boot read initializer.
  bool discover();

  /// Check if the read was successful.
  bool valid() { return (data_ != nullptr && table_data_ != nullptr); }

 public:
  virtual ~LinuxSMBIOSParser() {
    if (data_ != nullptr) {
      free(data_);
    }
    if (table_data_ != nullptr) {
      free(table_data_);
    }
  }

 private:
  bool discoverTables(size_t address, size_t length);

  /// Hold the raw SMBIOS memory read.
  uint8_t* data_{nullptr};
};
}
}
