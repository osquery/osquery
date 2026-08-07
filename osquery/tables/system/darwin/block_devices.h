/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <boost/optional.hpp>

namespace osquery::tables {

/// Information about a disk, such as size, vendor and model
struct DiskInformation final {
  /// The device protocol, such as PCI Express
  std::string protocol;

  /// The disk UUID
  std::string uuid;

  /// The disk identifier, such as disk0
  std::string id;

  /// Parent disk identifier
  std::string parent_id;

  /// The disk size
  std::uint64_t size{};

  /// Preferred block size
  std::uint64_t preferred_block_size{};

  /// The model name
  std::string model;

  /// Vendor
  std::string vendor;

  /// The disk label, if any
  std::string label;
};

/// A collection of DiskInformation structures
using DiskInformationList = std::vector<DiskInformation>;

/// Acquires a snapshot of all the disks attached to the system
boost::optional<DiskInformationList> getDiskInformationList();

} // namespace osquery::tables
