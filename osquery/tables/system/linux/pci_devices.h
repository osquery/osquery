/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/tables.h>

namespace osquery {
namespace tables {

/// Represents a model related data for PCI devices of a given vendor and model.
struct PciModel {
  std::string id;
  std::string desc;
  std::unordered_map<std::string, std::string> subsystemInfo;
};

/// Represents vendor related data for a PCI devices of a given vendor.
struct PciVendor {
  std::string id;
  std::string name;
  std::unordered_map<std::string, PciModel> models;
};

class PciDB {
 public:
  /**
   * @brief retrieves PCI device vendor name from system pci.ids database.
   *
   * @param vendorID ID of the vendor
   * @param vendor a reference to a string which will be populated with the
   * vendor name
   *
   * @return an instance of Status, indicating success or failure.
   */
  Status getVendorName(const std::string& vendorID, std::string& vendor);

  /**
   * @brief retrieves PCI device model description from pci.ids database.
   *
   * @param vendorID ID of the vendor
   * @param modelID ID of the model
   * @param model a reference to a string which will be populated with the
   * model description.
   * @param subsystemID ID of the subsystem in the format of
   * "<subsystem vendor> <subsystem device>".  If provided model will be
   * enriched with the additional information.
   *
   * @return an instance of Status, indicating success or failure.
   */
  Status getModel(const std::string& vendorID,
                  const std::string& modelID,
                  std::string& model,
                  const std::string& subsystemID = "");

 public:
  PciDB(const std::string& path = "/usr/share/misc/pci.ids");

 private:
  std::unordered_map<std::string, PciVendor> db_;
};
} // namespace tables
} // namespace osquery
