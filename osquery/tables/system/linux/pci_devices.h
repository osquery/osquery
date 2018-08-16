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
  /// ID of PCI device.
  std::string id;

  /// Description of PCI device.
  std::string desc;

  /// Stores subsystem information keyed by
  /// "<subsystem vendor id> <subsystem model id>". Key is preserved same as
  /// they are in pci.ids since lookup always requires both attribute ids.
  std::unordered_map<std::string, std::string> subsystemInfo;
};

/// Represents vendor related data for a PCI devices of a given vendor.
struct PciVendor {
  /// ID of vendor.
  std::string id;

  /// Name of vendor.
  std::string name;

  /// Stores device models information keyed by PCI device (model) ID.
  std::unordered_map<std::string, PciModel> models;
};

class PciDB {
 public:
  /**
   * @brief retrieves PCI device vendor name from system pci.ids database.
   *
   * @param vendor_id ID of the vendor.
   * @param vendor a reference to a string which will be populated with the
   * vendor name.
   *
   * @return an instance of Status, indicating success or failure.
   */
  Status getVendorName(const std::string& vendor_id, std::string& vendor);

  /**
   * @brief retrieves PCI device model description from pci.ids database.
   *
   * @param vendor_id ID of the vendor.
   * @param model_id ID of the model.
   * @param model a reference to a string which will be populated with the
   * model description.
   *
   * @return an instance of Status, indicating success or failure.
   */
  Status getModel(const std::string& vendor_id,
                  const std::string& model_id,
                  std::string& model);

  /**
   * @brief retrieves PCI device subsystem description from pci.ids database.
   *
   * @param vendor_id ID of the vendor.
   * @param model_id ID of the model.
   * @param subsystem_vendor_id ID of the subsystem vendor.
   * @param subsystem_device_id ID of the subsystem model.
   * @param subsystem a reference to a string which will be populated with the
   * subsystem description.
   *
   * @return an instance of Status, indicating success or failure.
   */
  Status getSubsystemInfo(const std::string& vendor_id,
                          const std::string& model_id,
                          const std::string& subsystem_vendor_id,
                          const std::string& subsystem_device_id,
                          std::string& subsystem);

 public:
  PciDB(std::istream& db_filestream);

 private:
  /**
   * @brief parses line of pci.ids.
   *
   * @param line line to parse.
   * @param cur_vendor PciVendor* reference that represents the current vendor.
   * @param cur_model PciModel* reference that represents the current model.
   *
   * @return bool true to keep parsing, false to stop.
   */
  bool parseLine(std::string& line,
                 PciVendor*& cur_vendor,
                 PciModel*& cur_model);

  /// Parses a vendor line.  Updates cur_vendor if no errors.
  Status parseVendor(std::string& line, PciVendor*& cur_vendor);

  /// Parses a model line.  Updates cur_model if no errors.
  Status parseModel(std::string& line,
                    PciVendor* cur_vendor,
                    PciModel*& cur_model);

  /// Parses a subsystem line.
  Status parseSubsystem(std::string& line, PciModel* cur_model);

 private:
  std::unordered_map<std::string, PciVendor> db_;
};
} // namespace tables
} // namespace osquery
