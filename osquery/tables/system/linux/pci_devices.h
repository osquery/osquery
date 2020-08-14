/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/tables.h>

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
  Status getVendorName(const std::string& vendor_id, std::string& vendor) const;

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
                  std::string& model) const;

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
                          std::string& subsystem) const;

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

/// Extracts PCI device information into row for provided sysFS attributes.
Status extractVendorModelFromPciDBIfPresent(
    Row& row,
    const std::string& device_ids_attr,
    const std::string& subsystem_ids_attr,
    const PciDB& pcidb);

///  Extracts PCI class identifier information into row for provided sysFs
///  attribute.
Status extractPCIClassIDAttrs(Row& row, std::string pci_class_attr);

} // namespace tables
} // namespace osquery
