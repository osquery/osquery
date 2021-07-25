/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream>
#include <locale>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/events/linux/udev.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/linux/pci_devices.h>
#include <osquery/utils/conversions/join.h>

namespace osquery {
namespace tables {

const std::string kPCIKeySlot = "PCI_SLOT_NAME";
const std::string kPCIKeyClass = "ID_PCI_CLASS_FROM_DATABASE";
const std::string kPCIKeySubclass = "ID_PCI_SUBCLASS_FROM_DATABASE";
const std::string kPCIKeyVendor = "ID_VENDOR_FROM_DATABASE";
const std::string kPCIKeyModel = "ID_MODEL_FROM_DATABASE";
const std::string kPCIKeyID = "PCI_ID";
const std::string kPCIClassID = "PCI_CLASS";
const std::string kPCIKeyDriver = "DRIVER";
const std::string kPCISubsysID = "PCI_SUBSYS_ID";

const std::vector<std::string> kPciidsPathList{"/usr/share/misc/pci.ids",
                                               "/usr/share/hwdata/pci.ids",
                                               "/usr/share/pci.ids"};
const std::string kPciidsDeviceClassStartIndicator = "ffff";
const std::string kPciidsValidHexChars = "0123456789abcdef";
const char kPciidsCommentChar = '#';

Status PciDB::parseVendor(std::string& line, PciVendor*& cur_vendor) {
  if (line.size() < 7) {
    return Status::failure("line is shorter than 7 characters");
  }

  auto vendor_id = line.substr(0, 4);
  // Setup current vendor.
  // Bump 2 chars to account for whitespace separation..
  auto result =
      db_.emplace(vendor_id,
                  PciVendor{vendor_id,
                            line.substr(6),
                            std::unordered_map<std::string, PciModel>{}});
  if (result.second != true) {
    return Status::failure(
        "failed to save to db for line because key already exists:: " + line);
  }

  cur_vendor = &result.first->second;

  return Status::success();
}

Status PciDB::parseModel(std::string& line,
                         PciVendor* cur_vendor,
                         PciModel*& cur_model) {
  if (line.size() < 8) {
    return Status::failure("line is shorter than 8 characters");
  }

  if (cur_vendor == nullptr) {
    return Status::failure("cur_vendor is null for line: " + line);
  }

  auto model_id = line.substr(1, 4);
  // Set up current model under the current vendor.
  // Bump 2 chars to account for whitespace separation.
  auto result = cur_vendor->models.emplace(
      model_id,
      PciModel{model_id,
               line.substr(7),
               std::unordered_map<std::string, std::string>{}});
  if (result.second != true) {
    return Status::failure(
        "failed to save to models db for line because key already exists:: " +
        line);
  }

  cur_model = &result.first->second;

  return Status::success();
}

Status PciDB::parseSubsystem(std::string& line, PciModel* cur_model) {
  if (line.size() < 12) {
    return Status::failure("line is shorter than 12 characters");
  }

  if (cur_model == nullptr) {
    return Status::failure("cur_model is null for line: " + line);
  }

  // Store current subsystem information under current vendor and model.
  auto subsystemInfo = line.substr(11);
  boost::trim(subsystemInfo);
  auto result = cur_model->subsystemInfo.emplace(line.substr(2, 9),
                                                 std::move(subsystemInfo));
  if (result.second != true) {
    return Status::failure(
        "failed to save to subsystems db for line because key already "
        "exists: " +
        line);
  }

  return Status::success();
}

bool PciDB::parseLine(std::string& line,
                      PciVendor*& cur_vendor,
                      PciModel*& cur_model) {
  switch (line.find_first_of(kPciidsValidHexChars)) {
  case 0: {
    auto status = parseVendor(line, cur_vendor);
    if (!status.ok()) {
      VLOG(1) << "Unexpected error while parsing pci.ids vendor line: "
              << status.getMessage();
      return true;
    }

    // We don't currently handle device class device so remove from DB if we get
    // the indicator.
    if (cur_vendor->id == kPciidsDeviceClassStartIndicator) {
      db_.erase(kPciidsDeviceClassStartIndicator);
      return false;
    }

    return true;
  }

  case 1: {
    auto status = parseModel(line, cur_vendor, cur_model);
    if (!status.ok()) {
      VLOG(1) << "Unexpected error while parsing pci.ids model line: "
              << status.getMessage();
    }

    return true;
  }

  case 2: {
    auto status = parseSubsystem(line, cur_model);
    if (!status.ok()) {
      VLOG(1) << "Unexpected error while parsing pci.ids subsystem line: "
              << status.getMessage();
    }

    return true;
  }

  default:
    VLOG(1) << "Unexpected pci.ids line format";
    return true;
  }
}

PciDB::PciDB(std::istream& db_filestream) {
  // pci.ids keep track of subsystem information of vendor and models
  // sequentially so we keep track of what the current vendor and models are.
  PciVendor* cur_vendor = nullptr;
  PciModel* cur_model = nullptr;

  std::string line;
  while (std::getline(db_filestream, line)) {
    line = line.substr(0, line.find_first_of(kPciidsCommentChar));
    boost::trim_right(line);

    if (parseLine(line, cur_vendor, cur_model) == false) {
      return;
    }
  }
}

Status PciDB::getVendorName(const std::string& vendor_id,
                            std::string& name) const {
  auto vendor_it = db_.find(vendor_id);
  if (vendor_it == db_.end()) {
    return Status::failure("Vendor ID does not exist");
  }

  name = vendor_it->second.name;

  return Status::success();
}

Status PciDB::getModel(const std::string& vendor_id,
                       const std::string& model_id,
                       std::string& model) const {
  auto vendor_it = db_.find(vendor_id);
  if (vendor_it == db_.end()) {
    return Status::failure("Vendor ID does not exist");
  }

  auto model_it = vendor_it->second.models.find(model_id);
  if (model_it == vendor_it->second.models.end()) {
    return Status::failure("Model ID does not exist");
  }

  model = model_it->second.desc;

  return Status::success();
}

Status PciDB::getSubsystemInfo(const std::string& vendor_id,
                               const std::string& model_id,
                               const std::string& subsystem_vendor_id,
                               const std::string& subsystem_device_id,
                               std::string& subsystem) const {
  auto vendor_it = db_.find(vendor_id);
  if (vendor_it == db_.end()) {
    return Status::failure("Vendor ID does not exist");
  }

  auto model_it = vendor_it->second.models.find(model_id);
  if (model_it == vendor_it->second.models.end()) {
    return Status::failure("Model ID does not exist");
  }

  auto subsystem_id = subsystem_vendor_id + " " + subsystem_device_id;

  auto subsystem_it = model_it->second.subsystemInfo.find(subsystem_id);
  if (subsystem_it == model_it->second.subsystemInfo.end()) {
    return Status::failure("Subsystem ID does not exist in system pci.ids: " +
                           subsystem_id);
  }

  subsystem = subsystem_it->second;

  return Status::success();
}

Status splitVendorModelAttrs(std::string pci_id_attr,
                             std::string& vendor,
                             std::string& model) {
  // pci.ids lower cases everything, so we follow suit.
  boost::algorithm::to_lower(pci_id_attr);

  auto colon = pci_id_attr.find(":");
  if (colon == std::string::npos || colon == pci_id_attr.length() - 1 ||
      pci_id_attr.find(":", colon + 1) != std::string::npos) {
    return Status::failure(
        "Unexpected input from sysFs PCI device attribute: " + pci_id_attr);
  }

  vendor = pci_id_attr.substr(0, colon);
  model = pci_id_attr.substr(colon + 1);
  return Status::success();
}

void extractOEMVendorModelFromPciDB(Row& row,
                                    const std::string& vendor_id,
                                    const std::string& model_id,
                                    const PciDB& pcidb) {
  row.emplace("vendor_id", "0x" + vendor_id);
  row.emplace("model_id", "0x" + model_id);

  std::string content;
  if (pcidb.getVendorName(vendor_id, content).ok()) {
    row["vendor"] = std::move(content);
  }

  content.clear();
  if (pcidb.getModel(vendor_id, model_id, content).ok()) {
    row["model"] = std::move(content);
  }
}

void extractSubsysVendorModelFromPciDB(Row& row,
                                       const std::string& vendor_id,
                                       const std::string& model_id,
                                       const std::string& subsys_vendor_id,
                                       const std::string& subsys_model_id,
                                       const PciDB& pcidb) {
  row.emplace("subsystem_vendor_id", "0x" + subsys_vendor_id);
  row.emplace("subsystem_model_id", "0x" + subsys_model_id);

  std::string content;
  if (pcidb.getVendorName(subsys_vendor_id, content).ok()) {
    row.emplace("subsystem_vendor", std::move(content));
  }

  content.clear();
  if (pcidb
          .getSubsystemInfo(
              vendor_id, model_id, subsys_vendor_id, subsys_model_id, content)
          .ok()) {
    row.emplace("subsystem_model", std::move(content));
  }
}

Status extractVendorModelFromPciDBIfPresent(
    Row& row,
    const std::string& device_ids_attr,
    const std::string& subsystem_ids_attr,
    const PciDB& pcidb) {
  std::string vendor_id;
  std::string model_id;
  auto status = splitVendorModelAttrs(device_ids_attr, vendor_id, model_id);
  if (!status.ok()) {
    // Legacy behavior of using value "0" being supported for backward
    // compatibility.
    row.emplace("vendor_id", "0");
    row.emplace("model_id", "0");

    return Status::failure("Failed to parse PCI device ID attributes: " +
                           status.getMessage());
  }

  extractOEMVendorModelFromPciDB(row, vendor_id, model_id, pcidb);

  std::string subsystem_vendor_id;
  std::string subsystem_model_id;
  status = splitVendorModelAttrs(
      subsystem_ids_attr, subsystem_vendor_id, subsystem_model_id);
  if (!status.ok()) {
    return Status::failure(
        "Failed to parse PCI device subsystem ID attributes: " +
        status.getMessage());
  }

  extractSubsysVendorModelFromPciDB(
      row, vendor_id, model_id, subsystem_vendor_id, subsystem_model_id, pcidb);

  return Status::success();
}

Status extractPCIVendorModelInfo(
    Row& row,
    std::unique_ptr<udev_device, decltype(&udev_device_unref)>& device,
    const PciDB& pcidb) {
  // Fallback data comes from UdevEventPublisher.
  row["vendor"] = UdevEventPublisher::getValue(device.get(), kPCIKeyVendor);
  row["model"] = UdevEventPublisher::getValue(device.get(), kPCIKeyModel);

  // Now try PciDB for more up to date info.
  return extractVendorModelFromPciDBIfPresent(
      row,
      UdevEventPublisher::getValue(device.get(), kPCIKeyID),
      UdevEventPublisher::getValue(device.get(), kPCISubsysID),
      pcidb);
}

Status extractPCIClassIDAttrs(Row& row, std::string pci_class_attr) {
  // pci.ids lower cases everything, so we follow suit.
  boost::algorithm::to_lower(pci_class_attr);

  auto id_len = pci_class_attr.length();
  switch (id_len) {
  case 5:
    row.emplace("pci_class_id", "0x0" + pci_class_attr.substr(0, 1));
    row.emplace("pci_subclass_id", "0x" + pci_class_attr.substr(1, 2));
    break;

  case 6:
    row.emplace("pci_class_id", "0x" + pci_class_attr.substr(0, 2));
    row.emplace("pci_subclass_id", "0x" + pci_class_attr.substr(2, 2));
    break;

  default:
    return Status::failure(
        "Expected PCI Class ID to be 6 or 7 characters long, but got " +
        std::to_string(id_len));
  }

  return Status::success();
}

QueryData genPCIDevices(QueryContext& context) {
  QueryData results;

  auto del_udev = [](udev* u) { udev_unref(u); };
  std::unique_ptr<udev, decltype(del_udev)> udev_handle(udev_new(), del_udev);
  if (udev_handle.get() == nullptr) {
    VLOG(1) << "Could not get udev handle";
    return results;
  }

  // Perform enumeration/search.
  auto del_udev_enum = [](udev_enumerate* e) { udev_enumerate_unref(e); };
  std::unique_ptr<udev_enumerate, decltype(del_udev_enum)> enumerate(
      udev_enumerate_new(udev_handle.get()), del_udev_enum);
  if (enumerate.get() == nullptr) {
    VLOG(1) << "Could not get udev_enumerate handle";
    return results;
  }

  // Check pci.ids path
  std::ifstream raw;
  for (const std::string& pci_ids_path : kPciidsPathList) {
    if (pathExists(pci_ids_path)) {
      raw.open(pci_ids_path);
      if (raw) {
        break;
      }
    }
  }
  if (!raw.is_open()) {
    LOG(ERROR) << "Unexpected error attempting to read pci.ids at path: "
               << osquery::join(kPciidsPathList, " ");
    return results;
  }

  PciDB pcidb(raw);

  udev_enumerate_add_match_subsystem(enumerate.get(), "pci");
  udev_enumerate_scan_devices(enumerate.get());

  // Get list entries and iterate over entries.
  struct udev_list_entry *device_entries, *entry;
  device_entries = udev_enumerate_get_list_entry(enumerate.get());

  udev_list_entry_foreach(entry, device_entries) {
    const char* path = udev_list_entry_get_name(entry);

    std::unique_ptr<udev_device, decltype(&udev_device_unref)> device(
        udev_device_new_from_syspath(udev_handle.get(), path),
        udev_device_unref);
    if (device.get() == nullptr) {
      VLOG(1) << "Could not get device";
      return results;
    }

    Row r;
    r["pci_slot"] = UdevEventPublisher::getValue(device.get(), kPCIKeySlot);
    r["pci_class"] = UdevEventPublisher::getValue(device.get(), kPCIKeyClass);
    r["pci_subclass"] =
        UdevEventPublisher::getValue(device.get(), kPCIKeySubclass);
    r["driver"] = UdevEventPublisher::getValue(device.get(), kPCIKeyDriver);

    auto status = extractPCIVendorModelInfo(r, device, pcidb);
    if (!status.ok()) {
      VLOG(1) << "Unexpected error extracting PCI Device information: "
              << status.getMessage();
    }

    status = extractPCIClassIDAttrs(
        r, UdevEventPublisher::getValue(device.get(), kPCIClassID));
    if (!status.ok()) {
      VLOG(1) << "Failed to extract PCI class attributes: "
              << status.getMessage();
    }

    results.emplace_back(std::move(r));
  }

  return results;
}
} // namespace tables
} // namespace osquery
