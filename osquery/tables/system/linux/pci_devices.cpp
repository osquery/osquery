/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <fstream>
#include <locale>

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/events/linux/udev.h"
#include "osquery/tables/system/linux/pci_devices.h"

namespace osquery {
namespace tables {

const std::string kPCIKeySlot = "PCI_SLOT_NAME";
const std::string kPCIKeyClass = "ID_PCI_CLASS_FROM_DATABASE";
const std::string kPCIKeyVendor = "ID_VENDOR_FROM_DATABASE";
const std::string kPCIKeyModel = "ID_MODEL_FROM_DATABASE";
const std::string kPCIKeyID = "PCI_ID";
const std::string kPCIKeyDriver = "DRIVER";
const std::string kPCISubsysID = "PCI_SUBSYS_ID";

const std::string kPciIdsPath = "/usr/share/misc/pci.ids";

PciDB::PciDB(std::istream& db_filestream) {
  // pci.ids keep track of subsystem information of vendor and models
  // sequentially so we keep track of what the current vendor and models are.
  std::string cur_vendor, cur_model, line;
  while (std::getline(db_filestream, line)) {
    line = line.substr(0, line.find_first_of('#'));
    boost::trim_right(line);
    if (line.size() < 7) {
      continue;
    }

    switch (line.find_first_of("0123456789abcdef")) {
    case 0: {
      // Vendor info.
      cur_vendor = line.substr(0, 4);

      // Once we get to illege vendor section we can stop since we're not
      // currently parsing device classes.
      if (cur_vendor == "ffff") {
        return;
      }

      // Setup current vendor.
      auto& vendor = db_[cur_vendor];
      vendor.id = cur_vendor;
      // Bump 2 chars to account for whitespace separation..
      vendor.name = line.substr(6);

      break;
    }

    case 1: {
      // Model info.
      auto vendor = db_.find(cur_vendor);
      if (vendor != db_.end() && line.size() > 7) {
        cur_model = line.substr(1, 4);

        // Set up current model under the current vendor.
        auto& model = vendor->second.models[cur_model];
        model.id = cur_model;
        // Bump 2 chars to account for whitespace separation.
        model.desc = line.substr(7);

      } else {
        VLOG(1) << "Unexpected error while parsing pci.ids: current vendor ID "
                << cur_vendor << " does not exist in DB yet";
      }

      break;
    }

    case 2: {
      // Subsystem info;
      auto vendor = db_.find(cur_vendor);
      if (vendor == db_.end()) {
        VLOG(1) << "Unexpected error while parsing pci.ids: current vendor ID "
                << cur_vendor << "does not exist in DB yet";
        continue;
      }

      auto model = vendor->second.models.find(cur_model);
      if (model == vendor->second.models.end()) {
        VLOG(1) << "Unexpected error while parsing pci.ids: current model ID "
                << cur_model << "does not exist in DB yet";
        continue;
      }

      if (line.size() > 11) {
        // Store current subsystem information under current vendor and model.
        auto subsystemInfo = line.substr(11);
        boost::trim(subsystemInfo);
        model->second.subsystemInfo[line.substr(2, 9)] = subsystemInfo;
      }

      break;
    }

    default:
      VLOG(1) << "Unexpected pci.ids line format";
    }
  }
}

Status PciDB::getVendorName(const std::string& vendor_id, std::string& name) {
  auto vendor_it = db_.find(vendor_id);
  if (vendor_it == db_.end()) {
    return Status::failure("Vendor ID does not exist");
  }

  name = vendor_it->second.name;
  return Status::success();
}

Status PciDB::getModel(const std::string& vendor_id,
                       const std::string& model_id,
                       std::string& model) {
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
                               std::string& subsystem) {
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

  std::ifstream raw(kPciIdsPath);
  if (raw.fail()) {
    LOG(ERROR) << "Unexpected error attempting to read pci.ids at path: "
               << kPciIdsPath;
    return results;
  }

  PciDB pcidb(raw);

  udev_enumerate_add_match_subsystem(enumerate.get(), "pci");
  udev_enumerate_scan_devices(enumerate.get());

  // Get list entries and iterate over entries.
  struct udev_list_entry *device_entries, *entry;
  device_entries = udev_enumerate_get_list_entry(enumerate.get());

  auto del_udev_device = [](udev_device* d) { udev_device_unref(d); };
  udev_list_entry_foreach(entry, device_entries) {
    const char* path = udev_list_entry_get_name(entry);
    std::unique_ptr<udev_device, decltype(del_udev_device)> device(
        udev_device_new_from_syspath(udev_handle.get(), path), del_udev_device);
    if (device.get() == nullptr) {
      VLOG(1) << "Could not get device";
      return results;
    }

    Row r;
    r["pci_slot"] = UdevEventPublisher::getValue(device.get(), kPCIKeySlot);
    r["pci_class"] = UdevEventPublisher::getValue(device.get(), kPCIKeyClass);
    r["driver"] = UdevEventPublisher::getValue(device.get(), kPCIKeyDriver);
    r["vendor"] = UdevEventPublisher::getValue(device.get(), kPCIKeyVendor);
    r["model"] = UdevEventPublisher::getValue(device.get(), kPCIKeyModel);

    // VENDOR:MODEL ID is in the form of HHHH:HHHH.
    std::vector<std::string> ids;
    auto device_id = UdevEventPublisher::getValue(device.get(), kPCIKeyID);

    // pci.ids lower cases everything, so we follow suit.
    boost::algorithm::to_lower(device_id);

    boost::split(ids, device_id, boost::is_any_of(":"));

    if (ids.size() == 2) {
      r["vendor_id"] = ids[0];
      r["model_id"] = ids[1];

      // Now that we know we have VENDOR and MODEL ID's, let's actually check on
      // the system PCI DB for descriptive information.
      std::string content;
      if (pcidb.getVendorName(ids[0], content).ok()) {
        r["vendor"] = content;
      }

      if (pcidb.getModel(ids[0], ids[1], content).ok()) {
        r["model"] = content;
      }

      // Try to enrich model with subsystem info.
      std::vector<std::string> subsystem_ids;
      auto subsystem_id =
          UdevEventPublisher::getValue(device.get(), kPCISubsysID);

      boost::algorithm::to_lower(subsystem_id);

      boost::split(subsystem_ids, subsystem_id, boost::is_any_of(":"));

      if (subsystem_ids.size() == 2) {
        r["subsystem_vendor_id"] = subsystem_ids[0];
        r["subsystem_model_id"] = subsystem_ids[1];

        if (pcidb.getVendorName(subsystem_ids[0], content).ok()) {
          r["subsystem_vendor"] = content;
        }

        if (pcidb
                .getSubsystemInfo(
                    ids[0], ids[1], subsystem_ids[0], subsystem_ids[1], content)
                .ok()) {
          r["subsystem_model"] = content;
        }
      }
    }

    // Set invalid vendor/model IDs to 0.
    if (r["vendor_id"].size() == 0) {
      r["vendor_id"] = "0";
    }

    if (r["model_id"].size() == 0) {
      r["model_id"] = "0";
    }

    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
