/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/events/linux/udev.h"

namespace osquery {
namespace tables {

const std::string kPCIKeySlot = "PCI_SLOT_NAME";
const std::string kPCIKeyClass = "ID_PCI_CLASS_FROM_DATABASE";
const std::string kPCIKeyVendor = "ID_VENDOR_FROM_DATABASE";
const std::string kPCIKeyModel = "ID_MODEL_FROM_DATABASE";
const std::string kPCIKeyID = "PCI_ID";
const std::string kPCIKeyDriver = "DRIVER";

QueryData genPCIDevices(QueryContext &context) {
  QueryData results;

  auto udev_handle = udev_new();
  if (udev_handle == nullptr) {
    VLOG(1) << "Could not get udev handle";
    return results;
  }

  // Perform enumeration/search.
  auto enumerate = udev_enumerate_new(udev_handle);
  udev_enumerate_add_match_subsystem(enumerate, "pci");
  udev_enumerate_scan_devices(enumerate);

  // Get list entries and iterate over entries.
  struct udev_list_entry *device_entries, *entry;
  device_entries = udev_enumerate_get_list_entry(enumerate);

  udev_list_entry_foreach(entry, device_entries) {
    const char *path = udev_list_entry_get_name(entry);
    auto device = udev_device_new_from_syspath(udev_handle, path);

    Row r;
    r["pci_slot"] = UdevEventPublisher::getValue(device, kPCIKeySlot);
    r["pci_class"] = UdevEventPublisher::getValue(device, kPCIKeyClass);
    r["driver"] = UdevEventPublisher::getValue(device, kPCIKeyDriver);
    r["vendor"] = UdevEventPublisher::getValue(device, kPCIKeyVendor);
    r["model"] = UdevEventPublisher::getValue(device, kPCIKeyModel);

    // VENDOR:MODEL ID is in the form of HHHH:HHHH.
    std::vector<std::string> ids;
    auto device_id = UdevEventPublisher::getValue(device, kPCIKeyID);
    boost::split(ids, device_id, boost::is_any_of(":"));
    if (ids.size() == 2) {
      r["vendor_id"] = ids[0];
      r["model_id"] = ids[1];
    }

    // Set invalid vendor/model IDs to 0.
    if (r["vendor_id"].size() == 0) {
      r["vendor_id"] = "0";
    }

    if (r["model_id"].size() == 0) {
      r["model_id"] = "0";
    }

    results.push_back(r);
    udev_device_unref(device);
  }

  // Drop references to udev structs.
  udev_enumerate_unref(enumerate);
  udev_unref(udev_handle);

  return results;
}
}
}
