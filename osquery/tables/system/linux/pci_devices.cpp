/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/events/linux/udev.h"

namespace osquery {
namespace tables {

const std::string kPCIKeySlot {"PCI_SLOT_NAME"};
const std::string kPCIKeyClass {"ID_PCI_CLASS_FROM_DATABASE"};
const std::string kPCIKeyVendor {"ID_VENDOR_FROM_DATABASE"};
const std::string kPCIKeyModel {"ID_MODEL_FROM_DATABASE"};
const std::string kPCIKeyID {"PCI_ID"};
const std::string kPCIKeyDriver {"DRIVER"};

QueryData genPCIDevices(QueryContext& context) {
  QueryData results;

  auto delUdev = [](udev* u) { udev_unref(u); };
  std::unique_ptr<udev, decltype(delUdev)> udev_handle(udev_new(), delUdev);
  if (udev_handle.get() == nullptr) {
    VLOG(1) << "Could not get udev handle";
    return results;
  }

  // Perform enumeration/search.
  auto delUdevEnum = [](udev_enumerate* e) { udev_enumerate_unref(e); };
  std::unique_ptr<udev_enumerate, decltype(delUdevEnum)> enumerate(
      udev_enumerate_new(udev_handle.get()), delUdevEnum);
  if (enumerate.get() == nullptr) {
    VLOG(1) << "Could not get udev_enumerate handle";
    return results;
  }

  udev_enumerate_add_match_subsystem(enumerate.get(), "pci");
  udev_enumerate_scan_devices(enumerate.get());

  // Get list entries and iterate over entries.
  struct udev_list_entry *device_entries, *entry;
  device_entries = udev_enumerate_get_list_entry(enumerate.get());

  auto delUdevDevice = [](udev_device* d) { udev_device_unref(d); };
  udev_list_entry_foreach(entry, device_entries) {
    const char* path = udev_list_entry_get_name(entry);
    std::unique_ptr<udev_device, decltype(delUdevDevice)> device(
        udev_device_new_from_syspath(udev_handle.get(), path), delUdevDevice);
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
  }

  return results;
}
}
}
