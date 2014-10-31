// Copyright 2004-present Facebook. All Rights Reserved.

#include <string>
#include <vector>

#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include <libudev.h>

#include "osquery/core.h"
#include "osquery/database.h"

namespace osquery {
    namespace tables {

        const char *kSlot = "PCI_SLOT_NAME";
        const char *kClass = "ID_PCI_CLASS_FROM_DATABASE";
        const char *kVendor = "ID_VENDOR_FROM_DATABASE";
        const char *kModel = "ID_MODEL_FROM_DATABASE";

        struct udev *udev;
        struct udev_enumerate *enumerate;
        struct udev_list_entry *devices, *dev_list_entry;
        struct udev_device *dev;

        QueryData genLspci() {
            QueryData results;

            /* Create the udev object */
            udev = udev_new();
            if (!udev) {
                LOG(ERROR) << "Can't create udev object";
                return results;
            }

            /* Enumerate the list of all PCI devices */
            enumerate = udev_enumerate_new(udev);
            udev_enumerate_add_match_subsystem(enumerate, "pci");
            udev_enumerate_scan_devices(enumerate);
            devices = udev_enumerate_get_list_entry(enumerate);

            /* udev_list_entry_foreach is a macro which expands to
               a loop. The loop will be executed for each member in
               devices, setting dev_list_entry to a list entry
               which contains the device's path in /sys. */

            udev_list_entry_foreach(dev_list_entry, devices) {
                const char *path;

                /* Get the filename of the /sys entry for the PCI device
                   and create a udev_device object (dev) representing it */
                path = udev_list_entry_get_name(dev_list_entry);
                dev = udev_device_new_from_syspath(udev, path);

                Row r;
                r["slot"] = boost::lexical_cast<std::string>
                        (udev_device_get_property_value(dev, kSlot));
                r["device_class"] = boost::lexical_cast<std::string>
                        (udev_device_get_property_value(dev, kClass));
                r["vendor"] = boost::lexical_cast<std::string>
                        (udev_device_get_property_value(dev, kVendor));
                r["model"] = boost::lexical_cast<std::string>
                        (udev_device_get_property_value(dev, kModel));
                results.push_back(r);
            }
            return results;
        }
    }
}
