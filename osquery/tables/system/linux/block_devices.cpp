#include <string>
#include <fstream>
#include <streambuf>
#include <sstream>
#include <map>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include <libudev.h>
#include <blkid/blkid.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

namespace osquery {
namespace tables {

static void fillRow(struct udev_device *dev, Row &r) {
  struct udev_device *parent, *scsi_dev;
  blkid_probe pr;
  const char *name, *tmp;

  if ((name = udev_device_get_devnode(dev))) {
    r["name"] = std::string(name);
  }
  if ((parent =
           udev_device_get_parent_with_subsystem_devtype(dev, "block", NULL))) {
    r["parent"] = std::string(udev_device_get_devnode(parent));
  }
  if ((tmp = udev_device_get_sysattr_value(dev, "size"))) {
    r["size"] = std::string(tmp);
  }
  if ((scsi_dev =
           udev_device_get_parent_with_subsystem_devtype(dev, "scsi", NULL))) {
    if ((tmp = udev_device_get_sysattr_value(scsi_dev, "model"))) {
      std::string model = tmp;
      boost::algorithm::trim(model);
      r["model"] = model;
    }
    if ((tmp = udev_device_get_sysattr_value(scsi_dev, "vendor"))) {
      std::string vendor = tmp;
      boost::algorithm::trim(vendor);
      r["vendor"] = vendor;
    }
  }

  if (name && ((pr = blkid_new_probe_from_filename(name)))) {
    blkid_probe_enable_superblocks(pr, 1);
    blkid_probe_set_superblocks_flags(
        pr, BLKID_SUBLKS_LABEL | BLKID_SUBLKS_UUID | BLKID_SUBLKS_TYPE);
    if (!blkid_do_safeprobe(pr)) {
      if (!blkid_probe_lookup_value(pr, "TYPE", &tmp, NULL)) {
        r["type"] = std::string(tmp);
      }
      if (!blkid_probe_lookup_value(pr, "UUID", &tmp, NULL)) {
        r["uuid"] = std::string(tmp);
      }
      if (!blkid_probe_lookup_value(pr, "LABEL", &tmp, NULL)) {
        r["label"] = std::string(tmp);
      }
    }
    blkid_free_probe(pr);
  }
}

QueryData genBlockDevs() {
  QueryData results;
  struct udev *udev;
  struct udev_enumerate *enumerate;
  struct udev_list_entry *devices, *dev_list_entry;
  struct udev_device *dev, *parent;

  if ((udev = udev_new())) {
    enumerate = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(enumerate, "block");
    udev_enumerate_scan_devices(enumerate);
    devices = udev_enumerate_get_list_entry(enumerate);
    udev_list_entry_foreach(dev_list_entry, devices) {
      const char *path;
      Row r;

      path = udev_list_entry_get_name(dev_list_entry);
      dev = udev_device_new_from_syspath(udev, path);

      fillRow(dev, r);

      results.push_back(r);
      udev_device_unref(dev);
    }
  }

  udev_enumerate_unref(enumerate);
  udev_unref(udev);

  return results;
}
}
}
