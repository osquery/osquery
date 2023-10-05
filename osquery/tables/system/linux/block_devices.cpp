/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <blkid/blkid.h>
#include <libudev.h>
#include <unistd.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

extern "C" {
#include <lvm2app.h>
#include <sys/sysmacros.h>
}

namespace osquery {
namespace tables {

void populatePVChildren(lvm_t lvm,
                        const std::string& devname,
                        const std::string& pvid,
                        std::map<std::string, std::string>& lvm_lv2pv) {
  const auto pvid_copy = boost::erase_all_copy(pvid, "-");
  const char* vg_name = lvm_vgname_from_pvid(lvm, pvid_copy.c_str());
  if (vg_name == nullptr) {
    return;
  }

  vg_t vg = lvm_vg_open(lvm, vg_name, "r", 0);
  if (vg == nullptr) {
    return;
  }
  struct dm_list* lvs = lvm_vg_list_lvs(vg);
  if (lvs != nullptr) {
    lv_list_t* lv = nullptr;
    dm_list_iterate_items(lv, lvs) {
      struct lvm_property_value kernel_major = lvm_lv_get_property(
                                    lv->lv, "lv_kernel_major"),
                                kernel_minor = lvm_lv_get_property(
                                    lv->lv, "lv_kernel_minor");
      const uint64_t major = kernel_major.value.integer,
                     minor = kernel_minor.value.integer;
      dev_t devno = makedev(major, minor);
      char* const child_devname = blkid_devno_to_devname(devno);
      if (child_devname != nullptr) {
        lvm_lv2pv[child_devname] = devname;
      }
      free(child_devname);
    }
  }
  lvm_vg_close(vg);
}

static void getBlockDevice(struct udev_device* dev,
                           QueryData& results,
                           std::map<std::string, std::string>& lvm_lv2pv) {
  Row r;
  const char *name = udev_device_get_devnode(dev);
  if (name == nullptr) {
    // Cannot get devnode information from UDEV.
    return;
  }

  // The device name may be blank but will have a string value.
  r["name"] = name;

  struct udev_device *subdev =
      udev_device_get_parent_with_subsystem_devtype(dev, "block", nullptr);
  if (subdev != nullptr) {
    r["parent"] = udev_device_get_devnode(subdev);
  } else if (lvm_lv2pv.count(name)) {
    r["parent"] = lvm_lv2pv[name];
  }

  const char *size = udev_device_get_sysattr_value(dev, "size");
  if (size != nullptr) {
    r["size"] = size;
  }

  const char* block_size =
      udev_device_get_sysattr_value(dev, "queue/logical_block_size");
  if (block_size != nullptr) {
    r["block_size"] = block_size;
  }

  subdev = udev_device_get_parent_with_subsystem_devtype(dev, "scsi", nullptr);
  if (subdev != nullptr) {
    const char *model = udev_device_get_sysattr_value(subdev, "model");
    std::string model_string = std::string(model);
    boost::algorithm::trim(model_string);
    r["model"] = model_string;

    model = udev_device_get_sysattr_value(subdev, "vendor");
    model_string = std::string(model);
    boost::algorithm::trim(model_string);
    r["vendor"] = model_string;
  }

  blkid_probe pr = blkid_new_probe_from_filename(name);
  if (pr != nullptr) {
    blkid_probe_enable_superblocks(pr, 1);
    blkid_probe_set_superblocks_flags(
        pr, BLKID_SUBLKS_LABEL | BLKID_SUBLKS_UUID | BLKID_SUBLKS_TYPE);

    if (!blkid_do_safeprobe(pr)) {
      const char *blk_value = nullptr;
      if (!blkid_probe_lookup_value(pr, "TYPE", &blk_value, nullptr)) {
        r["type"] = blk_value;
      }
      if (!blkid_probe_lookup_value(pr, "UUID", &blk_value, nullptr)) {
        r["uuid"] = blk_value;
      }
      if (!blkid_probe_lookup_value(pr, "LABEL", &blk_value, nullptr)) {
        r["label"] = blk_value;
      }
      if (boost::algorithm::starts_with(r["type"], "LVM")) {
        lvm_t lvm = lvm_init(nullptr);
        if (lvm != nullptr) {
          populatePVChildren(lvm, name, r["uuid"], lvm_lv2pv);
          lvm_quit(lvm);
        }
      }
    }
    blkid_free_probe(pr);
  }

  results.push_back(r);
}

QueryData genBlockDevs(QueryContext &context) {
  if (getuid() || geteuid()) {
    VLOG(1) << "Not running as root, LVM and other column data not available";
  }

  QueryData results;

  struct udev *udev = udev_new();
  if (udev == nullptr) {
    return {};
  }

  struct udev_enumerate *enumerate = udev_enumerate_new(udev);
  udev_enumerate_add_match_subsystem(enumerate, "block");
  udev_enumerate_scan_devices(enumerate);

  std::map<std::string, std::string> lvm_lv2pv;
  struct udev_list_entry *devices, *dev_list_entry;
  devices = udev_enumerate_get_list_entry(enumerate);
  udev_list_entry_foreach(dev_list_entry, devices) {
    const char *path = udev_list_entry_get_name(dev_list_entry);
    struct udev_device *dev = udev_device_new_from_syspath(udev, path);
    if (path != nullptr && dev != nullptr) {
      getBlockDevice(dev, results, lvm_lv2pv);
    }
    udev_device_unref(dev);
  }

  udev_enumerate_unref(enumerate);
  udev_unref(udev);

  return results;
}
}
}
