/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <blkid/blkid.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>

#include <boost/algorithm/string/trim.hpp>
#include <boost/range/as_array.hpp>

#include <osquery/core/core.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/linux/block_device_enumeration.h>

namespace osquery {
// Ensure the `uevent` file exists to validate block devices.
bool validBlockDevice(BlockDevice& block_device) {
  block_device.path /= "uevent";

  if (std::filesystem::exists(block_device.path)) {
    // Restore device path.
    block_device.path = block_device.path.parent_path();

    return true;
  }

  return false;
}

// The parent can be established by parent directory for physical block devices,
// or by `slaves/` directory for logical block devices. The `holders/` directory
// contains children for the block device, but it seems simpler to assign parent
// from child than the reverse.
void setBlockDeviceParent(BlockDevice& block_device) {
  block_device.parent = block_device.path.parent_path().filename().string();

  // If we don't have a valid parent from the directory, then we are a root or
  // logical block device.
  if (block_device.parent == "block") {
    block_device.parent.clear();
    block_device.path /= "slaves";

    // Check if slaves directory exists and enumerate the parents if it does.
    if (std::filesystem::exists(block_device.path)) {
      for (auto& parent :
           std::filesystem::directory_iterator(block_device.path)) {
        // We should only have one parent, so throw an error if there are more.
        if (!block_device.parent.empty()) {
          VLOG(1) << "Too many parent devices in slave directory for: "
                  << block_device.name;
          break;
        }

        block_device.parent = parent.path().filename().string();
      }
    }

    // Restore device path.
    block_device.path = block_device.path.parent_path();
  }

  // Format the parent device name.
  if (!block_device.parent.empty()) {
    block_device.parent = "/dev/" + block_device.parent;
  }
}

// Set various pieces of metadata for each block device. This combines use of
// libblkid and reading from sysfs.
void setBlockDeviceMetadata(
    BlockDevice& block_device,
    std::unordered_map<std::string, BlockDevice>& block_devices) {
  auto start_path = block_device.path;
  // Set model, serial, and vendor, for root devices. Child block devices
  // inherit these values later. Set block device size and sector size for all
  // block devices.
  for (std::string name : {"device/model",
                           "device/wwid",
                           "device/vendor",
                           "device/device/vendor",
                           "device/serial",
                           "size",
                           "queue/logical_block_size"}) {
    block_device.path /= name;
    std::ifstream file(block_device.path);

    // Restore device path.
    block_device.path = start_path;

    if (!file.is_open()) {
      continue;
    }

    // Read metadata from file.
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string data = buffer.str();

    if (data.empty()) {
      continue;
    }

    // Remove leading and trailing newlines, tabs, and spaces from data.
    boost::trim_if(data, boost::is_any_of(boost::as_array("\n\t ")));

    // Set metadata to respective block device member.
    if (name == "device/model") {
      block_device.model = data;
    } else if ((name == "device/wwid" || name == "device/serial") &&
               block_device.serial.empty()) {
      block_device.serial = data;
    } else if ((name == "device/vendor" || name == "device/device/vendor") &&
               block_device.vendor.empty()) {
      block_device.vendor = data;
    } else if (name == "size") {
      block_device.size = data;
    } else if (name == "queue/logical_block_size") {
      block_device.block_size = data;
    }
  }

  // Inherit root device model, serial, and vendor.
  if (!block_device.parent.empty()) {
    if (auto parent = block_devices.find(block_device.parent);
        parent != block_devices.end()) {
      block_device.model = parent->second.model;
      block_device.serial = parent->second.serial;
      block_device.vendor = parent->second.vendor;
    }
  }

  // Set block device label, type, and uuid with libblkid.
  blkid_probe pr = blkid_new_probe_from_filename(block_device.name.c_str());
  if (pr != nullptr) {
    blkid_probe_enable_superblocks(pr, 1);
    blkid_probe_set_superblocks_flags(
        pr, BLKID_SUBLKS_UUID | BLKID_SUBLKS_TYPE | BLKID_SUBLKS_LABEL);

    if (!blkid_do_safeprobe(pr)) {
      const char* value = nullptr;

      if (!blkid_probe_lookup_value(pr, "UUID", &value, nullptr)) {
        block_device.uuid = value;
      }

      if (!blkid_probe_lookup_value(pr, "TYPE", &value, nullptr)) {
        block_device.type = value;
      }

      if (!blkid_probe_lookup_value(pr, "LABEL", &value, nullptr)) {
        block_device.label = value;
      }
    }

    blkid_free_probe(pr);
  }
}

void genBlockDeviceResult(
    BlockDevice& block_device,
    std::unordered_map<std::string, BlockDevice>& block_devices,
    std::set<BlockDevice>& results,
    const bool include_parents) {
  // We've already set the metadata for this block device, so early exit to
  // ensure no duplicate runs.
  if (!block_device.size.empty()) {
    return;
  }

  // Recursive call to set parent block device metadata first. This always runs
  // even when we are not going to return the parents, so that we can inherit
  // model, serial, and vendor for non root block devices.
  if (!block_device.parent.empty()) {
    if (auto parent = block_devices.find(block_device.parent);
        parent != block_devices.end()) {
      genBlockDeviceResult(
          parent->second, block_devices, results, include_parents);
    }
  }

  setBlockDeviceMetadata(block_device, block_devices);

  // We add results in order of root -> parent(s) -> caller/context block
  // device.
  if (include_parents) {
    results.insert(block_device);
  }
}

std::set<BlockDevice> enumerateBlockDevices(std::set<std::string>& context,
                                            const bool include_parents) {
  std::set<BlockDevice> results;
  std::unordered_map<std::string, BlockDevice> block_devices;

  // We can simply walk sysfs to enumerate block devices on Linux. sysfs is
  // usually but not always mounted at `/sys`. Since we are relying on sysfs,
  // we'll get the mountpoint by collecting it from `/proc/mounts`. Defaults to
  // `/sys` if no sysfs is found in `/proc/mounts`.
  std::filesystem::path mountpoint = "/sys";
  std::ifstream mounts("/proc/mounts");
  std::string line;

  while (std::getline(mounts, line)) {
    std::stringstream linestream(line);
    std::string name, mount, fs;
    linestream >> name >> mount >> fs;

    if (fs == "sysfs") {
      mountpoint = mount;
      break;
    }
  }

  // Once we have the sysfs mount, we look at `class/block` to enumerate block
  // devices.
  // [See](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=edfaa7c36574f1bf09c65ad602412db9da5f96bf)
  mountpoint /= "class/block";
  std::filesystem::current_path(mountpoint);

  // Initially set block device name, path, and parent for all block devices
  // before checking context. We do this to cache the block devices, so that we
  // can recursively establish the device tree and inherit attributes from
  // parents when we are provided context.
  for (auto& device : std::filesystem::directory_iterator(mountpoint)) {
    // We can't enumerate the block device metadata if we don't have the sysfs
    // symlink for the block device.
    if (!std::filesystem::is_symlink(device.path())) {
      VLOG(1) << "No sysfs symlink for block device: "
              << device.path().filename().string();
      continue;
    }

    BlockDevice block_device;
    block_device.path = std::filesystem::canonical(
        std::filesystem::read_symlink(device.path()));
    block_device.name = "/dev/" + block_device.path.filename().string();

    if (!validBlockDevice(block_device)) {
      VLOG(1) << "Invalid block device. No uevent file found for block device: "
              << block_device.name;
      continue;
    }

    setBlockDeviceParent(block_device);
    block_devices[block_device.name] = block_device;
  }

  // We can now generate results since we have cached block devices to inherit
  // metadata from parents outside of the context.
  for (auto& pair : block_devices) {
    if (context.empty() || context.find(pair.first) != context.end()) {
      genBlockDeviceResult(
          pair.second, block_devices, results, include_parents);

      if (!include_parents) {
        results.insert(pair.second);
      }
    }
  }

  return results;
}
} // namespace osquery
