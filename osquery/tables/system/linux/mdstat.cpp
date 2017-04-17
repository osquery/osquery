/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/major.h>
#include <linux/raid/md_p.h>
#include <linux/raid/md_u.h>

#include <fstream>
#include <memory>

#include <osquery/logger.h>

#include "osquery/events/linux/udev.h"
#include <osquery/core/conversions.h>

namespace osquery {
namespace tables {

std::string kMDStatPath = "/proc/mdstat";

struct MDDrive {
  std::string name;
  size_t pos;
};

struct MDDevice {
  std::string name;
  std::string status;
  std::string raidLevel;
  std::string usableSize;
  std::string other;
  std::vector<MDDrive> drives;
  std::string healthyDrives;
  std::string driveStatuses;
  std::string recovery;
  std::string resync;
  std::string reshape;
  std::string bitmap;
  std::string checkArray;
};

struct MDStat {
  std::string personalities;
  std::vector<MDDevice> devices;
  std::string unused;
};

/**
 * @brief Removes prefixing and suffixing character
 *
 * @param s reference to target string
 * @param c character to remove
 *
 */
void trimStr(std::string& s, const char c = ' ') {
  std::size_t first = s.find_first_not_of(c);
  if (first == std::string::npos) {
    return;
  }

  std::size_t last = s.find_last_not_of(c);
  // erase last first b/c length change does not effect the beginning of string
  if (last < s.size() - 1) {
    s.erase(last + 1, std::string::npos);
  }

  s.erase(0, first);
}

/**
 * @brief Removes prefixing and suffixing character from each string in vector
 *
 * @param strs reference to vector of target strings
 * @param c character to remove
 *
 */
void trimStr(std::vector<std::string>& strs, const char c = ' ') {
  for (auto& s : strs) {
    trimStr(s, c);
  }
}

/**
 * @brief convenience function for working a with a udev subsystem
 *
 * @param systemName the name of the sysfs subsytem to work with
 * @param f function to execute on the subsystem
 *
 */
void useUdevListEntries(
    std::string systemName,
    std::function<void(udev_list_entry* const&, udev* const&)> f) {
  auto delUdev = [](udev* u) { udev_unref(u); };
  std::unique_ptr<udev, decltype(delUdev)> handle(udev_new(), delUdev);
  if (handle.get() == nullptr) {
    LOG(ERROR) << "Could not get udev handle";
    return;
  }

  auto delUdevEnum = [](udev_enumerate* e) { udev_enumerate_unref(e); };
  std::unique_ptr<udev_enumerate, decltype(delUdevEnum)> udevEnum(
      udev_enumerate_new(handle.get()), delUdevEnum);
  if (udevEnum.get() == nullptr) {
    LOG(ERROR) << "Could not get enumerate handle";
    return;
  }

  udev_enumerate_add_match_subsystem(udevEnum.get(), systemName.c_str());
  udev_enumerate_scan_devices(udevEnum.get());
  udev_list_entry* device_entries =
      udev_enumerate_get_list_entry(udevEnum.get());

  f(device_entries, handle.get());
}

/**
 * @brief gets the path to device driver by short name
 *
 * @param name name of the device, ie. `md0`
 *
 */
std::string getPathByDevName(std::string name) {
  std::string devPath;
  useUdevListEntries(
      "block",
      [&](udev_list_entry* const& device_entries, udev* const& handle) {
        udev_list_entry* entry;
        udev_list_entry_foreach(entry, device_entries) {
          const char* path = udev_list_entry_get_name(entry);

          auto delUdevDevice = [](udev_device* d) { udev_device_unref(d); };
          std::unique_ptr<udev_device, decltype(delUdevDevice)> device(
              udev_device_new_from_syspath(handle, path), delUdevDevice);
          if (device.get() == nullptr) {
            LOG(ERROR) << "Could not get udev device handle";
            continue;
          }

          const char* devName =
              udev_device_get_property_value(device.get(), "DEVNAME");
          if (strcmp(name.c_str(), &devName[strlen(devName) - name.length()]) ==
              0) {
            devPath = devName;
            break;
          } else {
            devName = "";
          }
        }
      });

  return devPath;
}

/**
 * @brief gets the device name by its major and minor number
 *
 * @param major major number
 * @param minor minor number
 *
 */
std::string getDevName(int major, int minor) {
  std::string devName = "unknown";

  useUdevListEntries(
      "block",
      [&](udev_list_entry* const& device_entries, udev* const& handle) {

        udev_list_entry* entry;
        udev_list_entry_foreach(entry, device_entries) {
          const char* path = udev_list_entry_get_name(entry);

          auto delUdevDevice = [](udev_device* d) { udev_device_unref(d); };
          std::unique_ptr<udev_device, decltype(delUdevDevice)> device(
              udev_device_new_from_syspath(handle, path), delUdevDevice);
          if (device.get() == nullptr) {
            LOG(ERROR) << "Could not get udev device handle";
            continue;
          }

          const char* devMajor =
              udev_device_get_property_value(device.get(), "MAJOR");
          const char* devMinor =
              udev_device_get_property_value(device.get(), "MINOR");

          if (std::stoi(devMajor) == major && std::stoi(devMinor) == minor) {
            devName = udev_device_get_property_value(device.get(), "DEVNAME");
            break;
          }
        }
      });

  return devName;
}

/**
 * @brief resolves MD disk state field to string representation
 *
 * @param  state state field of mdu_disk_info_t
 *
 * @return stringified state
 */
std::string getDiskStateStr(int state) {
  // If state is 0, which is undefined, we assume recoverying, as this is all
  // have seen in the wild
  if (state == 0)
    return "recovering";

  std::string s;

  if ((1 << MD_DISK_FAULTY) & state)
    s += "faulty ";

  if ((1 << MD_DISK_ACTIVE) & state)
    s += "active ";

  if ((1 << MD_DISK_SYNC) & state)
    s += "sync ";

  if ((1 << MD_DISK_REMOVED) & state)
    s += "removed ";

  if ((1 << MD_DISK_WRITEMOSTLY) & state)
    s += "writemostly ";

#ifdef MD_DISK_FAILFAST
  if ((1 << MD_DISK_FAILFAST) & state)
    s += "failfast ";
#endif

#ifdef MD_DISK_JOURNAL
  if ((1 << MD_DISK_JOURNAL) & state)
    s += "journal ";
#endif

#ifdef MD_DISK_CANDIDATE
  if ((1 << MD_DISK_CANDIDATE) & state)
    s += "spare ";
#endif

#ifdef MD_DISK_CLUSTER_ADD
  if ((1 << MD_DISK_CLUSTER_ADD) & 1)
    s += "clusteradd ";
#endif

  return s;
}

/**
 * @brief request disk information from MD drivers
 *
 * @param arrayName name of the md array, ie. `md0`
 * @param diskNum the disk number used by the system
 *
 * @return copy of mdu_disk_info_t struct
 */
mdu_disk_info_t getDiskInfo(std::string arrayName, int diskNum) {
  std::map<std::string, std::string> results;
  mdu_disk_info_t diskInfo;
  diskInfo.number = diskNum;

  int fd = open(arrayName.c_str(), O_RDONLY);
  int status = ioctl(fd, GET_DISK_INFO, &diskInfo);
  close(fd);

  if (status == -1) {
    LOG(WARNING) << "Call to ioctl 'GET_DISK_INFO' " << arrayName
                 << " failed: " << strerror(errno);
    return diskInfo;
  }

  return diskInfo;
}

/**
 * @brief request array information from MD drivers
 *
 * @param name name of the md array, ie. `md0`
 * @param array empty struct of mdu_array_info_t; will be filled out with info
 *
 */
void getArrayInfo(std::string name, mdu_array_info_t& array) {
  std::map<std::string, std::string> results;

  int fd = open(name.c_str(), O_RDONLY);
  int status = ioctl(fd, GET_ARRAY_INFO, &array);
  close(fd);

  if (status == -1) {
    LOG(ERROR) << "Call to ioctl 'GET_ARRAY_INFO' for " << name
               << " failed: " << strerror(errno);
  }
}

inline void getLines(std::vector<std::string>& lines) {
  std::ifstream handle(kMDStatPath);

  std::string line;
  if (handle.is_open()) {
    while (getline(handle, line)) {
      trimStr(line);

      if (line.find_first_not_of("\t\r\v ") != std::string::npos) {
        lines.push_back(line);
      }
    }

    handle.close();
  }
}

MDDrive parseMDDrive(std::string& name) {
  MDDrive drive;
  drive.name = name;

  std::size_t start = name.find('[');
  std::size_t end = name.find(']');
  if (start == std::string::npos || end == std::string::npos) {
    LOG(WARNING) << "Unexpected drive name format: " << name;
    return drive;
  }

  drive.pos = std::stoi(name.substr(start + 1, end - start - 1));

  return drive;
}

/**
 * @brief Parse mdstat text blob into MDStat struct
 *
 * @param result reference to a MDStat struct to store results into
 *
 * This function makes assumption about the structure of the mdstat text blobs.
 * If the structure is not what it expects, the logs a warning message and
 * moves on.
 *
 */
void parseMDStat(MDStat& result) {
  // Will be used to determine starting point of lines to work on.
  size_t n = 0;

  std::vector<std::string> lines;
  getLines(lines);

  if (lines.size() < 1) {
    return;
  }

  // This should always evaluate to true, but just in case we check.
  if (lines[0].find("Personalities :") != std::string::npos) {
    result.personalities = lines[0].substr(sizeof("Personalities :") - 1);
    n = 1;

  } else {
    LOG(WARNING) << "mdstat Personalites not found at line 0: " << lines[0];
  }

  while (n < lines.size()) {
    // Work off of first 2 character instead of just the first to be safe.
    std::string firstTwo = lines[n].substr(0, 2);
    if (firstTwo == "md") {
      std::vector<std::string> mdline = split(lines[n], ":", 1);
      if (mdline.size() < 2) {
        LOG(WARNING) << "Unexpected md device line structure: " << lines[n];
        continue;
      }

      MDDevice mdd;
      mdd.name = mdline[0];
      trimStr(mdd.name);

      std::vector<std::string> settings = split(mdline[1], " ");
      trimStr(settings);
      // First 2 of settings are always status and RAID level
      if (settings.size() >= 2) {
        mdd.status = settings[0];
        mdd.raidLevel = settings[1];

        for (size_t i = 2; i < settings.size(); i++) {
          mdd.drives.push_back(parseMDDrive(settings[i]));
        }
      }

      /* Next line is device config and settings.  We handle here instead of
       * later b/c pieces are need for both md_drives and md_devices table */
      std::vector<std::string> configline = split(lines[n + 1]);
      if (configline.size() < 4) {
        LOG(WARNING) << "Unexpected md device config: " << lines[n + 1];

      } else {
        trimStr(configline);
        mdd.usableSize = configline[0] + " " + configline[1];
        mdd.healthyDrives = configline[configline.size() - 2];
        mdd.driveStatuses = configline[configline.size() - 1];

        if (configline.size() > 4) {
          for (size_t i = 2; i < configline.size() - 2; i++) {
            mdd.other += (" " + configline[i]);
          }
        }
      }
      // Skip config line for next iteration
      n += 1;

      // Handle potential bitmap, recovery, and resync lines
      std::size_t pos;
      while (true) {
        if ((pos = lines[n + 1].find("recovery =")) != std::string::npos) {
          mdd.recovery = lines[n + 1].substr(pos + sizeof("recovery =") - 1);
          trimStr(mdd.recovery);
          // Add an extra line for next iteration if so..
          n += 1;

        } else if ((pos = lines[n + 1].find("resync =")) != std::string::npos) {
          mdd.resync = lines[n + 1].substr(pos + sizeof("resync =") - 1);
          trimStr(mdd.resync);
          // Add an extra line for next iteration if so..
          n += 1;

        } else if ((pos = lines[n + 1].find("reshape =")) !=
                   std::string::npos) {
          mdd.reshape = lines[n + 1].substr(pos + sizeof("reshape =") - 1);
          trimStr(mdd.reshape);
          // Add an extra line for next iteration if so..
          n += 1;

        } else if ((pos = lines[n + 1].find("check =")) != std::string::npos) {
          mdd.checkArray = lines[n + 1].substr(pos + sizeof("check =") - 1);
          trimStr(mdd.checkArray);
          // Add an extra line for next iteration if so..
          n += 1;

        } else if ((pos = lines[n + 1].find("bitmap:")) != std::string::npos) {
          mdd.bitmap = lines[n + 1].substr(pos + sizeof("bitmap:") - 1);
          trimStr(mdd.bitmap);
          // Add an extra line for next iteration if so..
          n += 1;
          // If none of above, then we can break out of loop
        } else {
          break;
        }
      }

      result.devices.push_back(mdd);

      // Assume unused
    } else if (firstTwo == "un") {
      result.unused = lines[n].substr(sizeof("unused devices:") - 1);

      // Unexpected mdstat line, log a warning...
    } else {
      LOG(WARNING) << "Unexpected mdstat line: " << lines[n];
    }

    n += 1;
  }
}

/**
 * @brief gets all the drive information associated with a particular array.
 *
 * @param arrayName name of the md array, ie. `md0`
 * @param data QueryData to be filed out
 *
 */
void getDrivesForArray(std::string arrayName, QueryData& data) {
  std::string path(getPathByDevName(arrayName));
  if (path == "") {
    LOG(ERROR) << "Could not get file path for " << arrayName;
    return;
  }
  mdu_array_info_t array;
  getArrayInfo(path, array);

  QueryData temp;
  for (size_t i = 0; i < MD_SB_DISKS; i++) {
    mdu_disk_info_t disk = getDiskInfo(path, i);
    if (disk.major > 0) {
      Row r;
      r["md_device_name"] = arrayName;
      r["drive_name"] = getDevName(disk.major, disk.minor);
      r["status"] = getDiskStateStr(disk.state);
      r["slot"] = std::to_string(disk.raid_disk);

      /* We have to check here b/c otherwise we have no idea if the slot has
       * been recovered.  We assume that if the disk number is less than the
       * total disk count of the array, that the original slot position;  If the
       * number is greater than the disk count, then it's not safe to make that
       * assumption, and we lose precision on the missing slot resolution in the
       * below block. */
      if (disk.raid_disk < 0 && disk.number < array.raid_disks) {
        r["slot"] = std::to_string(disk.number);
      }

      temp.push_back(r);
    }
  }

  // Find removed disks if number of rows don't match with array raid disks
  for (size_t slot = 0; slot < array.raid_disks; slot++) {
    bool found = false;
    int softRemoved = -1;
    for (size_t i = 0; i < temp.size(); i++) {
      if (std::stoi(temp[i]["slot"]) == slot) {
        found = true;
      } else if (std::stoi(temp[i]["slot"]) < 0) {
        softRemoved = i;
      }
    }

    /* All missing slots must be resolved.  It's feasible duplicate slots per
     * array b/c a slot can be in a faulty state on one drive prior to becoming
     * active/recovering on another as long as it has not been removed from the
     * array.  However, if the  */
    if (!found) {
      if (softRemoved > -1) {
        temp[softRemoved]["slot"] = std::to_string(slot);

      } else {
        Row r;
        r["md_device_name"] = arrayName;
        r["drive_name"] = "unknown";
        r["slot"] = std::to_string(slot);
        r["state"] = "removed";
        temp.push_back(r);
        continue;
      }
    }
  }

  data.reserve(data.size() + temp.size());
  data.insert(data.end(), temp.begin(), temp.end());
}

QueryData genMDDrives(QueryContext& context) {
  QueryData results;

  MDStat mds;
  parseMDStat(mds);

  for (auto& device : mds.devices) {
    getDrivesForArray(device.name, results);
  }

  return results;
}

QueryData genMDDevices(QueryContext& context) {
  QueryData results;
  MDStat mds;

  parseMDStat(mds);
  for (auto& device : mds.devices) {
    Row r;
    r["device_name"] = device.name;
    r["status"] = device.status;
    r["raid_level"] = device.raidLevel;
    r["healthy_drives"] = device.healthyDrives;
    r["usable_size"] = device.usableSize;

    // Handle recovery & resync
    /* Make assumption that recovery/resync format is [d+]% ([d+]/[d+])
     * finish=<duration> speed=<rate> */
    auto handleR = [&r](std::string& line, std::string prefix) {
      std::vector<std::string> pieces(split(line, " "));
      if (pieces.size() != 4) {
        LOG(WARNING) << "Unexpected recovery/resync line format: " << line;
        return;
      }
      trimStr(pieces);

      r[prefix + "_progress"] = pieces[0] + " " + pieces[1];

      std::size_t start = pieces[2].find_first_not_of("finish=");
      if (start != std::string::npos) {
        r[prefix + "_finish"] = pieces[2].substr(start);
      } else {
        r[prefix + "_finish"] = pieces[2];
      }

      start = pieces[3].find_first_not_of("speed=");
      if (start != std::string::npos) {
        r[prefix + "_speed"] = pieces[3].substr(start);
      } else {
        r[prefix + "_speed"] = pieces[3];
      }
    };

    if (device.recovery != "") {
      handleR(device.recovery, "discovery");
    }

    if (device.resync != "") {
      handleR(device.resync, "resync");
    }

    if (device.reshape != "") {
      handleR(device.reshape, "reshape");
    }

    if (device.checkArray != "") {
      handleR(device.checkArray, "check_array");
    }

    if (device.bitmap != "") {
      std::vector<std::string> bitmapInfos(split(device.bitmap, ","));
      if (bitmapInfos.size() < 2) {
        LOG(WARNING) << "Unexpected bitmap line structure: " << device.bitmap;
      } else {
        trimStr(bitmapInfos);
        r["bitmap_on_mem"] = bitmapInfos[0];
        r["bitmap_chunk_size"] = bitmapInfos[1];

        std::size_t pos;
        if (bitmapInfos.size() > 2 &&
            (pos = bitmapInfos[2].find("file:")) != std::string::npos) {
          r["bitmap_external_file"] =
              bitmapInfos[2].substr(pos + sizeof("file:") - 1);
          trimStr(r["bitmap_external_file"]);
        }
      }
    }

    r["unused_devices"] = mds.unused;

    results.push_back(r);
  }

  return results;
}

QueryData genMDPersonalities(QueryContext& context) {
  QueryData results;
  MDStat mds;

  parseMDStat(mds);

  std::vector<std::string> enabledPersonalities = split(mds.personalities, " ");
  for (auto& setting : enabledPersonalities) {
    trimStr(setting);
    std::string name(setting.substr(1, setting.length() - 2));
    Row r = {{"name", name}};

    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
