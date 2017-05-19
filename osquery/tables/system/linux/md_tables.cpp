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

#include <boost/algorithm/string/trim.hpp>

#include <osquery/core/conversions.h>
#include <osquery/logger.h>

#include "osquery/events/linux/udev.h"
#include "osquery/tables/system/linux/md_tables.h"

namespace osquery {
namespace tables {

std::string kMDStatPath = "/proc/mdstat";

/**
 * @brief Removes prefixing and suffixing character from each string in vector
 *
 * @param strs reference to vector of target strings
 * @param c character to remove
 *
 */
void trimStrs(std::vector<std::string>& strs) {
  for (auto& s : strs) {
    boost::algorithm::trim(s);
  }
}

/**
 * @brief reads mdstat file and parses as vector of lines
 *
 * @param lines reference to vector of strings to store lines in
 *
 * Trims all white space in lines and ignores empty lines (i.e. only spaces,
 * tabs, etc.)
 */
inline void getLines(std::vector<std::string>& lines) {
  std::ifstream handle(kMDStatPath);

  std::string line;
  if (handle.is_open()) {
    while (getline(handle, line)) {
      boost::algorithm::trim(line);

      if (line.find_first_not_of("\t\r\v ") != std::string::npos) {
        lines.push_back(line);
      }
    }

    handle.close();
  }
}

/**
 * @brief function for walking thru a udev subsystem and working on devices
 *
 * @param systemName the name of the sysfs subsytem to work with
 * @param f function to execute on the subsystem; returns true if can break the
 * device loop, false to keep walking
 *
 */
void walkUdevDevices(std::string systemName,
                     std::function<bool(udev_device* const&)> f) {
  auto delUdev = [](udev* u) { udev_unref(u); };
  std::unique_ptr<udev, decltype(delUdev)> handle(udev_new(), delUdev);
  if (handle.get() == nullptr) {
    LOG(ERROR) << "Could not get udev handle\n";
    return;
  }

  auto delUdevEnum = [](udev_enumerate* e) { udev_enumerate_unref(e); };
  std::unique_ptr<udev_enumerate, decltype(delUdevEnum)> udevEnum(
      udev_enumerate_new(handle.get()), delUdevEnum);
  if (udevEnum.get() == nullptr) {
    LOG(ERROR) << "Could not get enumerate handle\n";
    return;
  }

  udev_enumerate_add_match_subsystem(udevEnum.get(), systemName.c_str());
  udev_enumerate_scan_devices(udevEnum.get());
  udev_list_entry* device_entries =
      udev_enumerate_get_list_entry(udevEnum.get());

  udev_list_entry* entry;
  udev_list_entry_foreach(entry, device_entries) {
    const char* path = udev_list_entry_get_name(entry);

    auto delUdevDevice = [](udev_device* d) { udev_device_unref(d); };
    std::unique_ptr<udev_device, decltype(delUdevDevice)> device(
        udev_device_new_from_syspath(handle.get(), path), delUdevDevice);
    if (device.get() == nullptr) {
      LOG(ERROR) << "Could not get udev device handle\n";
      continue;
    }
    if (f(device.get())) {
      break;
    }
  }
}

std::string MD::getPathByDevName(std::string name) {
  std::string devPath;

  walkUdevDevices("block", [&](udev_device* const& device) {
    const char* devName = udev_device_get_property_value(device, "DEVNAME");

    if (strcmp(name.c_str(), &devName[strlen(devName) - name.length()]) == 0) {
      devPath = devName;
      if (devPath.find('/') != 0) {
        devPath = "/dev/" + devPath;
      }

      return true;
    }

    return false;
  });

  return devPath;
}

std::string MD::getDevName(int major, int minor) {
  std::string devName = "unknown";

  walkUdevDevices("block", [&](udev_device* const& device) {
    const char* devMajor = udev_device_get_property_value(device, "MAJOR");
    const char* devMinor = udev_device_get_property_value(device, "MINOR");

    if (std::stoi(devMajor) == major && std::stoi(devMinor) == minor) {
      devName = udev_device_get_property_value(device, "DEVNAME");
      return true;
    }

    return false;
  });

  return devName;
}

std::string MD::getSuperblkVersion(std::string arrayName) {
  std::string version;

  walkUdevDevices("block", [&](udev_device* const& device) {
    const char* devName = udev_device_get_property_value(device, "DEVNAME");

    if (strcmp(arrayName.c_str(),
               &devName[strlen(devName) - arrayName.length()]) == 0) {
      version = udev_device_get_property_value(device, "MD_METADATA");
      return true;
    }

    return false;
  });

  return version;
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

  boost::algorithm::trim(s);
  return s;
}

/**
 * @brief resolves superblock state field to string representation
 *
 * @param  state state field of mdu_array_info_t
 *
 * @return stringified state
 */
std::string getSuperBlkStateStr(int state) {
  if (state == 0)
    return "unknown";

  std::string s;

#ifdef MD_SB_CLEAN
  if ((1 << MD_SB_CLEAN) & state)
    s += "clean ";
#endif

#ifdef MD_SB_ERRORS
  if ((1 << MD_SB_ERRORS) & state)
    s += "errors ";
#endif

#ifdef MD_SB_BBM_ERRORS
  if ((1 << MD_SB_BBM_ERRORS) & state)
    s += "bbm_errors ";
#endif

#ifdef MD_SB_BLOCK_CONTAINER_RESHAPE
  if ((1 << MD_SB_BLOCK_CONTAINER_RESHAPE) & 1)
    s += "container_reshape ";
#endif

#ifdef MD_SB_BLOCK_VOLUME
  if ((1 << MD_SB_BLOCK_VOLUME) & 1)
    s += "block_activation ";
#endif

#ifdef MD_SB_CLUSTERED
  if ((1 << MD_SB_CLUSTERED) & 1)
    s += "clustered ";
#endif

#ifdef MD_SB_BITMAP_PRESENT
  if ((1 << MD_SB_BITMAP_PRESENT) & 1)
    s += "bitmap_present ";
#endif

  boost::algorithm::trim(s);
  return s;
}

// For use with unique_ptr of file close as a hacky way of preventing fd leaks
auto fClose = [](int* fd) { close(*fd); };

bool MD::getDiskInfo(std::string arrayName, mdu_disk_info_t& diskInfo) {
  std::map<std::string, std::string> results;
  int fd;

  std::unique_ptr<int, decltype(fClose)> _(
      &(fd = open(arrayName.c_str(), O_RDONLY)), fClose);
  int status = ioctl(fd, GET_DISK_INFO, &diskInfo);

  if (status == -1) {
    LOG(WARNING) << "Call to ioctl 'GET_DISK_INFO' " << arrayName
                 << " failed: " << strerror(errno);
    return false;
  }

  return true;
}

bool MD::getArrayInfo(std::string name, mdu_array_info_t& array) {
  std::map<std::string, std::string> results;
  int fd;

  std::unique_ptr<int, decltype(fClose)> _(&(fd = open(name.c_str(), O_RDONLY)),
                                           fClose);
  int status = ioctl(fd, GET_ARRAY_INFO, &array);

  if (status == -1) {
    LOG(ERROR) << "Call to ioctl 'GET_ARRAY_INFO' for " << name
               << " failed: " << strerror(errno);
    return false;
  }

  return true;
}

inline void parseMDPersonalities(std::string& line,
                                 std::vector<std::string>& result) {
  std::vector<std::string> enabledPersonalities = split(line, " ");
  for (auto& p : enabledPersonalities) {
    boost::algorithm::trim(p);
    result.push_back(p.substr(1, p.length() - 2));
  }
}

void parseMDAction(std::string& line, MDAction& result) {
  /* Make assumption that recovery/resync format is [d+]% ([d+]/[d+])
   * finish=<duration> speed=<rate> */
  std::vector<std::string> pieces(split(line, " "));
  if (pieces.size() != 4) {
    LOG(WARNING) << "Unexpected recovery/resync line format: " << line;
    return;
  }
  trimStrs(pieces);

  result.progress = pieces[0] + " " + pieces[1];

  std::size_t start = pieces[2].find_first_not_of("finish=");
  if (start != std::string::npos) {
    result.finish = pieces[2].substr(start);

  } else {
    result.finish = pieces[2];
  }

  start = pieces[3].find_first_not_of("speed=");
  if (start != std::string::npos) {
    result.speed = pieces[3].substr(start);

  } else {
    result.speed = pieces[3];
  }
}

void parseMDBitmap(std::string& line, MDBitmap& result) {
  std::vector<std::string> bitmapInfos(split(line, ","));
  if (bitmapInfos.size() < 2) {
    LOG(WARNING) << "Unexpected bitmap line structure: " << line;

  } else {
    trimStrs(bitmapInfos);
    result.onMem = bitmapInfos[0];
    result.chunkSize = bitmapInfos[1];

    std::size_t pos;
    if (bitmapInfos.size() > 2 &&
        (pos = bitmapInfos[2].find("file:")) != std::string::npos) {
      result.externalFile = bitmapInfos[2].substr(pos + sizeof("file:") - 1);
      boost::algorithm::trim(result.externalFile);
    }
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

void MD::parseMDStat(std::vector<std::string> lines, MDStat& result) {
  // Will be used to determine starting point of lines to work on.
  size_t n = 0;

  if (lines.size() < 1) {
    return;
  }

  // This should always evaluate to true, but just in case we check.
  if (lines[0].find("Personalities :") != std::string::npos) {
    std::string pline(lines[0].substr(sizeof("Personalities :") - 1));
    parseMDPersonalities(pline, result.personalities);

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
      boost::algorithm::trim(mdd.name);

      std::vector<std::string> settings = split(mdline[1], " ");
      trimStrs(settings);
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
        trimStrs(configline);
        // mdd.usableSize = configline[0] + " " + configline[1];
        if (configline[1] == "blocks") {
          mdd.usableSize = std::stoll(configline[0]);
        } else {
          LOG(WARNING) << "Did not find size in mdstat for " << mdd.name;
        }

        mdd.healthyDrives = configline[configline.size() - 2];
        mdd.driveStatuses = configline[configline.size() - 1];

        if (configline.size() > 4) {
          for (size_t i = 2; i < configline.size() - 2; i++) {
            mdd.other += (" " + configline[i]);
            boost::algorithm::trim(mdd.other);
          }
        }
      }
      // Skip config line for next iteration
      n += 1;

      // Handle potential bitmap, recovery, and resync lines
      std::size_t pos;
      while (true) {
        if ((pos = lines[n + 1].find("recovery =")) != std::string::npos) {
          std::string recovery(
              lines[n + 1].substr(pos + sizeof("recovery =") - 1));
          boost::algorithm::trim(recovery);
          parseMDAction(recovery, mdd.recovery);
          // Add an extra line for next iteration if so..
          n += 1;

        } else if ((pos = lines[n + 1].find("resync =")) != std::string::npos) {
          std::string resync(lines[n + 1].substr(pos + sizeof("resync =") - 1));
          boost::algorithm::trim(resync);
          parseMDAction(resync, mdd.resync);
          // Add an extra line for next iteration if so..
          n += 1;

        } else if ((pos = lines[n + 1].find("resync=")) != std::string::npos) {
          // If in this format, it's generally signaling a progress delay
          mdd.resync.progress =
              lines[n + 1].substr(pos + sizeof("resync=") - 1);
          boost::algorithm::trim(mdd.resync.progress);
          // Add an extra line for next iteration if so..
          n += 1;

        } else if ((pos = lines[n + 1].find("reshape =")) !=
                   std::string::npos) {
          std::string reshape(
              lines[n + 1].substr(pos + sizeof("reshape =") - 1));
          boost::algorithm::trim(reshape);
          parseMDAction(reshape, mdd.reshape);
          // Add an extra line for next iteration if so..
          n += 1;

        } else if ((pos = lines[n + 1].find("check =")) != std::string::npos) {
          std::string checkArray(
              lines[n + 1].substr(pos + sizeof("check =") - 1));
          boost::algorithm::trim(checkArray);
          parseMDAction(checkArray, mdd.checkArray);
          // Add an extra line for next iteration if so..
          n += 1;

        } else if ((pos = lines[n + 1].find("bitmap:")) != std::string::npos) {
          std::string bitmap(lines[n + 1].substr(pos + sizeof("bitmap:") - 1));
          boost::algorithm::trim(bitmap);
          parseMDBitmap(bitmap, mdd.bitmap);
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
      boost::algorithm::trim(result.unused);
      // Unexpected mdstat line, log a warning...
    } else {
      LOG(WARNING) << "Unexpected mdstat line: " << lines[n];
    }

    n += 1;
  }
}

void getDrivesForArray(std::string arrayName,
                       MDInterface& md,
                       QueryData& data) {
  std::string path(md.getPathByDevName(arrayName));
  if (path == "") {
    LOG(ERROR) << "Could not get file path for " << arrayName;
    return;
  }

  mdu_array_info_t array;
  if (!md.getArrayInfo(path, array)) {
    return;
  }

  QueryData temp;
  for (size_t i = 0; i < MD_SB_DISKS; i++) {
    mdu_disk_info_t disk;
    disk.number = i;
    if (!md.getDiskInfo(path, disk)) {
      continue;
    }

    if (disk.major > 0) {
      Row r;
      r["md_device_name"] = arrayName;
      r["drive_name"] = md.getDevName(disk.major, disk.minor);
      r["state"] = getDiskStateStr(disk.state);
      r["slot"] = INTEGER(disk.raid_disk);

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
  for (int slot = 0; slot < array.raid_disks; slot++) {
    bool found = false;
    int softRemoved = -1;

    for (size_t i = 0; i < temp.size(); i++) {
      if (std::stoi(temp[i]["slot"]) == slot) {
        found = true;

      } else if (std::stoi(temp[i]["slot"]) < 0) {
        /* Becase we iterate to the end, the softRemoved value will be the last
         * disk that is marked faulty.  We have to walk over the entire vector,
         * because a missing slot can show up at a later number. */
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
        r["state"] = "removed";
        r["slot"] = std::to_string(slot);
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
  MD md;
  std::vector<std::string> lines;
  getLines(lines);

  md.parseMDStat(lines, mds);

  for (auto& device : mds.devices) {
    getDrivesForArray(device.name, md, results);
  }

  return results;
}

QueryData genMDDevices(QueryContext& context) {
  QueryData results;
  MDStat mds;
  MD md;
  std::vector<std::string> lines;

  getLines(lines);

  md.parseMDStat(lines, mds);
  for (auto& device : mds.devices) {
    std::string path(md.getPathByDevName(device.name));
    if (path == "") {
      LOG(ERROR) << "Could not get file path for " << device.name;
      return results;
    }

    mdu_array_info_t array;
    if (!md.getArrayInfo(path, array)) {
      return results;
    }

    Row r;
    r["device_name"] = device.name;
    r["status"] = device.status;
    r["raid_level"] = INTEGER(array.level);
    r["size"] = BIGINT(device.usableSize);
    r["chunk_size"] = BIGINT(array.chunk_size);
    r["raid_disks"] = INTEGER(array.raid_disks);
    r["nr_raid_disks"] = INTEGER(array.nr_disks);
    r["working_disks"] = INTEGER(array.working_disks);
    r["active_disks"] = INTEGER(array.active_disks);
    r["failed_disks"] = INTEGER(array.failed_disks);
    r["spare_disks"] = INTEGER(array.spare_disks);

    r["superblock_state"] = getSuperBlkStateStr(array.state);
    r["superblock_version"] = md.getSuperblkVersion(device.name);
    r["superblock_update_time"] = BIGINT(array.utime);

    if (device.recovery.progress != "") {
      r["recovery_progress"] = device.recovery.progress;
      r["recovery_finish"] = device.recovery.finish;
      r["recovery_speed"] = device.recovery.speed;
    }

    if (device.resync.progress != "") {
      r["resync_progress"] = device.resync.progress;
      r["resync_finish"] = device.resync.finish;
      r["resync_speed"] = device.resync.speed;
    }

    if (device.reshape.progress != "") {
      r["reshape_progress"] = device.reshape.progress;
      r["reshape_finish"] = device.reshape.finish;
      r["reshape_speed"] = device.reshape.speed;
    }

    if (device.checkArray.progress != "") {
      r["check_array_progress"] = device.checkArray.progress;
      r["check_array_finish"] = device.checkArray.finish;
      r["check_array_speed"] = device.checkArray.speed;
    }

    if (device.bitmap.onMem != "") {
      r["bitmap_on_mem"] = device.bitmap.onMem;
      r["bitmap_chunk_size"] = device.bitmap.chunkSize;
      r["bitmap_external_file"] = device.bitmap.externalFile;
    }

    r["other"] = device.other;
    r["unused_devices"] = mds.unused;

    results.push_back(r);
  }

  return results;
}

QueryData genMDPersonalities(QueryContext& context) {
  QueryData results;
  MDStat mds;
  std::vector<std::string> lines;
  MD md;

  getLines(lines);

  md.parseMDStat(lines, mds);

  for (auto& name : mds.personalities) {
    Row r = {{"name", name}};

    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
