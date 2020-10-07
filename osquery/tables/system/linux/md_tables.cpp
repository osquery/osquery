/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
#include <numeric>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <osquery/events/linux/udev.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/linux/md_tables.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {
namespace tables {

const std::string kMDStatPath = "/proc/mdstat";

/**
 * @brief Removes prefixing and suffixing character from each string in vector
 *
 * @param strs reference to vector of target strings
 *
 */
static inline void trimStrs(std::vector<std::string>& strs) {
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
static inline void getLines(std::vector<std::string>& lines) {
  if (!pathExists(kMDStatPath).ok()) {
    return;
  }

  std::string content;
  if (!readFile(kMDStatPath, content).ok()) {
    return;
  }

  lines = split(content, "\n");
  trimStrs(lines);
}

/**
 * @brief function for walking through a udev subsystem and working on devices
 *
 * @param systemName the name of the sysfs subsytem to work with
 * @param f function to execute on the subsystem; returns true if can break the
 * device loop, false to keep walking
 *
 */
void walkUdevDevices(const std::string& systemName,
                     std::function<bool(udev_device* const&)> f) {
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

  udev_list_entry* entry;
  udev_list_entry_foreach(entry, device_entries) {
    const char* path = udev_list_entry_get_name(entry);

    auto delUdevDevice = [](udev_device* d) { udev_device_unref(d); };
    std::unique_ptr<udev_device, decltype(delUdevDevice)> device(
        udev_device_new_from_syspath(handle.get(), path), delUdevDevice);
    if (device.get() == nullptr) {
      LOG(ERROR) << "Could not get udev device handle";
      continue;
    }
    if (f(device.get()) == true) {
      break;
    }
  }
}

std::string MD::getPathByDevName(const std::string& name) {
  std::string devPath;

  walkUdevDevices("block", [&](udev_device* const& device) {
    auto const devName = std::string(
      udev_device_get_property_value(device, "DEVNAME")
    );
    if (boost::ends_with(devName, name)) {
      if (!boost::starts_with(devPath, "/")) {
        devPath = "/dev/" + devPath;
      } else {
        devPath = devName;
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

std::string MD::getSuperblkVersion(const std::string& arrayName) {
  std::string version;

  walkUdevDevices("block", [&](udev_device* const& device) {
    const char* devName = udev_device_get_property_value(device, "DEVNAME");

    if (arrayName.compare(strlen(devName) - arrayName.length(),
                          std::string::npos,
                          devName) == 0) {
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
  if (state == 0) {
    return "recovering";
  }

  std::string s;

  std::map<int, std::string> possibleStates = {
#ifdef MD_DISK_FAULTY
      {MD_DISK_FAULTY, "faulty "},
#endif
#ifdef MD_DISK_ACTIVE
      {MD_DISK_ACTIVE, "active "},
#endif
#ifdef MD_DISK_SYNC
      {MD_DISK_SYNC, "sync "},
#endif
#ifdef MD_DISK_REMOVED
      {MD_DISK_REMOVED, "removed "},
#endif
#ifdef MD_DISK_WRITEMOSTLY
      {MD_DISK_WRITEMOSTLY, "writemostly "},
#endif
#ifdef MD_DISK_FAILFAST
      {MD_DISK_FAILFAST, "failfast "},
#endif
#ifdef MD_DISK_JOURNAL
      {MD_DISK_JOURNAL, "journal "},
#endif
#ifdef MD_DISK_CANDIDATE
      {MD_DISK_CANDIDATE, "spare "},
#endif
#ifdef MD_DISK_CLUSTER_ADD
      {MD_DISK_CLUSTER_ADD, "clusteradd "},
#endif
  };

  for (auto const& ps : possibleStates) {
    if ((1 << ps.first) & state) {
      s += ps.second;
    }
  }

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
  if (state == 0) {
    return "unknown";
  }

  std::string s;

  std::map<int, std::string> possibleStates = {
#ifdef MD_SB_CLEAN
      {MD_SB_CLEAN, "clean "},
#endif
#ifdef MD_SB_ERRORS
      {MD_SB_ERRORS, "errors "},
#endif
#ifdef MD_SB_BBM_ERRORS
      {MD_SB_BBM_ERRORS, "bbm_errors "},
#endif
#ifdef MD_SB_BLOCK_CONTAINER_RESHAPE
      {MD_SB_BLOCK_CONTAINER_RESHAPE, "container_reshape "},
#endif
#ifdef MD_SB_BLOCK_VOLUME
      {MD_SB_BLOCK_VOLUME, "block_activation "},
#endif
#ifdef MD_SB_CLUSTERED
      {MD_SB_CLUSTERED, "clustered "},
#endif
#ifdef MD_SB_BITMAP_PRESENT
      {MD_SB_BITMAP_PRESENT, "bitmap_present "},
#endif
  };

  for (auto const& ps : possibleStates) {
    if ((1 << ps.first) & state) {
      s += ps.second;
    }
  }

  boost::algorithm::trim(s);
  return s;
}

bool MD::getDiskInfo(const std::string& arrayName, mdu_disk_info_t& diskInfo) {
  int fd = open(arrayName.c_str(), O_RDONLY);
  if (fd == -1) {
    return false;
  }

  auto status = ioctl(fd, GET_DISK_INFO, &diskInfo);
  close(fd);

  if (status == -1) {
    LOG(WARNING) << "Call to ioctl 'GET_DISK_INFO' " << arrayName
                 << " failed: " << strerror(errno);
    return false;
  }

  return true;
}

bool MD::getArrayInfo(const std::string& name, mdu_array_info_t& array) {
  int fd = open(name.c_str(), O_RDONLY);
  if (fd == -1) {
    return false;
  }

  auto status = ioctl(fd, GET_ARRAY_INFO, &array);
  close(fd);

  if (status == -1) {
    LOG(ERROR) << "Call to ioctl 'GET_ARRAY_INFO' for " << name
               << " failed: " << strerror(errno);
    return false;
  }

  return true;
}

inline void parseMDPersonalities(const std::string& line,
                                 std::vector<std::string>& result) {
  auto enabledPersonalities(split(line, " "));
  for (auto& p : enabledPersonalities) {
    boost::algorithm::trim(p);
    if (p.length() > 2) {
      result.push_back(p.substr(1, p.length() - 2));
    }
  }
}

void parseMDAction(const std::string& line, MDAction& result) {
  /* Make assumption that recovery/resync format is [d+]% ([d+]/[d+])
   * finish=<duration> speed=<rate> */
  auto pieces(split(line, " "));
  if (pieces.size() != 4) {
    LOG(WARNING) << "Unexpected recovery/resync line format: " << line;
    return;
  }
  trimStrs(pieces);

  result.progress = pieces[0] + ' ' + pieces[1];

  auto start = pieces[2].find_first_not_of("finish=");
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

void parseMDBitmap(const std::string& line, MDBitmap& result) {
  auto bitmapInfos(split(line, ","));
  if (bitmapInfos.size() < 2) {
    LOG(WARNING) << "Unexpected bitmap line structure: " << line;

  } else {
    trimStrs(bitmapInfos);
    result.onMem = bitmapInfos[0];
    result.chunkSize = bitmapInfos[1];

    if (bitmapInfos.size() > 2) {
      auto pos = bitmapInfos[2].find("file:");
      if (pos != std::string::npos) {
        result.externalFile = bitmapInfos[2].substr(pos + sizeof("file:") - 1);
        boost::algorithm::trim(result.externalFile);
      }
    }
  }
}

/*
 * @brief Handles checkArrays, resyncs, reshapes, bitmap lines of mdstat
 *
 * @param lines mdstat file represented as vector of lines
 * @param n ref to current line number; works on line n + 1
 * @param searchTerm search term to determine line should be handled
 * @param handleFunc function to execute when search term is found and line is
 * extracted
 *
 * @return bool indicating whether a line for the searchTerm was found in the
 * line n + 1 and handleFunc was executed, increments param n to n + 1.  Returns
 * false if value referenced by `n` + 1 is out of bounds.
 */
static inline bool handleMDStatuses(
    const std::vector<std::string>& lines,
    size_t& n,
    const std::string& searchTerm,
    std::function<void(const std::string& line)> handleFunc) {
  // Bounds check to ensure `n + 1` is a valid position in lines.
  if (n + 2 > lines.size()) {
    return false;
  }

  // Store on stack to avoid extra pointer jumps
  auto l = lines[n + 1];
  std::size_t pos = l.find(searchTerm);
  if (pos != std::string::npos && l.length() > (pos + searchTerm.length())) {
    std::string line(l.substr(pos + searchTerm.length()));
    boost::algorithm::trim(line);
    handleFunc(line);
    // Add an extra line for next iteration if so..
    n += 1;
    return true;
  }

  return false;
}

MDDrive parseMDDrive(const std::string& name) {
  MDDrive drive = {};
  drive.name = name;

  auto start = name.find('[');
  auto end = name.find(']');
  if (start == std::string::npos || end == std::string::npos || start > end) {
    LOG(WARNING) << "Unexpected drive name format: " << name;
    return drive;
  }

  // No need to check name length since we know it is at least 2 characters.
  drive.pos = std::stoi(name.substr(start + 1, end - start - 1));

  return drive;
}

void MD::parseMDStat(const std::vector<std::string>& lines, MDStat& result) {
  // Will be used to determine starting point of lines to work on.
  size_t n = 0;

  if (lines.empty()) {
    return;
  }

  // This should always evaluate to true, but just in case we check.
  if (lines[0].find("Personalities :") != std::string::npos) {
    std::string pline(lines[0].substr(sizeof("Personalities :") - 1));
    parseMDPersonalities(pline, result.personalities);

    n = 1;

  } else {
    LOG(WARNING) << "mdstat Personalities not found at line 0: " << lines[0];
  }

  while (n < lines.size()) {
    if (lines[n].find_first_not_of("\t\r\v ") == std::string::npos ||
        lines[n].length() < 2) {
      n += 1;
      continue;
    }
    // Work off of first 2 character instead of just the first to be safe.
    std::string firstTwo = lines[n].substr(0, 2);
    if (firstTwo == "md") {
      auto mdline(split(lines[n], ':', 1));
      if (mdline.size() < 2) {
        LOG(WARNING) << "Unexpected md device line structure: " << lines[n];
        n += 1;
        continue;
      }

      MDDevice mdd;
      mdd.name = std::move(mdline[0]);
      boost::algorithm::trim(mdd.name);

      auto settings(split(mdline[1], " "));
      trimStrs(settings);
      // First 2 of settings are always status and RAID level
      if (settings.size() >= 2) {
        mdd.status = std::move(settings[0]);
        mdd.raidLevel = std::move(settings[1]);

        for (size_t i = 2; i < settings.size(); i++) {
          mdd.drives.push_back(parseMDDrive(settings[i]));
        }
      }

      /* Next line is device config and settings.  We handle here instead of
       * later b/c pieces are need for both md_drives and md_devices table.  For
       * safety, we check if we at the end of the file. */
      if (n >= lines.size() - 1) {
        continue;
      }
      auto configline(split(lines[n + 1]));

      if (configline.size() < 4) {
        LOG(WARNING) << "Unexpected md device config: " << lines[n + 1];

      } else {
        trimStrs(configline);

        if (configline[1] == "blocks") {
          auto const exp = tryTo<long>(configline[0], 10);
          if (exp.isError()) {
            LOG(WARNING) << "Could not parse usable size of " << mdd.name;
          } else {
            mdd.usableSize = exp.get();
          }

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
      while (n < lines.size() - 1) {
        if (handleMDStatuses(
                lines, n, "recovery =", [&mdd](const std::string& line) {
                  parseMDAction(line, mdd.recovery);
                })) {
          continue;
        }

        if (handleMDStatuses(
                lines, n, "resync =", [&mdd](const std::string& line) {
                  parseMDAction(line, mdd.resync);
                })) {
          continue;
        }

        // If in this format, it's generally signaling a progress delay
        if (handleMDStatuses(
                lines, n, "resync=", [&mdd](const std::string& line) {
                  mdd.resync.progress = line;
                })) {
          continue;
        }

        if (handleMDStatuses(
                lines, n, "reshape =", [&mdd](const std::string& line) {
                  parseMDAction(line, mdd.reshape);
                })) {
          continue;
        }

        if (handleMDStatuses(
                lines, n, "check =", [&mdd](const std::string& line) {
                  parseMDAction(line, mdd.checkArray);
                })) {
          continue;
        }

        if (handleMDStatuses(
                lines, n, "bitmap:", [&mdd](const std::string& line) {
                  parseMDBitmap(line, mdd.bitmap);
                })) {
          continue;
        }

        // If none of above, then we can break out of loop
        break;
      }

      result.devices.push_back(mdd);

      // Assume unused but check length for safety
    } else if (firstTwo == "un" &&
               lines[n].length() > sizeof("unused devices:")) {
      result.unused = lines[n].substr(sizeof("unused devices:") - 1);
      boost::algorithm::trim(result.unused);
      // Unexpected mdstat line, log a warning...
    } else {
      LOG(WARNING) << "Unexpected mdstat line: " << lines[n];
    }

    n += 1;
  }
}

void getDrivesForArray(const std::string& arrayName,
                       MDInterface& md,
                       QueryData& data) {
  std::string path(md.getPathByDevName(arrayName));
  if (path.empty()) {
    LOG(ERROR) << "Could not get file path for " << arrayName;
    return;
  }

  mdu_array_info_t array;
  if (!md.getArrayInfo(path, array)) {
    return;
  }

  /* Create a vector of with all expected slot positions.  As we work through
   * the RAID disks, we remove discovered slots */
  std::vector<size_t> missingSlots(array.raid_disks);
  std::iota(missingSlots.begin(), missingSlots.end(), 0);

  /* Keep track of index in QueryData that have removed slots since we can't
   * make safe assumptions about it's original slot position if disk_number >=
   * total_disk and we're unable to deteremine total number of missing slots
   * until we walk through all MD_SB_DISKS */
  std::vector<size_t> removedSlots;

  size_t qdPos = data.size();
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

      if (disk.raid_disk >= 0) {
        r["slot"] = INTEGER(disk.raid_disk);
        missingSlots.erase(
            std::remove(
                missingSlots.begin(), missingSlots.end(), disk.raid_disk),
            missingSlots.end());

        /* We assume that if the disk number is less than the total disk count
         * of the array, then it assumes its original slot position;  If the
         * number is greater than the disk count, then it's not safe to make
         * that assumption. We do this check here b/c if a recovery is targeted
         * for the same slot, we potentially miss identifying the original slot
         * position of the bad disk. */
      } else if (disk.raid_disk < 0 && disk.number < array.raid_disks) {
        r["slot"] = INTEGER(disk.number);
        missingSlots.erase(
            std::remove(missingSlots.begin(), missingSlots.end(), disk.number),
            missingSlots.end());

        /* Mark QueryData position as a removedSlot to handle later*/
      } else {
        removedSlots.push_back(qdPos);
      }

      qdPos++;
      data.push_back(r);
    }
  }

  /* Handle all missing slots.  See `scattered_faulty_and_removed` unit test in
   * `./tests/md_tables_tests.cpp`*/
  for (const auto& slot : missingSlots) {
    if (!removedSlots.empty()) {
      data[removedSlots[0]]["slot"] = INTEGER(slot);
      removedSlots.erase(removedSlots.begin());

    } else {
      Row r;
      r["md_device_name"] = arrayName;
      r["drive_name"] = "unknown";
      r["state"] = "removed";
      r["slot"] = INTEGER(slot);
      data.push_back(r);
    }
  }
}

QueryData genMDDrives(QueryContext& context) {
  QueryData results;
  MDStat mds;
  MD md;
  std::vector<std::string> lines;
  getLines(lines);

  md.parseMDStat(lines, mds);

  for (const auto& device : mds.devices) {
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
  for (const auto& device : mds.devices) {
    std::string path(md.getPathByDevName(device.name));
    if (path.empty()) {
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

    if (!device.recovery.progress.empty()) {
      r["recovery_progress"] = device.recovery.progress;
      r["recovery_finish"] = device.recovery.finish;
      r["recovery_speed"] = device.recovery.speed;
    }

    if (!device.resync.progress.empty()) {
      r["resync_progress"] = device.resync.progress;
      r["resync_finish"] = device.resync.finish;
      r["resync_speed"] = device.resync.speed;
    }

    if (!device.reshape.progress.empty()) {
      r["reshape_progress"] = device.reshape.progress;
      r["reshape_finish"] = device.reshape.finish;
      r["reshape_speed"] = device.reshape.speed;
    }

    if (!device.checkArray.progress.empty()) {
      r["check_array_progress"] = device.checkArray.progress;
      r["check_array_finish"] = device.checkArray.finish;
      r["check_array_speed"] = device.checkArray.speed;
    }

    if (!device.bitmap.onMem.empty()) {
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

  for (const auto& name : mds.personalities) {
    Row r = {{"name", name}};

    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
