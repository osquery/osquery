/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <linux/raid/md_u.h>

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

struct MDDrive {
  std::string name;
  size_t pos;

  MDDrive() : pos(0) {}
};

struct MDAction {
  std::string progress;
  std::string finish;
  std::string speed;
};

struct MDBitmap {
  std::string onMem;
  std::string chunkSize;
  std::string externalFile;
};

struct MDDevice {
  std::string name;
  std::string status;
  std::string raidLevel;
  long usableSize;
  std::string other;
  std::vector<MDDrive> drives;
  std::string healthyDrives;
  std::string driveStatuses;
  MDAction recovery;
  MDAction resync;
  MDAction reshape;
  MDAction checkArray;
  MDBitmap bitmap;

  MDDevice() : usableSize(0) {}
};

struct MDStat {
  std::vector<std::string> personalities;
  std::vector<MDDevice> devices;
  std::string unused;
};

class MDInterface {
 public:
  /**
   * @brief request disk information from MD drivers
   *
   * @param arrayName name of the md array, ie. `md0`
   * @param diskInfo mdu_disk_info_t with number field filled
   *
   * @return bool indicating success of system call
   */
  virtual bool getDiskInfo(const std::string& arrayName,
                           mdu_disk_info_t& diskInfo) = 0;

  /**
   * @brief request array information from MD drivers
   *
   * @param name name of the md array, ie. `md0`
   * @param array empty struct of mdu_array_info_t; will be filled out with info
   *
   * @return bool indicating success of system call
   */
  virtual bool getArrayInfo(const std::string& name,
                            mdu_array_info_t& array) = 0;

  /**
   * @brief Parse mdstat text blob into MDStat struct
   *
   * @param lines mdstat file as a vector of lines
   * @param result reference to a MDStat struct to store results into
   *
   * This function makes assumption about the structure of the mdstat text
   * blobs. If the structure is not what it expects, the logs a warning message
   * and moves on.
   *
   */
  virtual void parseMDStat(const std::vector<std::string>& lines,
                           MDStat& result) = 0;

  /**
   * @brief gets the path to device driver by short name
   *
   * @param name name of the device, ie. `md0`
   *
   */
  virtual std::string getPathByDevName(const std::string& name) = 0;

  /**
   * @brief gets the device name by its major and minor number
   *
   * @param major major number
   * @param minor minor number
   *
   */
  virtual std::string getDevName(int major, int minor) = 0;

  /**
   * @brief gets the superblock version of the array
   *
   * @param name name of the array device
   *
   */
  virtual std::string getSuperblkVersion(const std::string& arrayName) = 0;

 public:
  virtual ~MDInterface() {}
};

class MD : public MDInterface {
 public:
  /**
   * @brief request disk information from MD drivers
   *
   * @param arrayName name of the md array, ie. `md0`
   * @param diskInfo mdu_disk_info_t with number field filled
   *
   * @return bool indicating success of system call
   */
  bool getDiskInfo(const std::string& arrayName,
                   mdu_disk_info_t& diskInfo) override;

  /**
   * @brief request array information from MD drivers
   *
   * @param name name of the md array, ie. `md0`
   * @param array empty struct of mdu_array_info_t; will be filled out with info
   *
   * @return bool indicating success of system call
   */
  bool getArrayInfo(const std::string& name, mdu_array_info_t& array) override;

  /**
   * @brief Parse mdstat text blob into MDStat struct
   *
   * @param lines mdstat file as a vector of lines
   * @param result reference to a MDStat struct to store results into
   *
   * This function makes assumption about the structure of the mdstat text
   * blobs. If the structure is not what it expects, the logs a warning message
   * and moves on.
   *
   */
  void parseMDStat(const std::vector<std::string>& lines,
                   MDStat& result) override;

  /**
   * @brief gets the path to device driver by short name
   *
   * @param name name of the device, ie. `md0`
   *
   */
  std::string getPathByDevName(const std::string& name) override;

  /**
   * @brief gets the device name by its major and minor number
   *
   * @param major major number
   * @param minor minor number
   *
   */
  std::string getDevName(int major, int minor) override;

  /**
   * @brief gets the superblock version of the array
   *
   * @param name name of the array device
   *
   */
  std::string getSuperblkVersion(const std::string& arrayName) override;
};

/**
 * @brief gets all the drive information associated with a particular array.
 *
 * @param arrayName name of the md array, ie. `md0`
 * @param data QueryData to be filed out
 *
 */
void getDrivesForArray(const std::string& arrayName,
                       MDInterface& md,
                       QueryData& data);

} // namespace tables
} // namespace osquery
