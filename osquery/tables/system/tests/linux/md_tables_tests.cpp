/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <linux/raid/md_p.h>
#include <linux/raid/md_u.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <utility>

#include <osquery/tables/system/linux/md_tables.h>

using namespace testing;

namespace osquery {
namespace tables {

class MockMD : public MDInterface {
 public:
  MOCK_METHOD2(getDiskInfo, bool(const std::string&, mdu_disk_info_t&));
  MOCK_METHOD2(getArrayInfo, bool(const std::string&, mdu_array_info_t&));
  MOCK_METHOD2(parseMDStat, void(const std::vector<std::string>&, MDStat&));
  MOCK_METHOD1(getPathByDevName, std::string(const std::string&));
  MOCK_METHOD2(getDevName, std::string(int, int));
  MOCK_METHOD1(getSuperblkVersion, std::string(const std::string&));
};

class GetDrivesForArrayTest : public ::testing::Test {};

mdu_disk_info_t getDiskInfo(
    int number, int raidDisk, int state, int major, int minor) {
  mdu_disk_info_t diskInfo{};

  diskInfo.number = number;
  diskInfo.raid_disk = raidDisk;
  diskInfo.state = state;
  diskInfo.major = major;
  diskInfo.minor = minor;

  return diskInfo;
}

/**
 * @brief Engine for testing getDrivesForArray
 *
 * @param arrayName name of the array to pass to getDrivesForArray
 * @param arrayRaidDisks number of raid disks of the array to be returned by
 * ioctl
 * @param blkDevicePrefix the prefix for the block device of disk, with expected
 * name to be prefix push the disk number
 * @param targetDisks the target disks that will return custom mdu_disk_info_t
 * @param got reference to QueryData to be passed to to getDrivesForArray
 */
void GetDrivesForArrayTestHarness(const std::string& arrayName,
                                  int arrayRaidDisks,
                                  const std::string& blkDevicePrefix,
                                  std::map<int, mdu_disk_info_t> targetDisks,
                                  QueryData& got) {
  MockMD md;
  std::string arrayDevPath = "/dev/" + arrayName;

  EXPECT_CALL(md, getPathByDevName(_)).WillOnce(Return(arrayDevPath));

  mdu_array_info_t arrayInfo{};
  arrayInfo.raid_disks = arrayRaidDisks;
  EXPECT_CALL(md, getArrayInfo(arrayDevPath, _))
      .WillOnce(DoAll(SetArgReferee<1>(arrayInfo), Return(true)));

  Sequence s1;
  for (int i = 0; i < MD_SB_DISKS; i++) {
    mdu_disk_info_t diskInfo{};
    diskInfo.number = i;
    if (targetDisks.find(i) != targetDisks.end()) {
      EXPECT_CALL(md, getDiskInfo(arrayDevPath, _))
          .InSequence(s1)
          .WillOnce(DoAll(SetArgReferee<1>(targetDisks[i]), Return(true)));

      EXPECT_CALL(md, getDevName(targetDisks[i].major, targetDisks[i].minor))
          .InSequence(s1)
          .WillOnce(Return(blkDevicePrefix + std::to_string(i)));

    } else {
      diskInfo.raid_disk = -1;
      diskInfo.state = 8;
      diskInfo.major = 0;
      diskInfo.minor = 0;
      EXPECT_CALL(md, getDiskInfo(arrayDevPath, _))
          .InSequence(s1)
          .WillOnce(DoAll(SetArgReferee<1>(diskInfo), Return(true)));
    }
  }

  getDrivesForArray(arrayName, md, got);
}

TEST_F(GetDrivesForArrayTest, all_drives_healthy) {
  int majorAddend = 5;
  int minorAddend = 10;
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";

  std::map<int, mdu_disk_info_t> targets;
  for (int i = 0; i < 6; i++) {
    int major = i + majorAddend;
    int minor = i + minorAddend;

    targets[i] = getDiskInfo(i, i, 6, major, minor);
  }

  std::string arrayName = "md0";
  QueryData got;
  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "0"},
          {"state", "active sync"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "active sync"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "2"},
          {"state", "active sync"},
          {"slot", "2"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "active sync"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "4"},
          {"state", "active sync"},
          {"slot", "4"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "active sync"},
          {"slot", "5"},
      },
  };

  EXPECT_EQ(got, expected);
}

TEST_F(GetDrivesForArrayTest, all_drives_removed) {
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";
  std::map<int, mdu_disk_info_t> targets;
  std::string arrayName = "md0";
  QueryData got;

  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "0"},
          {"state", "removed"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "removed"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "2"},
          {"state", "removed"},
          {"slot", "2"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "removed"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "4"},
          {"state", "removed"},
          {"slot", "4"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "removed"},
          {"slot", "5"},
      },
  };
};

TEST_F(GetDrivesForArrayTest, all_drives_faulty) {
  int majorAddend = 5;
  int minorAddend = 10;
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";

  std::map<int, mdu_disk_info_t> targets;
  for (int i = 0; i < 6; i++) {
    int major = i + majorAddend;
    int minor = i + minorAddend;

    targets[i] = getDiskInfo(i, i, 1, major, minor);
  }

  std::string arrayName = "md0";
  QueryData got;
  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "0"},
          {"state", "faulty"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "faulty"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "2"},
          {"state", "faulty"},
          {"slot", "2"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "faulty"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "4"},
          {"state", "faulty"},
          {"slot", "4"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "faulty"},
          {"slot", "5"},
      },
  };

  EXPECT_EQ(got, expected);
};

TEST_F(GetDrivesForArrayTest, every_other_drives_faulty) {
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";

  std::map<int, mdu_disk_info_t> targets;

  targets[1] = getDiskInfo(1, 1, 6, 5, 6);
  targets[3] = getDiskInfo(3, 3, 6, 7, 8);
  targets[5] = getDiskInfo(5, 5, 6, 9, 10);
  targets[0] = getDiskInfo(0, -1, 1, 11, 12);
  targets[2] = getDiskInfo(2, -1, 1, 13, 14);
  targets[4] = getDiskInfo(4, -1, 1, 15, 16);

  std::string arrayName = "md0";
  QueryData got;
  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "0"},
          {"state", "faulty"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "active sync"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "2"},
          {"state", "faulty"},
          {"slot", "2"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "active sync"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "4"},
          {"state", "faulty"},
          {"slot", "4"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "active sync"},
          {"slot", "5"},
      },
  };

  EXPECT_EQ(got, expected);
};

TEST_F(GetDrivesForArrayTest, some_drives_removed) {
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";

  std::map<int, mdu_disk_info_t> targets;

  targets[1] = getDiskInfo(1, 1, 6, 5, 6);
  targets[3] = getDiskInfo(3, 3, 6, 7, 8);
  targets[5] = getDiskInfo(5, 5, 6, 9, 10);

  std::string arrayName = "md0";
  QueryData got;
  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {

      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "active sync"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "active sync"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "active sync"},
          {"slot", "5"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", "unknown"},
          {"state", "removed"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", "unknown"},
          {"state", "removed"},
          {"slot", "2"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", "unknown"},
          {"state", "removed"},
          {"slot", "4"},
      },
  };

  EXPECT_EQ(got, expected);
};

TEST_F(GetDrivesForArrayTest, some_faulty_some_removed) {
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";

  std::map<int, mdu_disk_info_t> targets;
  targets[0] = getDiskInfo(0, -1, 1, 5, 6);
  targets[1] = getDiskInfo(1, 1, 6, 5, 6);
  targets[3] = getDiskInfo(3, 3, 6, 7, 8);
  targets[4] = getDiskInfo(4, 4, 6, 5, 6);
  targets[5] = getDiskInfo(5, -1, 1, 9, 10);
  targets[6] = getDiskInfo(6, 0, 6, 11, 12);

  std::string arrayName = "md0";
  QueryData got;
  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "0"},
          {"state", "faulty"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "active sync"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "active sync"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "4"},
          {"state", "active sync"},
          {"slot", "4"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "faulty"},
          {"slot", "5"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "6"},
          {"state", "active sync"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", "unknown"},
          {"state", "removed"},
          {"slot", "2"},
      },
  };

  EXPECT_EQ(got, expected);
};

/* This is a very interesting test, in that it validates the inability of code
 * to predict which exactly which slot a removed or faulty drive belonged to if
 * there are multiple faulties and/or removed and the mdu_disk_info_t number is
 * greater than the number of RAID disks*/
TEST_F(GetDrivesForArrayTest, scattered_faulty_and_removed) {
  int numArrayDisks = 6;
  std::string blkDevicePrefix = "/dev/sda";

  std::map<int, mdu_disk_info_t> targets;

  targets[1] = getDiskInfo(1, 1, 6, 5, 6);
  targets[3] = getDiskInfo(3, 3, 6, 7, 8);
  targets[5] = getDiskInfo(5, 5, 6, 9, 10);
  targets[9] = getDiskInfo(9, -1, 1, 13, 14);
  targets[17] = getDiskInfo(17, -1, 1, 15, 16);

  std::string arrayName = "md0";
  QueryData got;
  GetDrivesForArrayTestHarness(
      arrayName, numArrayDisks, blkDevicePrefix, targets, got);

  QueryData expected = {
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "1"},
          {"state", "active sync"},
          {"slot", "1"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "3"},
          {"state", "active sync"},
          {"slot", "3"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "5"},
          {"state", "active sync"},
          {"slot", "5"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "9"},
          {"state", "faulty"},
          {"slot", "0"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", blkDevicePrefix + "17"},
          {"state", "faulty"},
          {"slot", "2"},
      },
      {
          {"md_device_name", arrayName},
          {"drive_name", "unknown"},
          {"state", "removed"},
          {"slot", "4"},
      },
  };

  EXPECT_EQ(got, expected);
};

TEST_F(GetDrivesForArrayTest, arrayInfo_ioctl_error) {
  MockMD md;
  std::string arrayDevPath = "/dev/md0";

  EXPECT_CALL(md, getPathByDevName(_)).WillOnce(Return(arrayDevPath));
  EXPECT_CALL(md, getArrayInfo(arrayDevPath, _)).WillOnce(Return(false));

  QueryData got;
  getDrivesForArray("md0", md, got);

  EXPECT_TRUE(got.empty());
};

class ParseMDStatTest : public ::testing::Test {};

bool operator==(MDAction const& lhs, MDAction const& rhs) {
  if (lhs.progress != rhs.progress) {
    return false;
  }

  if (lhs.finish != rhs.finish) {
    return false;
  }

  if (lhs.speed != rhs.speed) {
    return false;
  }

  return true;
}

bool operator!=(MDAction const& lhs, MDAction const& rhs) {
  return !(lhs == rhs);
}

bool operator==(MDDevice const& lhs, MDDevice const& rhs) {
  if (lhs.name != rhs.name) {
    return false;
  }

  if (lhs.status != rhs.status) {
    return false;
  }

  if (lhs.raidLevel != rhs.raidLevel) {
    return false;
  }

  if (lhs.usableSize != rhs.usableSize) {
    return false;
  }

  if (lhs.other != rhs.other) {
    return false;
  }

  if (lhs.drives.size() != rhs.drives.size()) {
    return false;
  }

  for (size_t i = 0; i < lhs.drives.size(); i++) {
    if (lhs.drives[i].name != rhs.drives[i].name) {
      return false;
    }

    if (lhs.drives[i].pos != rhs.drives[i].pos) {
      return false;
    }
  }

  if (lhs.healthyDrives != rhs.healthyDrives) {
    return false;
  }

  if (lhs.driveStatuses != rhs.driveStatuses) {
    return false;
  }

  if (lhs.recovery != rhs.recovery) {
    return false;
  }

  if (lhs.resync != rhs.resync) {
    return false;
  }

  if (lhs.reshape != rhs.reshape) {
    return false;
  }

  if (lhs.checkArray != rhs.checkArray) {
    return false;
  }

  if (lhs.bitmap.onMem != rhs.bitmap.onMem) {
    return false;
  }

  if (lhs.bitmap.chunkSize != rhs.bitmap.chunkSize) {
    return false;
  }

  if (lhs.bitmap.externalFile != rhs.bitmap.externalFile) {
    return false;
  }

  return true;
}

bool operator!=(MDDevice const& lhs, MDDevice const& rhs) {
  return !(lhs == rhs);
}

bool operator==(MDStat const& lhs, MDStat const& rhs) {
  if (lhs.personalities.size() != rhs.personalities.size()) {
    return false;
  }

  for (size_t i = 0; i < lhs.personalities.size(); i++) {
    if (lhs.personalities[i] != rhs.personalities[i]) {
      return false;
    }
  }

  if (lhs.devices.size() != rhs.devices.size()) {
    return false;
  }

  for (size_t i = 0; i < lhs.devices.size(); i++) {
    if (lhs.devices[i] != rhs.devices[i]) {
      return false;
    }
  }

  return lhs.unused == rhs.unused;
}

bool operator!=(MDStat const& lhs, MDStat const& rhs) {
  return !(lhs == rhs);
}

MDDrive getMDDrive(std::string name, size_t pos) {
  MDDrive drive;
  drive.name = std::move(name);
  drive.pos = pos;

  return drive;
}

TEST_F(ParseMDStatTest, 2_devices_1_missing_each) {
  std::vector<std::string> lines = {
      "Personalities : [raid1] [raid10] [linear] [multipath] [raid0] [raid6] "
      "[raid5] [raid4]",
      "md1 : active raid10 sde2[4] sdd2[3] sdc2[6] sdb2[7] sda2[0]",
      "4687296000 blocks super 1.2 512K chunks 2 near-copies [6/5] [UUUUU_]",
      "",
      "md0 : active raid1 sde1[4] sdf1[5] sdd1[3] sdb1[1] sda1[0]",
      "248640 blocks super 1.2 [6/5] [UU_UUU]",
      "",
      "unused devices: <none>",
  };

  MDStat expected;
  expected.personalities = {
      "raid1",
      "raid10",
      "linear",
      "multipath",
      "raid0",
      "raid6",
      "raid5",
      "raid4",
  };

  MDDevice md0, md1;

  md1.name = "md1";
  md1.status = "active";
  md1.raidLevel = "raid10";
  md1.usableSize = 4687296000;
  md1.drives = {
      getMDDrive("sde2[4]", 4),
      getMDDrive("sdd2[3]", 3),
      getMDDrive("sdc2[6]", 6),
      getMDDrive("sdb2[7]", 7),
      getMDDrive("sda2[0]", 0),
  };
  md1.other = "super 1.2 512K chunks 2 near-copies";
  md1.healthyDrives = "[6/5]";
  md1.driveStatuses = "[UUUUU_]";

  md0.name = "md0";
  md0.status = "active";
  md0.raidLevel = "raid1";
  md0.usableSize = 248640;
  md0.drives = {
      getMDDrive("sde1[4]", 4),
      getMDDrive("sdf1[5]", 5),
      getMDDrive("sdd1[3]", 3),
      getMDDrive("sdb1[1]", 1),
      getMDDrive("sda1[0]", 0),
  };
  md0.other = "super 1.2";
  md0.healthyDrives = "[6/5]";
  md0.driveStatuses = "[UU_UUU]";

  expected.devices = {md1, md0};

  expected.unused = "<none>";

  MD md;
  MDStat got;
  md.parseMDStat(lines, got);
  EXPECT_EQ(got, expected);
};

TEST_F(ParseMDStatTest, 2_devices_1_recovery) {
  std::vector<std::string> lines = {
      "Personalities : [raid1] [raid10] [linear] [multipath] [raid0] [raid6] "
      "[raid5] [raid4]",
      "md1 : active raid10 sde2[4] sdd2[3] sdc2[6] sdb2[7] sda2[0]",
      "4687296000 blocks super 1.2 512K chunks 2 near-copies [6/5] [UUUUU_]",
      "[>....................]  recovery =  0.0% (1021056/1562432000) "
      "finish=127.4min speed=204211K/sec",
      "",
      "md0 : active raid1 sde1[4] sdf1[5] sdd1[3] sdb1[1] sda1[0]",
      "248640 blocks super 1.2 [6/5] [UU_UUU]",
      "",
      "unused devices: <none>",
  };

  MDStat expected;
  expected.personalities = {
      "raid1",
      "raid10",
      "linear",
      "multipath",
      "raid0",
      "raid6",
      "raid5",
      "raid4",
  };

  MDDevice md0, md1;

  md1.name = "md1";
  md1.status = "active";
  md1.raidLevel = "raid10";
  md1.usableSize = 4687296000;
  md1.drives = {
      getMDDrive("sde2[4]", 4),
      getMDDrive("sdd2[3]", 3),
      getMDDrive("sdc2[6]", 6),
      getMDDrive("sdb2[7]", 7),
      getMDDrive("sda2[0]", 0),
  };
  md1.other = "super 1.2 512K chunks 2 near-copies";
  md1.healthyDrives = "[6/5]";
  md1.driveStatuses = "[UUUUU_]";
  md1.recovery.progress = "0.0% (1021056/1562432000)";
  md1.recovery.finish = "127.4min";
  md1.recovery.speed = "204211K/sec";

  md0.name = "md0";
  md0.status = "active";
  md0.raidLevel = "raid1";
  md0.usableSize = 248640;
  md0.drives = {
      getMDDrive("sde1[4]", 4),
      getMDDrive("sdf1[5]", 5),
      getMDDrive("sdd1[3]", 3),
      getMDDrive("sdb1[1]", 1),
      getMDDrive("sda1[0]", 0),
  };
  md0.other = "super 1.2";
  md0.healthyDrives = "[6/5]";
  md0.driveStatuses = "[UU_UUU]";

  expected.devices = {md1, md0};

  expected.unused = "<none>";

  MD md;
  MDStat got;
  md.parseMDStat(lines, got);

  EXPECT_EQ(got, expected);
};

TEST_F(ParseMDStatTest, 2_devices_2_actions) {
  std::vector<std::string> lines = {
      "Personalities : [raid1] [raid10] [linear] [multipath] [raid0] [raid6] "
      "[raid5] [raid4]",
      "md1 : active raid10 sde2[4] sdd2[3] sdc2[6] sdb2[7] sda2[0]",
      "4687296000 blocks super 1.2 512K chunks 2 near-copies [6/5] [UUUUU_]",
      "[>....................]  recovery =  0.0% (1021056/1562432000) "
      "finish=127.4min speed=204211K/sec",
      "[======>..............]  check = 34.1% (716160/2095040) finish=0.0min "
      "speed=238720K/sec",
      "",
      "md0 : active raid1 sde1[4] sdf1[5] sdd1[3] sdb1[1] sda1[0]",
      "248640 blocks super 1.2 [6/5] [UU_UUU]",
      "",
      "unused devices: <none>",
  };

  MDStat expected;
  expected.personalities = {
      "raid1",
      "raid10",
      "linear",
      "multipath",
      "raid0",
      "raid6",
      "raid5",
      "raid4",
  };

  MDDevice md0, md1;

  md1.name = "md1";
  md1.status = "active";
  md1.raidLevel = "raid10";
  md1.usableSize = 4687296000;
  md1.drives = {
      getMDDrive("sde2[4]", 4),
      getMDDrive("sdd2[3]", 3),
      getMDDrive("sdc2[6]", 6),
      getMDDrive("sdb2[7]", 7),
      getMDDrive("sda2[0]", 0),
  };
  md1.other = "super 1.2 512K chunks 2 near-copies";
  md1.healthyDrives = "[6/5]";
  md1.driveStatuses = "[UUUUU_]";
  md1.recovery.progress = "0.0% (1021056/1562432000)";
  md1.recovery.finish = "127.4min";
  md1.recovery.speed = "204211K/sec";
  md1.checkArray.progress = "34.1% (716160/2095040)";
  md1.checkArray.finish = "0.0min";
  md1.checkArray.speed = "238720K/sec";

  md0.name = "md0";
  md0.status = "active";
  md0.raidLevel = "raid1";
  md0.usableSize = 248640;
  md0.drives = {
      getMDDrive("sde1[4]", 4),
      getMDDrive("sdf1[5]", 5),
      getMDDrive("sdd1[3]", 3),
      getMDDrive("sdb1[1]", 1),
      getMDDrive("sda1[0]", 0),
  };
  md0.other = "super 1.2";
  md0.healthyDrives = "[6/5]";
  md0.driveStatuses = "[UU_UUU]";

  expected.devices = {md1, md0};

  expected.unused = "<none>";

  MD md;
  MDStat got;
  md.parseMDStat(lines, got);
  EXPECT_EQ(got, expected);
};

TEST_F(ParseMDStatTest, 2_devices_1_recovery_1_delay) {
  std::vector<std::string> lines = {
      "Personalities : [raid1] [raid10] [linear] [multipath] [raid0] [raid6] "
      "[raid5] [raid4]",
      "md1 : active raid10 sde2[4] sdd2[3] sdc2[6] sdb2[7] sda2[0]",
      "4687296000 blocks super 1.2 512K chunks 2 near-copies [6/5] [UUUUU_]",
      "[>....................]  recovery =  0.0% (1021056/1562432000) "
      "finish=127.4min speed=204211K/sec",
      "",
      "md0 : active raid1 sde1[4] sdf1[5] sdd1[3] sdb1[1] sda1[0]",
      "248640 blocks super 1.2 [6/5] [UU_UUU]",
      "resync=DELAYED",
      "",
      "unused devices: <none>",
  };

  MDStat expected;
  expected.personalities = {
      "raid1",
      "raid10",
      "linear",
      "multipath",
      "raid0",
      "raid6",
      "raid5",
      "raid4",
  };

  MDDevice md0, md1;

  md1.name = "md1";
  md1.status = "active";
  md1.raidLevel = "raid10";
  md1.usableSize = 4687296000;
  md1.drives = {
      getMDDrive("sde2[4]", 4),
      getMDDrive("sdd2[3]", 3),
      getMDDrive("sdc2[6]", 6),
      getMDDrive("sdb2[7]", 7),
      getMDDrive("sda2[0]", 0),
  };
  md1.other = "super 1.2 512K chunks 2 near-copies";
  md1.healthyDrives = "[6/5]";
  md1.driveStatuses = "[UUUUU_]";
  md1.recovery.progress = "0.0% (1021056/1562432000)";
  md1.recovery.finish = "127.4min";
  md1.recovery.speed = "204211K/sec";

  md0.name = "md0";
  md0.status = "active";
  md0.raidLevel = "raid1";
  md0.usableSize = 248640;
  md0.drives = {
      getMDDrive("sde1[4]", 4),
      getMDDrive("sdf1[5]", 5),
      getMDDrive("sdd1[3]", 3),
      getMDDrive("sdb1[1]", 1),
      getMDDrive("sda1[0]", 0),
  };
  md0.other = "super 1.2";
  md0.healthyDrives = "[6/5]";
  md0.driveStatuses = "[UU_UUU]";
  md0.resync.progress = "DELAYED";

  expected.devices = {md1, md0};

  expected.unused = "<none>";

  MD md;
  MDStat got;
  md.parseMDStat(lines, got);
  EXPECT_EQ(got, expected);
};

TEST_F(ParseMDStatTest, 2_devices_1_recovery_bitmap) {
  std::vector<std::string> lines = {
      "Personalities : [raid1] [raid10] [linear] [multipath] [raid0] [raid6] "
      "[raid5] [raid4]",
      "md1 : active raid10 sde2[4] sdd2[3] sdc2[6] sdb2[7] sda2[0]",
      "4687296000 blocks super 1.2 512K chunks 2 near-copies [6/5] [UUUUU_]",
      "bitmap: 0/234 pages [0KB], 512KB chunk",
      "[>....................]  recovery =  0.0% (1021056/1562432000) "
      "finish=127.4min speed=204211K/sec",
      "",
      "md0 : active raid1 sde1[4] sdf1[5] sdd1[3] sdb1[1] sda1[0]",
      "248640 blocks super 1.2 [6/5] [UU_UUU]",
      "",
      "unused devices: <none>",
  };

  MDStat expected;
  expected.personalities = {
      "raid1",
      "raid10",
      "linear",
      "multipath",
      "raid0",
      "raid6",
      "raid5",
      "raid4",
  };

  MDDevice md0, md1;

  md1.name = "md1";
  md1.status = "active";
  md1.raidLevel = "raid10";
  md1.usableSize = 4687296000;
  md1.drives = {
      getMDDrive("sde2[4]", 4),
      getMDDrive("sdd2[3]", 3),
      getMDDrive("sdc2[6]", 6),
      getMDDrive("sdb2[7]", 7),
      getMDDrive("sda2[0]", 0),
  };
  md1.other = "super 1.2 512K chunks 2 near-copies";
  md1.healthyDrives = "[6/5]";
  md1.driveStatuses = "[UUUUU_]";
  md1.recovery.progress = "0.0% (1021056/1562432000)";
  md1.recovery.finish = "127.4min";
  md1.recovery.speed = "204211K/sec";
  md1.bitmap.onMem = "0/234 pages [0KB]";
  md1.bitmap.chunkSize = "512KB chunk";

  md0.name = "md0";
  md0.status = "active";
  md0.raidLevel = "raid1";
  md0.usableSize = 248640;
  md0.drives = {
      getMDDrive("sde1[4]", 4),
      getMDDrive("sdf1[5]", 5),
      getMDDrive("sdd1[3]", 3),
      getMDDrive("sdb1[1]", 1),
      getMDDrive("sda1[0]", 0),
  };
  md0.other = "super 1.2";
  md0.healthyDrives = "[6/5]";
  md0.driveStatuses = "[UU_UUU]";

  expected.devices = {md1, md0};

  expected.unused = "<none>";

  MD md;
  MDStat got;
  md.parseMDStat(lines, got);
  EXPECT_EQ(got, expected);
};

TEST_F(ParseMDStatTest, 2_devices_1_recovery_bitmap_file) {
  std::vector<std::string> lines = {
      "Personalities : [raid1] [raid10] [linear] [multipath] [raid0] [raid6] "
      "[raid5] [raid4]",
      "md1 : active raid10 sde2[4] sdd2[3] sdc2[6] sdb2[7] sda2[0]",
      "4687296000 blocks super 1.2 512K chunks 2 near-copies [6/5] [UUUUU_]",
      "bitmap: 5/113 pages [20KB], 8192KB chunk, file: "
      "/WIBS/<node>:md0/WIB_<node>:md0",
      "",
      "md0 : active raid1 sde1[4] sdf1[5] sdd1[3] sdb1[1] sda1[0]",
      "248640 blocks super 1.2 [6/5] [UU_UUU]",
      "",
      "unused devices: <none>",
  };

  MDStat expected;
  expected.personalities = {
      "raid1",
      "raid10",
      "linear",
      "multipath",
      "raid0",
      "raid6",
      "raid5",
      "raid4",
  };

  MDDevice md0, md1;

  md1.name = "md1";
  md1.status = "active";
  md1.raidLevel = "raid10";
  md1.usableSize = 4687296000;
  md1.drives = {
      getMDDrive("sde2[4]", 4),
      getMDDrive("sdd2[3]", 3),
      getMDDrive("sdc2[6]", 6),
      getMDDrive("sdb2[7]", 7),
      getMDDrive("sda2[0]", 0),
  };
  md1.other = "super 1.2 512K chunks 2 near-copies";
  md1.healthyDrives = "[6/5]";
  md1.driveStatuses = "[UUUUU_]";
  md1.bitmap.onMem = "5/113 pages [20KB]";
  md1.bitmap.chunkSize = "8192KB chunk";
  md1.bitmap.externalFile = "/WIBS/<node>:md0/WIB_<node>:md0";

  md0.name = "md0";
  md0.status = "active";
  md0.raidLevel = "raid1";
  md0.usableSize = 248640;
  md0.drives = {
      getMDDrive("sde1[4]", 4),
      getMDDrive("sdf1[5]", 5),
      getMDDrive("sdd1[3]", 3),
      getMDDrive("sdb1[1]", 1),
      getMDDrive("sda1[0]", 0),
  };
  md0.other = "super 1.2";
  md0.healthyDrives = "[6/5]";
  md0.driveStatuses = "[UU_UUU]";

  expected.devices = {md1, md0};

  expected.unused = "<none>";

  MD md;
  MDStat got;
  md.parseMDStat(lines, got);
  EXPECT_EQ(got, expected);
};

TEST_F(ParseMDStatTest, negative_test_unexpected_texts_in_substr_receivers) {
  std::vector<std::string> lines = {
      "Personalities : [] r",
      "md1 : active raid10 sde2[ sdd2] sdc2 sdb2 sda2][",
      "4687296000 blocks super 1.2 512K chunks 2 near-copies [6/5] [UUUUU_]",
      "[>....................]  recovery =",
      "check =",
      "bitmap: 5/113 pages [20KB], 8192KB chunk, file:",
      "",
      "md0",
      "248640 blocks super 1.2 [6/5] [UU_UUU]",
      "",
      "unu <none>",
  };

  MDStat expected;
  expected.personalities = {};

  MDDevice md1;

  md1.name = "md1";
  md1.status = "active";
  md1.raidLevel = "raid10";
  md1.usableSize = 4687296000;
  md1.drives = {
      getMDDrive("sde2[", 0),
      getMDDrive("sdd2]", 0),
      getMDDrive("sdc2", 0),
      getMDDrive("sdb2", 0),
      getMDDrive("sda2][", 0),
  };
  md1.other = "super 1.2 512K chunks 2 near-copies";
  md1.healthyDrives = "[6/5]";
  md1.driveStatuses = "[UUUUU_]";

  expected.devices = {md1};

  MD md;
  MDStat got;
  md.parseMDStat(lines, got);
  EXPECT_EQ(got, expected);
};

} // namespace tables
} // namespace osquery
