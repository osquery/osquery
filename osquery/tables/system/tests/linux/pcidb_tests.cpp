/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/system/linux/pci_devices.h>

namespace osquery {
namespace tables {

class PciDBTest : public testing::Test {};

TEST_F(PciDBTest, basic_db_format) {
  std::istringstream raw_db(
      "# Some Test Comment\n"
      "8002  Fake Vendor, Inc.\n"
      "\t1312  Foobar\n"
      "\t1313  Foobar [Some R7 Rapidfire]\n"
      "\t1314  Wrestler HDMI Audio\n"
      "\t\t174b 1001  90K Diffusion Mini\n"
      "\t1315  Foobar [Some R5 Rapidfire]\n"
      "\t1316  Foobar [Some R5 Rapidfire]\n"
      "\t1317  Foobar\n"
      "\t1318  Foobar [Some R5 Rapidfire]\n"
      "\t131b  Foobar [Some R4 Rapidfire]\n"
      "\t131c  Foobar [Some R7 Rapidfire]\n"
      "\t131d  Foobar [Some R6 Rapidfire]\n"
      "\t1714  BeaverCreek HDMI Audio [Some HD 6500D and 6400G-6600G series]\n"
      "\t\t103c 168b  ProBook 4535s\n"
      "\t3150  RV380/M24 [Loops Some X600]\n"
      "\t\t103c 0934  nx8220\n"
      "\t3151  RV380 GL [IcyhotMV 2400]\n"
      "\t3152  RV370/M22 [Loops Some X300]\n"
      "\t3154  RV380/M24 GL [Loops IcyhotGL V3200]\n"
      "\t3155  RV380 GL [IcyhotMV 2400]\n"
      "\t3171  RV380 GL [IcyhotMV 2400] (Secondary)\n"
      "\t3e50  RV380 [Some X600]\n"
      "\t3e54  RV380 GL [IcyhotGL V3200]\n"
      "\t3e70  RV380 [Some X600] (Secondary)\n"
      "\t4136  RS100 [Loops ABC 320M]\n"
      "ffff  Illegal Vendor ID\n" // Device class information below.
      "\n\n"
      "# List of known device classes, subclasses and programming interfaces\n"
      "\n"
      "# Syntax:\n"
      "# C class	class_name\n"
      "#	subclass	subclass_name  		<-- single tab\n"
      "#		prog-if  prog-if_name  	<-- two tabs\n"
      "\n"
      "C 00  Unclassified device\n"
      "\t00  Non-VGA unclassified device\n"
      "\t01  VGA compatible unclassified device\n"
      "C 01  Mass storage controller\n"
      "\t00  SCSI storage controller\n"
      "\t01  IDE interface\n");

  PciDB parsed_db(raw_db);

  std::string got;

  // Happy Path Tests
  parsed_db.getVendorName("8002", got);
  EXPECT_EQ("Fake Vendor, Inc.", got);

  parsed_db.getModel("8002", "1313", got);
  EXPECT_EQ("Foobar [Some R7 Rapidfire]", got);

  parsed_db.getModel("8002", "1314", got);
  EXPECT_EQ("Wrestler HDMI Audio", got);

  parsed_db.getModel("8002", "4136", got);
  EXPECT_EQ("RS100 [Loops ABC 320M]", got);

  parsed_db.getSubsystemInfo("8002", "1314", "174b", "1001", got);
  EXPECT_EQ("90K Diffusion Mini", got);

  parsed_db.getSubsystemInfo("8002", "3150", "103c", "0934", got);
  EXPECT_EQ("nx8220", got);

  parsed_db.getSubsystemInfo("8002", "1714", "103c", "168b", got);
  EXPECT_EQ("ProBook 4535s", got);

  // Negative Tests
  got = "";

  parsed_db.getVendorName("8086", got);
  EXPECT_EQ("", got);

  parsed_db.getModel("8002", "1388", got);
  EXPECT_EQ("", got);

  parsed_db.getSubsystemInfo("8002", "1714", "103c", "168c", got);
  EXPECT_EQ("", got);

  // Things below 'ffff' should not be retrievable.
  parsed_db.getVendorName("ffff", got);
  EXPECT_EQ("", got);

  parsed_db.getVendorName("C 00", got);
  EXPECT_EQ("", got);

  parsed_db.getVendorName("C 01", got);
  EXPECT_EQ("", got);

  parsed_db.getModel("C 00", "00", got);
  EXPECT_EQ("", got);
}
} // namespace tables
} // namespace osquery
