/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <osquery/tables/system/linux/pci_devices.h>

using namespace testing;

namespace osquery {
namespace tables {

class PciDevicesTest : public ::testing::Test {
 protected:
  PciDevicesTest() {}

  static void SetUpTestCase() {
    std::istringstream test_db_stream(
        "# Some Test Comment\n"
        "8002  Fake Vendor, Inc.\n"
        "\t1312  Foobar\n"
        "\t1313  Foobar [Some R7 Rapidfire]\n"
        "\t131b  Wrestler HDMI Audio\n"
        "\t\t174b 1001  90K Diffusion Mini\n"
        "174b  Fake Vendor, LLC.\n"
        "ffff  Illegal Vendor ID\n" // Device class information below.

    );

    pcidb_ = new PciDB(test_db_stream);
  }

  static void TearDownTestCase() {
    delete pcidb_;
    pcidb_ = nullptr;
  }

  static PciDB* pcidb_;
};

PciDB* PciDevicesTest::pcidb_ = nullptr;

TEST_F(PciDevicesTest,
       extract_pci_vendor_model_info_from_pcidb_all_fields_exists) {
  Row expected = {
      {"vendor_id", "0x8002"},
      {"model_id", "0x131b"},
      {"vendor", "Fake Vendor, Inc."},
      {"model", "Wrestler HDMI Audio"},
      {"subsystem_vendor_id", "0x174b"},
      {"subsystem_model_id", "0x1001"},
      {"subsystem_vendor", "Fake Vendor, LLC."},
      {"subsystem_model", "90K Diffusion Mini"},
  };

  Row got;
  auto status = extractVendorModelFromPciDBIfPresent(
      got, "8002:131B", "174B:1001", *PciDevicesTest::pcidb_);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(expected, got);
}

TEST_F(PciDevicesTest,
       extract_pci_vendor_model_info_from_pcidb_missing_subsystem_info) {
  Row expected = {
      {"vendor_id", "0x8002"},
      {"model_id", "0x131b"},
      {"vendor", "Fake Vendor, Inc."},
      {"model", "Wrestler HDMI Audio"},
      {"subsystem_vendor_id", "0x174c"},
      {"subsystem_model_id", "0x1003"},
  };

  Row got;
  auto status = extractVendorModelFromPciDBIfPresent(
      got, "8002:131B", "174C:1003", *PciDevicesTest::pcidb_);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(expected, got);
}

TEST_F(PciDevicesTest,
       extract_pci_vendor_model_info_from_pcidb_missing_all_info) {
  Row expected = {
      {"vendor_id", "0x8005"},
      {"model_id", "0x1311"},
      {"subsystem_vendor_id", "0x174c"},
      {"subsystem_model_id", "0x1003"},
  };

  Row got;
  auto status = extractVendorModelFromPciDBIfPresent(
      got, "8005:1311", "174C:1003", *PciDevicesTest::pcidb_);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(expected, got);
}

TEST_F(PciDevicesTest,
       extract_pci_vendor_model_info_from_pcidb_negative_bad_pci_id) {
  Row got;
  auto status = extractVendorModelFromPciDBIfPresent(
      got, "blahblah", "174C:1003", *PciDevicesTest::pcidb_);
  EXPECT_FALSE(status.ok());
}

TEST_F(PciDevicesTest,
       extract_pci_vendor_model_info_from_pcidb_negative_bad_subsys_id) {
  Row got;
  auto status = extractVendorModelFromPciDBIfPresent(
      got, "8005:1311", "blahblah", *PciDevicesTest::pcidb_);
  EXPECT_FALSE(status.ok());
}

TEST_F(PciDevicesTest,
       extract_pci_vendor_model_info_from_pcidb_negative_3_pci_ids) {
  Row got;
  auto status = extractVendorModelFromPciDBIfPresent(
      got, "8005:1311:1533", "174C:1003", *PciDevicesTest::pcidb_);
  EXPECT_FALSE(status.ok());
}

TEST_F(PciDevicesTest,
       extract_pci_vendor_model_info_from_pcidb_negative_empty_pci_id) {
  Row got;
  auto status = extractVendorModelFromPciDBIfPresent(
      got, "", "174C:1003", *PciDevicesTest::pcidb_);
  EXPECT_FALSE(status.ok());
}

TEST_F(PciDevicesTest,
       extract_pci_vendor_model_info_from_pcidb_negative_3_subsys_ids) {
  Row expected = {
      {"vendor_id", "0x8005"},
      {"model_id", "0x1311"},
  };

  Row got;
  auto status = extractVendorModelFromPciDBIfPresent(
      got, "8005:1311", "174C:1003:1B33", *PciDevicesTest::pcidb_);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(expected, got);
}

TEST_F(PciDevicesTest,
       extract_pci_vendor_model_info_from_pcidb_negative_empty_subsys_ids) {
  Row expected = {
      {"vendor_id", "0x8005"},
      {"model_id", "0x1311"},
  };

  Row got;
  auto status = extractVendorModelFromPciDBIfPresent(
      got, "8005:1311", "", *PciDevicesTest::pcidb_);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(expected, got);
}

TEST_F(PciDevicesTest, extract_pci_class_ids_single_digit_class_id) {
  Row expected = {
      {"pci_class_id", "0x08"},
      {"pci_subclass_id", "0x1c"},
  };

  Row got;
  auto status = extractPCIClassIDAttrs(got, "81C00");
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(expected, got);
}

TEST_F(PciDevicesTest, extract_pci_class_ids_double_digit_class_id) {
  Row expected = {
      {"pci_class_id", "0x1d"},
      {"pci_subclass_id", "0x1c"},
  };

  Row got;
  auto status = extractPCIClassIDAttrs(got, "1D1C00");
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(expected, got);
}

TEST_F(PciDevicesTest, extract_pci_class_ids_negative_bad_length) {
  Row got;
  auto status = extractPCIClassIDAttrs(got, "FDD1D1C00");
  EXPECT_FALSE(status.ok());
}

} // namespace tables
} // namespace osquery
