/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/registry.h>
#include <osquery/system.h>
#include <osquery/tables.h>

#include <osquery/tables/system/windows/certificates.h>

namespace osquery {

DECLARE_bool(disable_database);

namespace tables {

class CertificatesTablesTest : public testing::Test {
 protected:
  void SetUp() override {
    Initializer::platformSetup();
    registryAndPluginInit();

    FLAGS_disable_database = true;
    DatabasePlugin::setAllowOpen(true);
    DatabasePlugin::initPlugin();
  }
};

TEST_F(CertificatesTablesTest, test_only_store_non_special_case) {
  LPCWSTR input = L"My";
  std::string storeLocation = "CurrentService";
  std::string serviceNameOrUserId, sid, storeName;
  ServiceNameMap cache;

  parseSystemStoreString(
      input, storeLocation, cache, serviceNameOrUserId, sid, storeName);

  EXPECT_EQ(serviceNameOrUserId, "");
  EXPECT_EQ(sid, "");
  EXPECT_EQ(storeName, "Personal");
}

TEST_F(CertificatesTablesTest, test_service) {
  LPCWSTR input = L"RpcSs\\My"; // This service should always exist
  std::string storeLocation = "Services";
  std::string serviceNameOrUserId, sid, storeName;
  ServiceNameMap cache;

  parseSystemStoreString(
      input, storeLocation, cache, serviceNameOrUserId, sid, storeName);

  EXPECT_EQ(serviceNameOrUserId, "RpcSs");
  EXPECT_EQ(sid, kNetworkService);
  EXPECT_EQ(storeName, "Personal");
}

TEST_F(CertificatesTablesTest, test_user_default) {
  LPCWSTR input = L".DEFAULT\\My";
  std::string storeLocation = "Users";
  std::string serviceNameOrUserId, sid, storeName;
  ServiceNameMap cache;

  parseSystemStoreString(
      input, storeLocation, cache, serviceNameOrUserId, sid, storeName);

  EXPECT_EQ(serviceNameOrUserId, ".DEFAULT");
  EXPECT_EQ(sid, kLocalSystem);
  EXPECT_EQ(storeName, "Personal");
}

TEST_F(CertificatesTablesTest, test_user_sid) {
  LPCWSTR input = L"S-1-5-18\\Root";
  std::string storeLocation = "Users";
  std::string serviceNameOrUserId, sid, storeName;
  ServiceNameMap cache;

  parseSystemStoreString(
      input, storeLocation, cache, serviceNameOrUserId, sid, storeName);

  EXPECT_EQ(serviceNameOrUserId, "S-1-5-18");
  EXPECT_EQ(sid, kLocalSystem);
  EXPECT_EQ(storeName, "Trusted Root Certification Authorities");
}

TEST_F(CertificatesTablesTest, test_user_classes) {
  LPCWSTR input =
      L"S-1-5-21-2821152761-3909955410-1545212275-1001_Classes\\Root";
  std::string storeLocation = "Users";
  std::string serviceNameOrUserId, sid, storeName;
  ServiceNameMap cache;

  parseSystemStoreString(
      input, storeLocation, cache, serviceNameOrUserId, sid, storeName);

  EXPECT_EQ(serviceNameOrUserId,
            "S-1-5-21-2821152761-3909955410-1545212275-1001_Classes");
  EXPECT_EQ(sid, "S-1-5-21-2821152761-3909955410-1545212275-1001");
  EXPECT_EQ(storeName, "Trusted Root Certification Authorities");
}

} // namespace tables
} // namespace osquery