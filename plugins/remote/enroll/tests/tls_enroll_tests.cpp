/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// clang-format off
// Keep it on top of all other includes to fix double include WinSock.h header file
// which is windows specific boost build problem
#include "osquery/remote/transports/tls.h"
// clang-format on

#include <gtest/gtest.h>

#include <vector>

#include <osquery/config/config.h>
#include <osquery/database/database.h>
#include <osquery/core/flags.h>
#include <osquery/sql/sql.h>
#include <osquery/core/system.h>
#include <osquery/registry/registry_factory.h>

#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include <osquery/remote/tests/test_utils.h>
#include "osquery/tests/test_util.h"

#include <plugins/remote/enroll/tls_enroll.h>

namespace osquery {

DECLARE_string(tls_hostname);

class TLSEnrollTests : public testing::Test {
 protected:
  void SetUp() override;
  void TearDown() override;

  Status testReadRequests(JSON& response_tree);

 private:
  std::string test_read_uri_;
};

void TLSEnrollTests::SetUp() {
  platformSetup();
  registryAndPluginInit();
  initDatabasePluginForTesting();

  // Start a server.
  ASSERT_TRUE(TLSServerRunner::start());
  TLSServerRunner::setClientConfig();
  clearNodeKey();

  test_read_uri_ =
      "https://" + Flag::getValue("tls_hostname") + "/test_read_requests";
}

void TLSEnrollTests::TearDown() {
  // Stop the server.
  TLSServerRunner::unsetClientConfig();
  TLSServerRunner::stop();
}

Status TLSEnrollTests::testReadRequests(JSON& response_tree) {
  Request<TLSTransport, JSONSerializer> request_(test_read_uri_);
  request_.setOption("hostname", Flag::getValue("tls_hostname"));
  auto status = request_.call(JSON());
  if (status.ok()) {
    status = request_.getResponse(response_tree);
  } else {
    LOG(ERROR) << status.getMessage();
  }
  return status;
}

TEST_F(TLSEnrollTests, test_tls_enroll) {
  auto node_key = getNodeKey("tls");

  ASSERT_FALSE(node_key.empty());

  JSON response;
  std::string value;

  auto status = testReadRequests(response);
  ASSERT_TRUE(status.ok());
  ASSERT_TRUE(response.doc().IsArray());
  ASSERT_EQ(response.doc().Size(), 1U);

  auto const& obj = response.doc()[0];
  ASSERT_TRUE(obj.IsObject());

  ASSERT_TRUE(obj.HasMember("command"));
  ASSERT_TRUE(obj["command"].IsString());
  value = obj["command"].GetString();
  EXPECT_EQ(value, "enroll");

  ASSERT_TRUE(obj.HasMember("host_identifier"));
  ASSERT_TRUE(obj["host_identifier"].IsString());
  value = obj["host_identifier"].GetString();
  EXPECT_EQ(value, getHostIdentifier());

  ASSERT_EQ(kEnrollHostDetails.count("osquery_info"), 1U);
  auto osquery_info = SQL::selectAllFrom("osquery_info");
  ASSERT_EQ(osquery_info.size(), 1U);
  ASSERT_EQ(osquery_info[0].count("uuid"), 1U);
  ASSERT_TRUE(obj.HasMember("host_details"));
  ASSERT_TRUE(obj["host_details"].HasMember("osquery_info"));
  ASSERT_TRUE(obj["host_details"]["osquery_info"].HasMember("uuid"));
  ASSERT_TRUE(obj["host_details"]["osquery_info"]["uuid"].IsString());
  value = obj["host_details"]["osquery_info"]["uuid"].GetString();
  EXPECT_EQ(osquery_info[0]["uuid"], value);
}
} // namespace osquery
