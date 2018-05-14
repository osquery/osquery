/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <vector>

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/sql.h>

#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/transports/tls.h"
#include "osquery/tests/test_additional_util.h"
#include "osquery/tests/test_util.h"

#include "osquery/remote/enroll/plugins/tls_enroll.h"

namespace pt = boost::property_tree;

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
  // Start a server.
  TLSServerRunner::start();
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
  }
  return status;
}

TEST_F(TLSEnrollTests, test_tls_enroll) {
  auto node_key = getNodeKey("tls");

  JSON response;
  std::string value;

  auto status = testReadRequests(response);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(response.doc().Size(), 1U);

  auto const& obj = response.doc()[0];
  EXPECT_TRUE(obj.IsObject());
  EXPECT_TRUE(obj.HasMember("command"));
  EXPECT_TRUE(obj["command"].IsString());
  value = obj["command"].GetString();
  EXPECT_EQ(value, "enroll");

  EXPECT_TRUE(obj.HasMember("host_identifier"));
  EXPECT_TRUE(obj["host_identifier"].IsString());
  value = obj["host_identifier"].GetString();
  EXPECT_EQ(value, getHostIdentifier());

  // Check that osquery_info exists in the host_details.
  ASSERT_EQ(kEnrollHostDetails.count("osquery_info"), 1U);
  auto osquery_info = SQL::selectAllFrom("osquery_info");
  ASSERT_EQ(osquery_info.size(), 1U);
  ASSERT_EQ(osquery_info[0].count("uuid"), 1U);

  EXPECT_TRUE(obj.HasMember("host_details"));
  EXPECT_TRUE(obj["host_details"].HasMember("osquery_info"));
  EXPECT_TRUE(obj["host_details"]["osquery_info"].HasMember("uuid"));

  EXPECT_TRUE(obj["host_details"]["osquery_info"]["uuid"].IsString());
  value = obj["host_details"]["osquery_info"]["uuid"].GetString();
  EXPECT_EQ(osquery_info[0]["uuid"], value);
}
}
