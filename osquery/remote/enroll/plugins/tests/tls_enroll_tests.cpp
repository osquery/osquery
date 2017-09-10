/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <vector>

#include <boost/property_tree/ptree.hpp>

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

  Status testReadRequests(pt::ptree& response_tree);

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

Status TLSEnrollTests::testReadRequests(pt::ptree& response_tree) {
  auto request_ = Request<TLSTransport, JSONSerializer>(test_read_uri_);
  request_.setOption("hostname", Flag::getValue("tls_hostname"));
  auto status = request_.call(pt::ptree());
  if (status.ok()) {
    status = request_.getResponse(response_tree);
  }
  return status;
}

TEST_F(TLSEnrollTests, test_tls_enroll) {
  auto node_key = getNodeKey("tls");

  pt::ptree response;
  auto status = testReadRequests(response);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(response.size(), 1U);

  auto value = response.get<std::string>(".command");
  EXPECT_EQ(value, "enroll");

  value = response.get<std::string>(".host_identifier");
  EXPECT_EQ(value, getHostIdentifier());

  // Check that osquery_info exists in the host_details.
  ASSERT_EQ(kEnrollHostDetails.count("osquery_info"), 1U);
  auto osquery_info = SQL::selectAllFrom("osquery_info");
  ASSERT_EQ(osquery_info.size(), 1U);
  ASSERT_EQ(osquery_info[0].count("uuid"), 1U);

  value = response.get<std::string>(".host_details.osquery_info.uuid");
  EXPECT_EQ(osquery_info[0]["uuid"], value);
}
}
