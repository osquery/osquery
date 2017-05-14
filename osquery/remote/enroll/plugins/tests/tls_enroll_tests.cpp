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
#include <osquery/sql.h>
#include <osquery/system.h>

#include "osquery/core/conversions.h"
#include "osquery/core/json.h"
#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/transports/tls.h"
#include "osquery/remote/utility.h"
#include "osquery/tests/test_additional_util.h"
#include "osquery/tests/test_util.h"

#include "osquery/remote/enroll/plugins/tls.h"

namespace pt = boost::property_tree;

namespace osquery {

DECLARE_string(tls_hostname);

class TLSEnrollTests : public testing::Test {
 protected:
  virtual void SetUp() {
    // Start a server.
    TLSServerRunner::start();
    TLSServerRunner::setClientConfig();
    clearNodeKey();

    test_read_uri_ =
        "https://" + Flag::getValue("tls_hostname") + "/test_read_requests";
  }

  virtual void TearDown() {
    // Stop the server.
    TLSServerRunner::unsetClientConfig();
    TLSServerRunner::stop();
  }

  Status testReadRequests(pt::ptree& response_tree) {
    auto request_ = Request<TLSTransport, JSONSerializer>(test_read_uri_);
    request_.setOption("hostname", Flag::getValue("tls_hostname"));
    auto status = request_.call(pt::ptree());
    if (status.ok()) {
      status = request_.getResponse(response_tree);
    }
    return status;
  }

 private:
  std::string test_read_uri_;
};

bool verifyResultTree(const pt::ptree& result_tree, const QueryData& rows) {
  bool matching_row_found = false;
  std::string db_value;
  for (const pt::ptree::value_type& result_pair : result_tree) {
    for (const auto& row : rows) {
      matching_row_found = true;
      for (const auto& column : row) {
        db_value = result_pair.second.get<std::string>(column.first);
        if (strcmp(db_value.c_str(), column.second.c_str()) != 0) {
          // if this row doesn't match, stop comparing columns
          matching_row_found = false;
          break;
        }
      }
      // If this row matches, we found what we are looking for. Stop looking.
      if (matching_row_found) {
        break;
      }
    }
    // If an item in result_tree doesn't match any row, stop comparing more
    // items.
    if (!matching_row_found) {
      break;
    }
  } // end for every item in the result_tree

  return matching_row_found;
}

TEST_F(TLSEnrollTests, test_tls_enroll_basic) {
  // Default case -- make enroll plugin request a nodekey
  auto node_key = getNodeKey("tls");

  // Verify that the plugin made a enroll call with the basic metadata only
  pt::ptree response_tree;

  auto status = testReadRequests(response_tree);
  ASSERT_TRUE(status.ok());

  // There should only be one command that should have been posted - an enroll
  EXPECT_EQ(response_tree.size(), 1UL);

  // Verify that it is indeed Enroll and has the correct host_identifier
  std::string db_value = response_tree.get<std::string>(".command");
  EXPECT_STREQ(db_value.c_str(), "enroll");

  db_value = response_tree.get<std::string>(".host_identifier");
  EXPECT_STREQ(db_value.c_str(), getHostIdentifier().c_str());
}

TEST_F(TLSEnrollTests, test_tls_enroll_single_query) {
  Flag::updateValue("enroll_tls_metadata",
                    "osquery_info:select * from osquery_info;");

  auto node_key = getNodeKey("tls");

  // Verify that the plugin made a enroll call with the basic metadata only
  pt::ptree response_tree;

  auto status = testReadRequests(response_tree);
  ASSERT_TRUE(status.ok());

  // There should only be one command that should have been posted - an enroll
  EXPECT_EQ(response_tree.size(), 1UL);

  // Verify that it is indeed Enroll and has the correct host_identifier
  std::string db_value = response_tree.get<std::string>(".command");
  EXPECT_STREQ(db_value.c_str(), "enroll");

  db_value = response_tree.get<std::string>(".host_identifier");
  EXPECT_STREQ(db_value.c_str(), getHostIdentifier().c_str());

  auto osquery_info_tree = response_tree.get_child(".osquery_info");
  ASSERT_EQ(osquery_info_tree.size(), 1UL);

  pt::write_json(std::cerr, osquery_info_tree);

  auto sql_table = SQL("select * from osquery_info");
  ASSERT_TRUE(sql_table.ok());
  auto rows = sql_table.rows();
  ASSERT_EQ(rows.size(), 1UL);

  EXPECT_TRUE(verifyResultTree(osquery_info_tree, rows));
}

TEST_F(TLSEnrollTests, test_tls_enroll_multiple_query) {
  Flag::updateValue("enroll_tls_metadata",
                    "osquery_info:select * from osquery_info;"
                    "os_version:select * from os_version;"
                    "osquery_flags:select * from osquery_flags;");

  auto node_key = getNodeKey("tls");

  // Verify that the plugin made a enroll call with the basic metadata only
  pt::ptree response_tree;

  auto status = testReadRequests(response_tree);
  ASSERT_TRUE(status.ok());

  // There should only be one command that should have been posted - an enroll
  EXPECT_EQ(response_tree.size(), 1UL);

  pt::write_json(std::cerr, response_tree);

  // Verify that it is indeed Enroll and has the correct host_identifier
  std::string db_value = response_tree.get<std::string>(".command");
  EXPECT_STREQ(db_value.c_str(), "enroll");

  db_value = response_tree.get<std::string>(".host_identifier");
  EXPECT_STREQ(db_value.c_str(), getHostIdentifier().c_str());

  auto osquery_info_tree = response_tree.get_child(".osquery_info");
  ASSERT_EQ(osquery_info_tree.size(), 1UL);

  auto sql_table = SQL("select * from osquery_info");
  ASSERT_TRUE(sql_table.ok());
  auto rows = sql_table.rows();
  ASSERT_EQ(rows.size(), 1UL);

  EXPECT_TRUE(verifyResultTree(osquery_info_tree, rows));

  auto os_version_tree = response_tree.get_child(".os_version");
  ASSERT_EQ(os_version_tree.size(), 1UL);

  sql_table = SQL("select * from os_version");
  ASSERT_TRUE(sql_table.ok());
  rows = sql_table.rows();
  ASSERT_EQ(rows.size(), 1UL);

  EXPECT_TRUE(verifyResultTree(os_version_tree, rows));

  auto osquery_flags_tree = response_tree.get_child(".osquery_flags");
  ASSERT_GE(osquery_flags_tree.size(), 1UL);

  sql_table = SQL("select * from osquery_flags");
  ASSERT_TRUE(sql_table.ok());
  rows = sql_table.rows();
  ASSERT_GE(rows.size(), 1UL);

  EXPECT_TRUE(verifyResultTree(osquery_flags_tree, rows));
}
}
