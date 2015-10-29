/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/distributed.h>
#include <osquery/enroll.h>
#include <osquery/sql.h>

#include "osquery/core/test_util.h"
#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/transports/tls.h"

#include "osquery/sql/sqlite_util.h"

namespace pt = boost::property_tree;

DECLARE_string(distributed_tls_read_endpoint);
DECLARE_string(distributed_tls_write_endpoint);
DECLARE_string(enroll_tls_endpoint);

namespace osquery {

class DistributedTests : public testing::Test {
 protected:
  void SetUp() {
    TLSServerRunner::start();
    clearNodeKey();

    tls_hostname_ = Flag::getValue("tls_hostname");
    Flag::updateValue("tls_hostname", "localhost:" + TLSServerRunner::port());

    enroll_tls_endpoint_ = Flag::getValue("enroll_tls_endpoint");
    Flag::updateValue("enroll_tls_endpoint", "/enroll");

    distributed_tls_read_endpoint_ =
        Flag::getValue("distributed_tls_read_endpoint");
    Flag::updateValue("distributed_tls_read_endpoint", "/distributed_read");

    distributed_tls_write_endpoint_ =
        Flag::getValue("distributed_tls_write_endpoint");
    Flag::updateValue("distributed_tls_write_endpoint", "/distributed_write");

    tls_server_certs_ = Flag::getValue("tls_server_certs");
    Flag::updateValue("tls_server_certs",
                      kTestDataPath + "/test_server_ca.pem");

    enroll_secret_path_ = Flag::getValue("enroll_secret_path");
    Flag::updateValue("enroll_secret_path",
                      kTestDataPath + "/test_enroll_secret.txt");

    Registry::setActive("distributed", "tls");
  }

  void TearDown() {
    TLSServerRunner::stop();
    clearNodeKey();
    Flag::updateValue("tls_hostname", tls_hostname_);
    Flag::updateValue("enroll_tls_endpoint", enroll_tls_endpoint_);
    Flag::updateValue("distributed_tls_read_endpoint",
                      distributed_tls_read_endpoint_);
    Flag::updateValue("distributed_tls_write_endpoint",
                      distributed_tls_write_endpoint_);
    Flag::updateValue("tls_server_certs", tls_server_certs_);
    Flag::updateValue("enroll_secret_path", enroll_secret_path_);
  }

  std::string tls_hostname_;
  std::string enroll_tls_endpoint_;
  std::string distributed_tls_read_endpoint_;
  std::string distributed_tls_write_endpoint_;
  std::string tls_server_certs_;
  std::string enroll_secret_path_;
};

TEST_F(DistributedTests, test_workflow) {
  auto dist = Distributed();
  auto s = dist.pullUpdates();
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  EXPECT_EQ(dist.getPendingQueryCount(), 2U);
  EXPECT_EQ(dist.results_.size(), 0U);
  s = dist.runQueries();
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  EXPECT_EQ(dist.getPendingQueryCount(), 0U);
  EXPECT_EQ(dist.results_.size(), 2U);
}
}
