/*
 *  Copyright (c) 2014-present, Facebook, Inc.
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

#include "osquery/sql/sqlite_util.h"

namespace pt = boost::property_tree;

DECLARE_string(distributed_tls_read_endpoint);
DECLARE_string(distributed_tls_write_endpoint);

namespace osquery {

class DistributedTests : public testing::Test {
 protected:
  void SetUp() {
    TLSServerRunner::start();
    TLSServerRunner::setClientConfig();
    clearNodeKey();

    distributed_tls_read_endpoint_ =
        Flag::getValue("distributed_tls_read_endpoint");
    Flag::updateValue("distributed_tls_read_endpoint", "/distributed_read");

    distributed_tls_write_endpoint_ =
        Flag::getValue("distributed_tls_write_endpoint");
    Flag::updateValue("distributed_tls_write_endpoint", "/distributed_write");

    Registry::setActive("distributed", "tls");
  }

  void TearDown() {
    TLSServerRunner::stop();
    TLSServerRunner::unsetClientConfig();
    clearNodeKey();

    Flag::updateValue("distributed_tls_read_endpoint",
                      distributed_tls_read_endpoint_);
    Flag::updateValue("distributed_tls_write_endpoint",
                      distributed_tls_write_endpoint_);
  }

 protected:
  std::string distributed_tls_read_endpoint_;
  std::string distributed_tls_write_endpoint_;
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
