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
#include <osquery/sql.h>

#include "osquery/core/test_util.h"
#include "osquery/remote/requests.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/transports/tls.h"

#include "osquery/sql/sqlite_util.h"

namespace pt = boost::property_tree;

namespace osquery {

class TestDistributedPlugin : public DistributedPlugin {
 public:
  Status setUp() {
    TLSServerRunner::start();
    host = "https://localhost:" + TLSServerRunner::port();
    return Status(0, "OK");
  }

  void tearDown() { TLSServerRunner::stop(); }

  Status getQueries(std::string& json) {
    auto t = std::make_shared<TLSTransport>();
    t->disableVerifyPeer();
    auto url = host + "/distributed_read";
    auto r = Request<TLSTransport, JSONSerializer>(url, t);

    pt::ptree params;
    params.put<std::string>("node_key", "this_is_a_node_secret");
    auto s = r.call(params);
    if (!s.ok()) {
      throw std::runtime_error(s.toString());
    }

    pt::ptree recv;
    s = r.getResponse(recv);
    if (!s.ok()) {
      throw std::runtime_error(s.toString());
    }

    auto serial = JSONSerializer();
    return serial.serialize(recv, json);
  }

  Status writeResults(const std::string& json) {
    pt::ptree tree;
    std::stringstream ss(json);
    pt::read_json(ss, tree);

    auto& queries = tree.get_child("queries");
    for (const auto& result : queries) {
      if (result.first.empty()) {
        throw std::runtime_error("result ID is empty");
      }

      QueryData qd;
      auto s = deserializeQueryData(result.second, qd);
      if (!s.ok()) {
        throw std::runtime_error(s.toString());
      }
      writeCount++;
    }

    auto t = std::make_shared<TLSTransport>();
    t->disableVerifyPeer();
    auto url = host + "/distributed_write";
    auto r = Request<TLSTransport, JSONSerializer>(url, t);

    tree.put<std::string>("node_key", "this_is_a_node_secret");
    auto s = r.call(tree);
    if (!s.ok()) {
      throw std::runtime_error(s.toString());
    }

    pt::ptree recv;
    s = r.getResponse(recv);
    if (!s.ok()) {
      throw std::runtime_error(s.toString());
    }

    return Status(0, "OK");
  }

  int writeCount;
  std::string host;
};

class DistributedTests : public testing::Test {};

TEST_F(DistributedTests, test_workflow) {
  Registry::add<TestDistributedPlugin>("distributed", "test");
  Registry::setActive("distributed", "test");

  auto dist = Distributed();
  auto s = dist.pullUpdates();
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");

  EXPECT_EQ(dist.getPendingQueryCount(), 2);
  EXPECT_EQ(dist.results_.size(), 0);
  s = dist.runQueries();
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(dist.getPendingQueryCount(), 0);
  EXPECT_EQ(dist.results_.size(), 2);

  const auto& plugin = std::dynamic_pointer_cast<TestDistributedPlugin>(
      Registry::get("distributed", "test"));
  EXPECT_EQ(plugin->writeCount, 2);
}
}
