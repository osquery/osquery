/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/core/tables.h>
#include <osquery/registry/registry_interface.h>
#include <osquery/worker/ipc/linux/linux_table_container_ipc.h>
#include <osquery/worker/logging/logger.h>

namespace osquery {

DECLARE_bool(verbose);
DECLARE_bool(disable_database);

extern template std::set<int> ConstraintList::getAll<int>(
    ConstraintOperator) const;

class WorkerTableContainerTests : public testing::Test {
  void SetUp() override {
    FLAGS_verbose = true;
    FLAGS_minloglevel = google::GLOG_INFO;
    FLAGS_alsologtostderr = true;
    FLAGS_v = 1;
    platformSetup();
    registryAndPluginInit();
  }
};

QueryData genTest1(QueryContext&, Logger&) {
  Row r;
  r["test"] = "Hello";
  return {r};
}

TEST_F(WorkerTableContainerTests, test_ipc_container_connect) {
  PipeChannelFactory factory;

  LinuxTableContainerIPC container_ipc(factory);

  auto status = container_ipc.connectToContainer("test", false, genTest1);
  ASSERT_TRUE(status.ok()) << status.getMessage();

  auto my_pid = getpid();

  QueryContext context;
  context.constraints["pid_with_namespace"].add(
      Constraint(ConstraintOperator::EQUALS, std::to_string(my_pid)));
  UsedColumns columns_used;
  columns_used.emplace("pid_with_namespace");
  context.colsUsed = std::move(columns_used);

  auto constraints =
      context.constraints["pid_with_namespace"].getAll<int>(EQUALS);

  ASSERT_EQ(constraints.size(), 1);

  QueryData results;
  status = container_ipc.retrieveQueryDataFromContainer(context, results);
  ASSERT_TRUE(status.ok()) << status.getMessage();

  ASSERT_EQ(results.size(), 1);
  ASSERT_EQ(results[0].count("test"), 1);
  EXPECT_EQ(results[0]["test"], "Hello");

  container_ipc.stopContainerWorker();
}
} // namespace osquery
