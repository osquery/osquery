/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/events/linux/bpf_socket_events.h>

#include <netinet/in.h>

namespace osquery {

namespace {

const std::unordered_map<ISystemStateTracker::Event::Type, std::string>
    kEventTypeToLabel = {

        {ISystemStateTracker::Event::Type::Connect, "connect"},
        {ISystemStateTracker::Event::Type::Bind, "bind"},
        {ISystemStateTracker::Event::Type::Listen, "listen"},
        {ISystemStateTracker::Event::Type::Accept, "accept"}};

const std::vector<std::string> kExpectedRowList = {"syscall",
                                                   "ntime",
                                                   "tid",
                                                   "pid",
                                                   "uid",
                                                   "gid",
                                                   "cid",
                                                   "exit_code",
                                                   "probe_error",
                                                   "parent",
                                                   "path",
                                                   "fd",
                                                   "family",
                                                   "type",
                                                   "protocol",
                                                   "local_address",
                                                   "remote_address",
                                                   "local_port",
                                                   "remote_port"};

} // namespace

class BPFSocketEventsTests : public testing::Test {};

TEST_F(BPFSocketEventsTests, event_type) {
  for (const auto& p : kEventTypeToLabel) {
    const auto& event_id = p.first;
    const auto& expected_label = p.second;

    ISystemStateTracker::Event event{};
    event.type = event_id;

    Row row;
    auto succeeded = BPFSocketEventSubscriber::generateRow(row, event);
    ASSERT_TRUE(succeeded);
    ASSERT_EQ(row.size(), kExpectedRowList.size());

    for (const auto& expected_row : kExpectedRowList) {
      ASSERT_EQ(row.count(expected_row), 1U);
    }

    EXPECT_EQ(row.at("syscall"), expected_label);
  }
}

TEST_F(BPFSocketEventsTests, default_values) {
  ISystemStateTracker::Event event{};
  event.type = ISystemStateTracker::Event::Type::Connect;

  Row row;
  auto succeeded = BPFSocketEventSubscriber::generateRow(row, event);
  ASSERT_TRUE(succeeded);
  ASSERT_EQ(row.size(), kExpectedRowList.size());

  for (const auto& expected_row : kExpectedRowList) {
    ASSERT_EQ(row.count(expected_row), 1U);
  }

  EXPECT_TRUE(row.at("fd").empty());
  EXPECT_EQ(row.at("family"), "-1");
  EXPECT_EQ(row.at("type"), "-1");
  EXPECT_EQ(row.at("protocol"), "-1");
  EXPECT_TRUE(row.at("local_address").empty());
  EXPECT_TRUE(row.at("remote_address").empty());
  EXPECT_EQ(row.at("local_port"), "0");
  EXPECT_EQ(row.at("remote_port"), "0");
}

TEST_F(BPFSocketEventsTests, socket_data) {
  ISystemStateTracker::Event event{};
  event.type = ISystemStateTracker::Event::Type::Connect;

  ISystemStateTracker::Event::SocketData socket_data;
  socket_data.domain = AF_INET;
  socket_data.type = SOCK_STREAM;
  socket_data.protocol = 0;
  socket_data.fd = 10;
  socket_data.local_address = "127.0.0.1";
  socket_data.local_port = 5000;
  socket_data.remote_address = "192.168.1.2";
  socket_data.remote_port = 8080;

  event.data = std::move(socket_data);

  Row row;
  auto succeeded = BPFSocketEventSubscriber::generateRow(row, event);
  ASSERT_TRUE(succeeded);
  ASSERT_EQ(row.size(), kExpectedRowList.size());

  for (const auto& expected_row : kExpectedRowList) {
    ASSERT_EQ(row.count(expected_row), 1U);
  }

  EXPECT_EQ(row.at("fd"), "10");
  EXPECT_EQ(row.at("family"), std::to_string(AF_INET));
  EXPECT_EQ(row.at("type"), std::to_string(SOCK_STREAM));
  EXPECT_EQ(row.at("protocol"), "0");
  EXPECT_EQ(row.at("local_address"), "127.0.0.1");
  EXPECT_EQ(row.at("remote_address"), "192.168.1.2");
  EXPECT_EQ(row.at("local_port"), "5000");
  EXPECT_EQ(row.at("remote_port"), "8080");
}

} // namespace osquery
