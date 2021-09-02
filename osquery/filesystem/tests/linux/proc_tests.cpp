/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/filesystem/linux/proc.h>

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

#ifndef ETH_P_LLDP
#define ETH_P_LLDP 0x88cc
#endif

namespace osquery {
namespace {
class LinuxProc : public testing::Test {};

TEST_F(LinuxProc, testProcGetSocketListPacketValidInput) {
  Status status;
  SocketInfoList socket_list;

  int expected_socket_index;
  SocketInfoList expected_sockets = {
      {"154955523", 42, AF_PACKET, ETH_P_ALL, "", 0, "", 0, "", "NONE"},
      {"154955524", 42, AF_PACKET, ETH_P_LLDP, "", 0, "", 0, "", "NONE"}};

  std::string test_input =
      "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n"
      "000000007cb3dfdb 3      3    0003   0     1 113784 0      154955523\n"
      "000000003f7450c6 3      3    88cc   0     1 0      0      154955524";

  status = procGetSocketListPacket(AF_PACKET, 0, 42, test_input, socket_list);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(2, socket_list.size());

  for (uint index = 0; index < socket_list.size(); ++index) {
    EXPECT_EQ(expected_sockets[index].family, socket_list[index].family);
    EXPECT_EQ(expected_sockets[index].protocol, socket_list[index].protocol);
    EXPECT_EQ(expected_sockets[index].socket, socket_list[index].socket);
    EXPECT_EQ(expected_sockets[index].state, socket_list[index].state);
  };

  // Reset the list for filter by protocol test (filtering with ETH_P_LLDP)
  socket_list.clear();

  status = procGetSocketListPacket(
      AF_PACKET, ETH_P_LLDP, 42, test_input, socket_list);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(1, socket_list.size());

  // This test is returning the 2nd expected result entry.
  expected_socket_index = 1;
  EXPECT_EQ(expected_sockets[expected_socket_index].family,
            socket_list[0].family);
  EXPECT_EQ(expected_sockets[expected_socket_index].protocol,
            socket_list[0].protocol);
  EXPECT_EQ(expected_sockets[expected_socket_index].socket,
            socket_list[0].socket);
  EXPECT_EQ(expected_sockets[expected_socket_index].state,
            socket_list[0].state);

  // Reset the list for filter by protocol test (filtering with ETH_P_ALL)
  socket_list.clear();

  status = procGetSocketListPacket(
      AF_PACKET, ETH_P_ALL, 42, test_input, socket_list);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(1, socket_list.size());

  // This test is returning the 1st expected result entry.
  expected_socket_index = 0;
  EXPECT_EQ(expected_sockets[expected_socket_index].family,
            socket_list[0].family);
  EXPECT_EQ(expected_sockets[expected_socket_index].protocol,
            socket_list[0].protocol);
  EXPECT_EQ(expected_sockets[expected_socket_index].socket,
            socket_list[0].socket);
  EXPECT_EQ(expected_sockets[expected_socket_index].state,
            socket_list[0].state);
}

TEST_F(LinuxProc, testProcGetSocketListPacketValidInvalidHeader) {
  Status status;
  SocketInfoList socket_list;

  std::string test_input =
      "invalid_sk               RefCnt Type Proto  Iface R Rmem   User"
      "   Inode\n"
      "000000007cb3dfdb 3      3    0003   0     1 113784 0      154955523\n"
      "000000003f7450c6 3      3    88cc   0     1 0      0      154955524";

  status = procGetSocketListPacket(AF_PACKET, 0, 42, test_input, socket_list);

  EXPECT_FALSE(status.ok());
  EXPECT_EQ(0, socket_list.size());
}

TEST_F(LinuxProc, testProcGetSocketListPacketValidInvalidContent) {
  Status status;
  SocketInfoList socket_list;

  std::string test_input =
      "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n"
      "000000007cb3dfdb 3      3    0003   0     1 113784 0      154955523\n"
      "000000003f7450c6 3      3    88";

  status = procGetSocketListPacket(AF_PACKET, 0, 42, test_input, socket_list);

  // Only consider parsed valid/entries.
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(1, socket_list.size());

  EXPECT_EQ(AF_PACKET, socket_list[0].family);
  EXPECT_EQ(ETH_P_ALL, socket_list[0].protocol);
  EXPECT_EQ("154955523", socket_list[0].socket);
  EXPECT_EQ("NONE", socket_list[0].state);
}

} // namespace
} // namespace osquery