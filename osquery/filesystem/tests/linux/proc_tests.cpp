/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <osquery/filesystem/filesystem.h>
#include <osquery/filesystem/linux/proc.h>

#include <fcntl.h>
#include <unistd.h>

#include <string>

#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

#ifndef ETH_P_LLDP
#define ETH_P_LLDP 0x88cc
#endif

namespace fs = boost::filesystem;

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

TEST_F(LinuxProc, test_user_namespace_parser) {
  auto unique_path = fs::temp_directory_path() /
                     fs::unique_path("osquery.tests.user_ns_parser.%%%%.%%%%");

  auto temp_path = unique_path.native();

  boost::system::error_code error_code;
  EXPECT_EQ(fs::create_directory(temp_path, error_code), true);

  auto symlink_path = temp_path + "/namespace";
  EXPECT_EQ(symlink("namespace:[112233]", symlink_path.data()), 0);

  ino_t namespace_inode;
  auto status = procGetNamespaceInode(namespace_inode, "namespace", temp_path);
  EXPECT_TRUE(status.ok());

  removePath(temp_path);
  EXPECT_EQ(namespace_inode, static_cast<ino_t>(112233));
}

// Independent reference reader (raw read() to EOF), to compare against
// readFile without sharing its buffer-growth logic.
std::string rawReadAll(const std::string& path) {
  int fd = ::open(path.c_str(), O_RDONLY);
  std::string out;
  if (fd < 0) {
    return out;
  }
  char buf[4096];
  ssize_t n;
  while ((n = ::read(fd, buf, sizeof(buf))) > 0) {
    out.append(buf, static_cast<std::size_t>(n));
  }
  ::close(fd);
  return out;
}

// readFile's unknown-size path (buffer grown block by block) is only reached by
// special files, which report size 0 -- /proc entries are the real-world case.
// cmdline is stable and smaller than one block: exercises the short-read path
// (grow never triggers) and must return the complete content.
TEST_F(LinuxProc, readFileReadsShortProcFileCompletely) {
  std::string content;
  ASSERT_TRUE(readFile("/proc/self/cmdline", content).ok());
  EXPECT_FALSE(content.empty());
  EXPECT_EQ(content, rawReadAll("/proc/self/cmdline"));
}

// maps is typically larger than one block, exercising the grow-when-full and
// bounded-read logic. It can shift if mappings change, so compare against a
// reference read and retry a few times to get a consistent snapshot.
TEST_F(LinuxProc, readFileReadsMultiBlockProcFileCompletely) {
  std::string content;
  bool consistent = false;
  for (int attempt = 0; attempt < 5 && !consistent; ++attempt) {
    content.clear();
    ASSERT_TRUE(readFile("/proc/self/maps", content).ok());
    consistent = (content == rawReadAll("/proc/self/maps"));
  }
  ASSERT_TRUE(consistent) << "/proc/self/maps kept changing between reads";
  EXPECT_FALSE(content.empty());
}

} // namespace
} // namespace osquery
