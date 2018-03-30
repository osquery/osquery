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

#include <osquery/logger.h>
#include <osquery/sql.h>

#include "osquery/tests/test_additional_util.h"
#include "osquery/tests/test_util.h"

#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace {
const int kNamespaceTestPort = 27960;

// It is easier to allocate these structures here instead of inside the
// new entry point (which may cause stack issues)
struct sockaddr_in server_addr = {};
struct sockaddr_in client_addr = {};

// The new entry point used by the listening_ports_table test; this
// code just listens for a new client and terminates after a connection
// has been received
int NetNamespaceTests_CloneEntryPoint(void*) {
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(kNamespaceTestPort);

  auto server_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (server_socket == -1) {
    std::cerr << "Failed to create the socket\n";
    return 1;
  }

  if (bind(server_socket,
           reinterpret_cast<struct sockaddr*>(&server_addr),
           sizeof(server_addr)) != 0) {
    std::cerr << "bind() has failed\n";
    return 1;
  }

  if (listen(server_socket, 1) != 0) {
    std::cerr << "listen() has failed\n";
    return 1;
  }

  socklen_t client_addr_size = sizeof(client_addr);
  auto client_socket = accept(server_socket,
                              reinterpret_cast<struct sockaddr*>(&client_addr),
                              &client_addr_size);
  if (client_socket == -1) {
    std::cerr << "accept() has failed\n";
    return 1;
  }

  close(client_socket);
  close(server_socket);

  return 0;
}
} // namespace

namespace osquery {
namespace tables {
class NetNamespaceTests : public testing::Test {};

TEST_F(NetNamespaceTests, listening_ports_table) {
  // Get the current net namespace
  std::string net_path = "/proc/" + std::to_string(getpid()) + "/ns/net";

  char current_net_namespace[PATH_MAX] = {};
  if (readlink(net_path.data(), current_net_namespace, PATH_MAX - 1) == -1) {
    std::cerr << "Failed to acquire the current net namespace. Are namespaces "
                 "enabled? Skipping this test...";
    return;
  }

  // Clone the process while also creating a new net namespace
  std::uint8_t new_stack[4096U];
  auto new_stack_ptr = new_stack + sizeof(new_stack) - 1U;

  auto child_id =
      clone(NetNamespaceTests_CloneEntryPoint, new_stack_ptr, CLONE_NEWNET, 0);
  EXPECT_NE(child_id, -1);
  if (child_id == -1) {
    std::cerr << "clone() has failed; root privileges are required to create a "
                 "new namespace\n";
    return;
  }

  sleep(1);

  // Make sure the child process is running on a different net namespace
  net_path = "/proc/" + std::to_string(child_id) + "/ns/net";

  char child_net_namespace[PATH_MAX] = {};
  auto readlink_err =
      readlink(net_path.data(), child_net_namespace, PATH_MAX - 1);
  EXPECT_NE(readlink_err, -1);
  if (readlink_err == -1) {
    std::cerr
        << "Failed to acquire the child net namespace (it may have crashed)\n";
    kill(child_id, SIGKILL);
    return;
  }

  // Convert to std::string so that glog can correctly print the contents
  EXPECT_NE(std::string(current_net_namespace),
            std::string(child_net_namespace));

  // Make sure that the listening_ports table (which internally queries
  // process_open_sockets) has picked up our port
  auto expected_pid = std::to_string(child_id);
  auto expected_port = std::to_string(kNamespaceTestPort);

  auto results = SQL::selectAllFrom("listening_ports");

  auto kill_err = kill(child_id, SIGKILL);
  EXPECT_NE(kill_err, -1);
  if (kill_err == -1) {
    std::cerr
        << "The child process could not be killed (it may have crashed)\n";
    return;
  }

  // clang-format off
  auto it = std::find_if(
    results.begin(),
    results.end(),

    [expected_pid, expected_port](const Row &row) -> bool {
      // Depending on the table implementation, we may not have
      // all fields populated when programmatically querying a table 
      auto port_it = row.find("port");
      if (port_it == row.end()) {
        return false;
      }

      const auto &port = port_it->second;
      if (port.empty() || port == "0") {
        return false;
      }

      auto pid_it = row.find("pid");
      if (pid_it == row.end()) {
        return false;
      }

      const auto &pid = pid_it->second;
      if (pid.empty() || pid == "0") {
        return false;
      }

      return (pid == expected_pid && port == expected_port);
    }
  );
  // clang-format on

  EXPECT_TRUE(it != results.end());
}
} // namespace tables
} // namespace osquery
