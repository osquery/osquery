/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <asm/unistd.h>

#include <gtest/gtest.h>

#include <osquery/events/linux/auditdnetlink.h>
#include <osquery/events/linux/auditeventpublisher.h>
#include <osquery/tables/events/linux/socket_events.h>

namespace osquery {

namespace {

extern const AuditEvent kSucceededConnectEvent;
extern const AuditEvent kSucceededBindEvent;
extern const AuditEvent kSucceededAccept4Event;

} // namespace

class SocketEventsTableTests : public testing::Test {};

TEST_F(SocketEventsTableTests, test_parse_sock_addr) {
  Row r;
  std::string msg = "02001F907F0000010000000000000000";
  bool unix_socket;
  SocketEventSubscriber::parseSockAddr(msg, r, unix_socket);
  ASSERT_FALSE(r["remote_address"].empty());
  EXPECT_EQ(r["remote_address"], "127.0.0.1");
  EXPECT_EQ(r["family"], "2");
  EXPECT_EQ(r["remote_port"], "8080");

  Row r3;
  std::string msg2 = "0A001F9100000000FE80000000000000022522FFFEB03684000000";
  SocketEventSubscriber::parseSockAddr(msg2, r3, unix_socket);
  ASSERT_FALSE(r3["remote_address"].empty());
  EXPECT_EQ(r3["remote_address"], "fe80:0000:0000:0000:0225:22ff:feb0:3684");
  EXPECT_EQ(r3["remote_port"], "8081");

  Row r4;
  std::string msg3 = "01002F746D702F6F7371756572792E656D0000";
  SocketEventSubscriber::parseSockAddr(msg3, r4, unix_socket);
  ASSERT_FALSE(r4["socket"].empty());
  EXPECT_EQ(r4["socket"], "/tmp/osquery.em");

  msg3 = "0100002F746D702F6F7371756572792E656D";
  SocketEventSubscriber::parseSockAddr(msg3, r4, unix_socket);
  EXPECT_EQ(r4["socket"], "/tmp/osquery.em");
}

TEST_F(SocketEventsTableTests, succeeded_blocking_connect_syscall) {
  const bool kAllowUnixSocketEvents{false};
  const bool kAllowAcceptEvents{false};
  const bool kAllowNullAcceptEvents{false};

  for (const auto& allow_failed_events : {true, false}) {
    std::vector<Row> emitted_row_list;
    auto status = SocketEventSubscriber::ProcessEvents(emitted_row_list,
                                                       {kSucceededConnectEvent},
                                                       allow_failed_events,
                                                       kAllowUnixSocketEvents,
                                                       kAllowAcceptEvents,
                                                       kAllowNullAcceptEvents);

    EXPECT_TRUE(status.ok());
    ASSERT_EQ(emitted_row_list.size(), 1);
    EXPECT_EQ(emitted_row_list.front()["success"], "1");
    EXPECT_EQ(emitted_row_list.front()["status"], "succeeded");
  }
}

TEST_F(SocketEventsTableTests, failed_blocking_connect_syscall) {
  const bool kAllowUnixSocketEvents{false};
  const bool kAllowAcceptEvents{false};
  const bool kAllowNullAcceptEvents{false};

  auto audit_event = kSucceededConnectEvent;
  auto& syscall_data = boost::get<SyscallAuditEventData>(audit_event.data);

  syscall_data.succeeded = false;
  audit_event.record_list.at(0).fields["success"] = "no";
  audit_event.record_list.at(0).fields["exit"] = std::to_string(-EBADF);

  for (const auto& allow_failed_events : {true, false}) {
    std::vector<Row> emitted_row_list;
    auto status = SocketEventSubscriber::ProcessEvents(emitted_row_list,
                                                       {audit_event},
                                                       allow_failed_events,
                                                       kAllowUnixSocketEvents,
                                                       kAllowAcceptEvents,
                                                       kAllowNullAcceptEvents);

    EXPECT_TRUE(status.ok());

    if (allow_failed_events) {
      ASSERT_EQ(emitted_row_list.size(), 1);
      EXPECT_EQ(emitted_row_list.front()["success"], "0");
      EXPECT_EQ(emitted_row_list.front()["status"], "failed");

    } else {
      EXPECT_TRUE(emitted_row_list.empty());
    }
  }
}

TEST_F(SocketEventsTableTests, succeeded_non_blocking_connect_syscall) {
  const bool kAllowUnixSocketEvents{false};
  const bool kAllowAcceptEvents{false};
  const bool kAllowNullAcceptEvents{false};

  auto audit_event = kSucceededConnectEvent;
  auto& syscall_data = boost::get<SyscallAuditEventData>(audit_event.data);

  syscall_data.succeeded = false;
  audit_event.record_list.at(0).fields["success"] = "no";
  audit_event.record_list.at(0).fields["exit"] = std::to_string(-EINPROGRESS);

  for (const auto& allow_failed_events : {true, false}) {
    std::vector<Row> emitted_row_list;
    auto status = SocketEventSubscriber::ProcessEvents(emitted_row_list,
                                                       {audit_event},
                                                       allow_failed_events,
                                                       kAllowUnixSocketEvents,
                                                       kAllowAcceptEvents,
                                                       kAllowNullAcceptEvents);

    EXPECT_TRUE(status.ok());
    ASSERT_EQ(emitted_row_list.size(), 1);
    EXPECT_EQ(emitted_row_list.front()["success"], "1");
    EXPECT_EQ(emitted_row_list.front()["status"], "in_progress");
  }
}

TEST_F(SocketEventsTableTests, succeeded_bind_syscall) {
  const bool kAllowUnixSocketEvents{false};
  const bool kAllowAcceptEvents{false};
  const bool kAllowNullAcceptEvents{false};

  for (const auto& allow_failed_events : {true, false}) {
    std::vector<Row> emitted_row_list;
    auto status = SocketEventSubscriber::ProcessEvents(emitted_row_list,
                                                       {kSucceededBindEvent},
                                                       allow_failed_events,
                                                       kAllowUnixSocketEvents,
                                                       kAllowAcceptEvents,
                                                       kAllowNullAcceptEvents);

    EXPECT_TRUE(status.ok());
    ASSERT_EQ(emitted_row_list.size(), 1);
    EXPECT_EQ(emitted_row_list.front()["success"], "1");
    EXPECT_EQ(emitted_row_list.front()["status"], "succeeded");
  }
}

TEST_F(SocketEventsTableTests, failed_bind_syscall) {
  const bool kAllowUnixSocketEvents{false};
  const bool kAllowAcceptEvents{false};
  const bool kAllowNullAcceptEvents{false};

  auto audit_event = kSucceededBindEvent;
  auto& syscall_data = boost::get<SyscallAuditEventData>(audit_event.data);

  syscall_data.succeeded = false;
  audit_event.record_list.at(0).fields["success"] = "no";

  for (const auto& errno_value : {-EINPROGRESS, -EBADF}) {
    audit_event.record_list.at(0).fields["exit"] = std::to_string(errno_value);

    for (const auto& allow_failed_events : {true, false}) {
      std::vector<Row> emitted_row_list;
      auto status =
          SocketEventSubscriber::ProcessEvents(emitted_row_list,
                                               {audit_event},
                                               allow_failed_events,
                                               kAllowUnixSocketEvents,
                                               kAllowAcceptEvents,
                                               kAllowNullAcceptEvents);

      EXPECT_TRUE(status.ok());

      if (allow_failed_events) {
        ASSERT_EQ(emitted_row_list.size(), 1);
        EXPECT_EQ(emitted_row_list.front()["success"], "0");
        EXPECT_EQ(emitted_row_list.front()["status"], "failed");

      } else {
        EXPECT_TRUE(emitted_row_list.empty());
      }
    }
  }
}

TEST_F(SocketEventsTableTests, succeeded_accept_syscall) {
  const bool kAllowFailedEvents{false};
  const bool kAllowUnixSocketEvents{false};
  const bool kAllowNullAcceptEvents{false};

  auto audit_event = kSucceededAccept4Event;
  auto& syscall_data = boost::get<SyscallAuditEventData>(audit_event.data);

  for (const auto& syscall_number : {__NR_accept, __NR_accept4}) {
    for (const auto& allow_accept_events : {false, true}) {
      audit_event.record_list.at(0).fields["syscall"] =
          std::to_string(syscall_number);

      syscall_data.syscall_number = syscall_number;

      std::vector<Row> emitted_row_list;
      auto status =
          SocketEventSubscriber::ProcessEvents(emitted_row_list,
                                               {audit_event},
                                               kAllowFailedEvents,
                                               kAllowUnixSocketEvents,
                                               allow_accept_events,
                                               kAllowNullAcceptEvents);

      EXPECT_TRUE(status.ok());

      if (allow_accept_events) {
        ASSERT_EQ(emitted_row_list.size(), 1);
        EXPECT_EQ(emitted_row_list.front()["success"], "1");
        EXPECT_EQ(emitted_row_list.front()["status"], "succeeded");

      } else {
        EXPECT_TRUE(emitted_row_list.empty());
      }
    }
  }
}

TEST_F(SocketEventsTableTests, failed_accept_syscall) {
  const bool kAllowAcceptEvents{true};
  const bool kAllowUnixSocketEvents{false};
  const bool kAllowNullAcceptEvents{false};

  auto audit_event = kSucceededAccept4Event;
  auto& syscall_data = boost::get<SyscallAuditEventData>(audit_event.data);

  syscall_data.succeeded = false;
  audit_event.record_list.at(0).fields["success"] = "no";
  audit_event.record_list.at(0).fields["exit"] = std::to_string(-EBADF);

  for (const auto& syscall_number : {__NR_accept, __NR_accept4}) {
    for (const auto& allow_failed_events : {false, true}) {
      audit_event.record_list.at(0).fields["syscall"] =
          std::to_string(syscall_number);

      syscall_data.syscall_number = syscall_number;

      std::vector<Row> emitted_row_list;
      auto status =
          SocketEventSubscriber::ProcessEvents(emitted_row_list,
                                               {audit_event},
                                               allow_failed_events,
                                               kAllowUnixSocketEvents,
                                               kAllowAcceptEvents,
                                               kAllowNullAcceptEvents);

      EXPECT_TRUE(status.ok());

      if (allow_failed_events) {
        ASSERT_EQ(emitted_row_list.size(), 1);
        EXPECT_EQ(emitted_row_list.front()["success"], "0");
        EXPECT_EQ(emitted_row_list.front()["status"], "failed");

      } else {
        EXPECT_TRUE(emitted_row_list.empty());
      }
    }
  }
}

TEST_F(SocketEventsTableTests, succeeded_non_blocking_accept_syscall) {
  const bool kAllowUnixSocketEvents{false};
  const bool kAllowFailedEvents{false};
  const bool kAllowAcceptEvents{true};

  auto audit_event = kSucceededConnectEvent;
  auto& syscall_data = boost::get<SyscallAuditEventData>(audit_event.data);

  for (const auto& syscall_number : {__NR_accept, __NR_accept4}) {
    for (const auto& no_incoming_connection : {true, false}) {
      for (const auto& allow_null_accept_events : {true, false}) {
        audit_event.record_list.at(0).fields["syscall"] =
            std::to_string(syscall_number);

        syscall_data.syscall_number = syscall_number;

        if (no_incoming_connection) {
          syscall_data.succeeded = false;
          audit_event.record_list.at(0).fields["success"] = "no";
          audit_event.record_list.at(0).fields["exit"] =
              std::to_string(-EAGAIN);

        } else {
          syscall_data.succeeded = true;
          audit_event.record_list.at(0).fields["success"] = "yes";
          audit_event.record_list.at(0).fields["exit"] = "10";
        }

        std::vector<Row> emitted_row_list;
        auto status =
            SocketEventSubscriber::ProcessEvents(emitted_row_list,
                                                 {audit_event},
                                                 kAllowFailedEvents,
                                                 kAllowUnixSocketEvents,
                                                 kAllowAcceptEvents,
                                                 allow_null_accept_events);

        EXPECT_TRUE(status.ok());

        if (no_incoming_connection) {
          if (allow_null_accept_events) {
            ASSERT_EQ(emitted_row_list.size(), 1);
            EXPECT_EQ(emitted_row_list.front()["success"], "1");
            EXPECT_EQ(emitted_row_list.front()["status"], "no_client");

          } else {
            EXPECT_TRUE(emitted_row_list.empty());
          }

        } else {
          ASSERT_EQ(emitted_row_list.size(), 1);
          EXPECT_EQ(emitted_row_list.front()["success"], "1");
          EXPECT_EQ(emitted_row_list.front()["status"], "succeeded");
        }
      }
    }
  }
}

namespace {

// clang-format off
const AuditEvent kSucceededConnectEvent{
  AuditEvent::Type::Syscall,

  SyscallAuditEventData{
    // syscall id, and whether the 'success' field was set to 'yes'
    __NR_connect,
    true,

    // pid, ppid
    39598,
    39590,

    // uid, auid, euid, fsuid, suid
    1000,
    1000,
    1000,
    1000,
    1000,

    // gid, egid, fsgid, sgid
    1000,
    1000,
    1000,
    1000,

    // Binary path, from the 'exe' field
    "/usr/bin/curl",
  },

  {
    {
      AUDIT_SYSCALL,
      1,
      "1629377973.356:1276",
      {
        { "arch", "c000003e" },
        { "syscall", "42" },
        { "success", "yes" },
        { "exit", "0" },
        { "a0", "7" },
        { "a1", "7fb5de285d0c" },
        { "a2", "10" },
        { "a3", "7fb5df747291" },
        { "items", "0" },
        { "ppid", "39590" },
        { "pid", "39598" },
        { "auid", "1000" },
        { "uid", "1000" },
        { "gid", "1000" },
        { "euid", "1000" },
        { "suid", "1000" },
        { "fsuid", "1000" },
        { "egid", "1000" },
        { "sgid", "1000" },
        { "fsgid", "1000" },
        { "tty", "pts1" },
        { "ses", "2" },
        { "comm", "curl" },
        { "exe", "/usr/bin/curl" },
        { "subj", "unconfined" },
        { "key", "" },
      },
      ""
    },

    {
      AUDIT_SOCKADDR,
      2,
      "1629377973.356:1276",
      {
        { "saddr", "020000357F000035900600D8B57F0000" },
      },
      ""
    },

    {
      AUDIT_PROCTITLE,
      3,
      "1629377973.356:1276",
      {
        { "proctitle", "6375726C0068747470733A2F2F6769746875622E636F6D" },
      },
      ""
    },

    {
      AUDIT_EOE,
      4,
      "1629377973.356:1276",
      { },
      ""
    }
  }
};
// clang-format on

// clang-format off
const AuditEvent kSucceededBindEvent{
  AuditEvent::Type::Syscall,

  SyscallAuditEventData{
    // syscall id, and whether the 'success' field was set to 'yes'
    __NR_bind,
    true,

    // pid, ppid
    48359,
    39590,

    // uid, auid, euid, fsuid, suid
    1000,
    1000,
    1000,
    1000,
    1000,

    // gid, egid, fsgid, sgid
    1000,
    1000,
    1000,
    1000,

    // Binary path, from the 'exe' field
    "/usr/bin/nc.openbsd",
  },

  {
    {
      AUDIT_SYSCALL,
      1,
      "1629382051.394:1296",
      {
        { "arch", "c000003e" },
        { "syscall", "49" },
        { "success", "yes" },
        { "exit", "0" },
        { "a0", "3" },
        { "a1", "55ea21a222d0" },
        { "a2", "10" },
        { "a3", "7fff5c13e390" },
        { "items", "0" },
        { "ppid", "39590" },
        { "pid", "48359" },
        { "auid", "1000" },
        { "uid", "1000" },
        { "gid", "1000" },
        { "euid", "1000" },
        { "suid", "1000" },
        { "fsuid", "1000" },
        { "egid", "1000" },
        { "sgid", "1000" },
        { "fsgid", "1000" },
        { "tty", "pts1" },
        { "ses", "2" },
        { "comm", "nc" },
        { "exe", "/usr/bin/nc.openbsd" },
        { "subj", "unconfined" },
        { "key", "" },
      },
      ""
    },

    {
      AUDIT_SOCKADDR,
      2,
      "1629382051.394:1296",
      {
        { "saddr", "02001F907F0000010000000000000000" },
      },
      ""
    },

    {
      AUDIT_PROCTITLE,
      3,
      "1629382051.394:1296",
      {
        { "proctitle", "6E63002D6C003132372E302E302E310038303830" },
      },
      ""
    },

    {
      AUDIT_EOE,
      4,
      "1629382051.394:1296",
      { },
      ""
    }
  }
};
// clang-format on

// clang-format off
const AuditEvent kSucceededAccept4Event{
  AuditEvent::Type::Syscall,

  SyscallAuditEventData{
    // syscall id, and whether the 'success' field was set to 'yes'
    __NR_accept4,
    true,

    // pid, ppid
    93383,
    93329,

    // uid, auid, euid, fsuid, suid
    1000,
    1000,
    1000,
    1000,
    1000,

    // gid, egid, fsgid, sgid
    1000,
    1000,
    1000,
    1000,

    // Binary path, from the 'exe' field
    "/usr/bin/nc.openbsd",
  },

  {
    {
      AUDIT_SYSCALL,
      1,
      "1629395472.368:1348",
      {
        { "arch", "c000003e" },
        { "syscall", "288" },
        { "success", "yes" },
        { "exit", "4" },
        { "a0", "3" },
        { "a1", "7fff4b475ec0" },
        { "a2", "7fff4b475e54" },
        { "a3", "800" },
        { "items", "0" },
        { "ppid", "93329" },
        { "pid", "93383" },
        { "auid", "1000" },
        { "uid", "1000" },
        { "gid", "1000" },
        { "euid", "1000" },
        { "suid", "1000" },
        { "fsuid", "1000" },
        { "egid", "1000" },
        { "sgid", "1000" },
        { "fsgid", "1000" },
        { "tty", "pts1" },
        { "ses", "2" },
        { "comm", "nc" },
        { "exe", "/usr/bin/nc.openbsd" },
        { "subj", "unconfined" },
        { "key", "" },
      },
      ""
    },

    {
      AUDIT_SOCKADDR,
      2,
      "1629395472.368:1348",
      {
        { "saddr", "0200E8007F0000010000000000000000" },
      },
      ""
    },

    {
      AUDIT_PROCTITLE,
      3,
      "1629395472.368:1348",
      {
        { "proctitle", "6E63002D6C003132372E302E302E310038303830" },
      },
      ""
    },

    {
      AUDIT_EOE,
      4,
      "1629395472.368:1348",
      { },
      ""
    }
  }
};
// clang-format on

} // namespace

} // namespace osquery
