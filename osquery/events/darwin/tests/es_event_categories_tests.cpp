/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/events/darwin/es_event_categories.h>
#include <osquery/utils/status/status.h>

namespace osquery {
namespace {

class EndpointSecurityEventCategoriesTests : public testing::Test {};

TEST_F(EndpointSecurityEventCategoriesTests, test_event_categorization) {
  // Test process events
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_EXEC), "process");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_FORK), "process");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_EXIT), "process");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_PTY_CLOSE), "process");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_PTY_GRANT), "process");

  // Test file system events
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_CREATE), "filesystem");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_RENAME), "filesystem");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_OPEN), "filesystem");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_CLOSE), "filesystem");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_WRITE), "filesystem");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_UNLINK), "filesystem");
  // CHMOD and CHOWN are removed in macOS 15+, replaced by SETMODE and SETOWNER
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_CHMOD), "filesystem");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_CHOWN), "filesystem");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_SETACL), "filesystem");

  // Test authentication events
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION),
            "authentication");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED),
            "authentication");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED),
            "authentication");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN),
            "authentication");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT),
            "authentication");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK),
            "authentication");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK),
            "authentication");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_TCC_MODIFY),
            "authentication");

  // Test network events - many are removed in macOS 15+
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_CONNECT), "network");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_BIND), "network");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_SOCKET), "network");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_LISTEN), "network");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_ACCEPT), "network");
  // EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_SENDTO), "network");
  // EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_RECVFROM), "network");

  // Test privilege events
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_SETUID), "privilege");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_SETGID), "privilege");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_SETEUID), "privilege");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_SETEGID), "privilege");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_SETREUID), "privilege");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_SETREGID), "privilege");

  // Test system events
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_MOUNT), "system");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_UNMOUNT), "system");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN), "system");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_KEXTLOAD), "system");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD), "system");
  // SYSCTL and PTRACE are removed in macOS 15+
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_SYSCTL), "system");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_PTRACE), "system");

  // Test remote events
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE),
            "remote");

  // Test profile events
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_PROFILE_ADD), "profile");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE), "profile");

  // Test XPC events
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_XPC_CONNECT), "xpc");

  // Test OpenDirectory events
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD), "directory");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE),
            "directory");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET), "directory");
  EXPECT_EQ(getEventCategory(ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD),
            "directory");

  // Test default/unknown
  EXPECT_EQ(getEventCategory(static_cast<es_event_type_t>(9999)), "unknown");
}

TEST_F(EndpointSecurityEventCategoriesTests, test_event_severity) {
  // High severity events
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_EXEC), "high");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION), "high");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED), "high");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_KEXTLOAD), "high");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE),
            "high");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_SETUID), "high");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN), "high");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_TCC_MODIFY), "high");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_PTRACE), "high");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD), "high");

  // Medium severity events
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_FORK), "medium");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_WRITE), "medium");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_UNLINK), "medium");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_CONNECT), "medium");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_BIND), "medium");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_SYSCTL), "medium");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_MOUNT), "medium");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK), "medium");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK), "medium");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD), "medium");

  // Low severity events
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_OPEN), "low");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_CLOSE), "low");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_EXIT), "low");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_CREATE), "low");

  // Unknown/default
  EXPECT_EQ(getEventSeverity(static_cast<es_event_type_t>(9999)), "low");
}

TEST_F(EndpointSecurityEventCategoriesTests, test_event_description) {
  // Test process events
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_EXEC)
                .find("process was executed"),
            std::string::npos);
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_FORK).find("process fork"),
            std::string::npos);
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_EXIT).find("process exit"),
            std::string::npos);
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_PTY_CLOSE)
                .find("pseudo-terminal was closed"),
            std::string::npos);
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_PTY_GRANT)
                .find("pseudo-terminal was granted"),
            std::string::npos);

  // Test file events
  EXPECT_NE(
      getEventDescription(ES_EVENT_TYPE_NOTIFY_CREATE).find("file was created"),
      std::string::npos);
  EXPECT_NE(
      getEventDescription(ES_EVENT_TYPE_NOTIFY_RENAME).find("file was renamed"),
      std::string::npos);
  EXPECT_NE(
      getEventDescription(ES_EVENT_TYPE_NOTIFY_UNLINK).find("file was deleted"),
      std::string::npos);
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_CHMOD)
                .find("permissions were changed"),
            std::string::npos);
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_CHOWN)
                .find("ownership was changed"),
            std::string::npos);

  // Test auth events
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION)
                .find("authentication"),
            std::string::npos);
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED)
                .find("Malware was detected"),
            std::string::npos);
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_TCC_MODIFY).find("TCC"),
            std::string::npos);
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN)
                .find("Login window session login"),
            std::string::npos);
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK)
                .find("Login window session lock"),
            std::string::npos);

  // Test network events
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_SOCKET)
                .find("socket was created"),
            std::string::npos);
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_CONNECT)
                .find("network connection"),
            std::string::npos);
  EXPECT_NE(
      getEventDescription(ES_EVENT_TYPE_NOTIFY_BIND).find("socket was bound"),
      std::string::npos);
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_LISTEN)
                .find("listening for connections"),
            std::string::npos);

  // Test privilege events
  EXPECT_NE(
      getEventDescription(ES_EVENT_TYPE_NOTIFY_SETUID).find("changed user ID"),
      std::string::npos);
  EXPECT_NE(
      getEventDescription(ES_EVENT_TYPE_NOTIFY_SETGID).find("changed group ID"),
      std::string::npos);

  // Test OpenDirectory events
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD)
                .find("User added to OpenDirectory"),
            std::string::npos);
  EXPECT_NE(getEventDescription(ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD)
                .find("OpenDirectory password"),
            std::string::npos);

  // Test unknown
  EXPECT_NE(
      getEventDescription(static_cast<es_event_type_t>(9999)).find("Unknown"),
      std::string::npos);
}

TEST_F(EndpointSecurityEventCategoriesTests, test_high_severity_filtering) {
  std::vector<es_event_type_t> high_only = getHighSeverityEventTypes();

  // Check that all events in high_only are actually high severity
  for (const auto& event_type : high_only) {
    EXPECT_EQ(getEventSeverity(event_type), "high");
  }

  // Check some specific events that should be in the high severity list
  auto contains = [&high_only](es_event_type_t type) {
    return std::find(high_only.begin(), high_only.end(), type) !=
           high_only.end();
  };

  EXPECT_TRUE(contains(ES_EVENT_TYPE_NOTIFY_EXEC));
  EXPECT_TRUE(contains(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION));
  EXPECT_TRUE(contains(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED));
  EXPECT_TRUE(contains(ES_EVENT_TYPE_NOTIFY_KEXTLOAD));
  EXPECT_TRUE(contains(ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE));
  EXPECT_TRUE(contains(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN));
  EXPECT_TRUE(contains(ES_EVENT_TYPE_NOTIFY_TCC_MODIFY));
  EXPECT_TRUE(contains(ES_EVENT_TYPE_NOTIFY_PTRACE));
  EXPECT_TRUE(contains(ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD));

  // Check some medium/low events that should NOT be in the high list
  EXPECT_FALSE(contains(ES_EVENT_TYPE_NOTIFY_OPEN));
  EXPECT_FALSE(contains(ES_EVENT_TYPE_NOTIFY_CLOSE));
  EXPECT_FALSE(contains(ES_EVENT_TYPE_NOTIFY_EXIT));
  EXPECT_FALSE(contains(ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK));
  EXPECT_FALSE(contains(ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD));
}

TEST_F(EndpointSecurityEventCategoriesTests, test_event_filtering) {
  // Test include filtering
  std::string include_list = "EXEC,FORK,AUTHENTICATION,LW_SESSION_LOGIN";
  std::set<es_event_type_t> included_events = parseEventTypes(include_list);

  EXPECT_EQ(included_events.size(), 4);
  EXPECT_TRUE(included_events.find(ES_EVENT_TYPE_NOTIFY_EXEC) !=
              included_events.end());
  EXPECT_TRUE(included_events.find(ES_EVENT_TYPE_NOTIFY_FORK) !=
              included_events.end());
  EXPECT_TRUE(included_events.find(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION) !=
              included_events.end());
  EXPECT_TRUE(included_events.find(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN) !=
              included_events.end());

  // Test exclude filtering
  std::string exclude_list = "OPEN,CLOSE,EXIT,TCC_MODIFY";
  std::set<es_event_type_t> excluded_events = parseEventTypes(exclude_list);

  EXPECT_EQ(excluded_events.size(), 4);
  EXPECT_TRUE(excluded_events.find(ES_EVENT_TYPE_NOTIFY_OPEN) !=
              excluded_events.end());
  EXPECT_TRUE(excluded_events.find(ES_EVENT_TYPE_NOTIFY_CLOSE) !=
              excluded_events.end());
  EXPECT_TRUE(excluded_events.find(ES_EVENT_TYPE_NOTIFY_EXIT) !=
              excluded_events.end());
  EXPECT_TRUE(excluded_events.find(ES_EVENT_TYPE_NOTIFY_TCC_MODIFY) !=
              excluded_events.end());

  // Test invalid events
  std::string invalid_list = "EXEC,INVALID_EVENT,FORK";
  std::set<es_event_type_t> parsed_events = parseEventTypes(invalid_list);

  EXPECT_EQ(parsed_events.size(), 2); // The invalid one should be skipped
  EXPECT_TRUE(parsed_events.find(ES_EVENT_TYPE_NOTIFY_EXEC) !=
              parsed_events.end());
  EXPECT_TRUE(parsed_events.find(ES_EVENT_TYPE_NOTIFY_FORK) !=
              parsed_events.end());

  // Test case insensitivity
  std::string mixed_case_list = "exec,Fork,AUTHENTICATION";
  std::set<es_event_type_t> case_events = parseEventTypes(mixed_case_list);

  EXPECT_EQ(case_events.size(), 3);
  EXPECT_TRUE(case_events.find(ES_EVENT_TYPE_NOTIFY_EXEC) != case_events.end());
  EXPECT_TRUE(case_events.find(ES_EVENT_TYPE_NOTIFY_FORK) != case_events.end());
  EXPECT_TRUE(case_events.find(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION) !=
              case_events.end());
}

TEST_F(EndpointSecurityEventCategoriesTests, test_event_type_name) {
  // Test process events
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_EXEC), "EXEC");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_FORK), "FORK");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_EXIT), "EXIT");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_PTY_CLOSE), "PTY_CLOSE");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_PTY_GRANT), "PTY_GRANT");

  // Test file events
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_CREATE), "CREATE");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_RENAME), "RENAME");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_UNLINK), "UNLINK");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_CHMOD), "CHMOD");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_CHOWN), "CHOWN");

  // Test auth events
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION),
            "AUTHENTICATION");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_TCC_MODIFY), "TCC_MODIFY");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN),
            "LW_SESSION_LOGIN");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK),
            "LW_SESSION_LOCK");

  // Test network events
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_SOCKET), "SOCKET");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_CONNECT), "CONNECT");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_BIND), "BIND");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_LISTEN), "LISTEN");

  // Test OpenDirectory events
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD),
            "OD_GROUP_ADD");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE),
            "OD_GROUP_REMOVE");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET),
            "OD_GROUP_SET");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD),
            "OD_MODIFY_PASSWORD");

  // Test unknown
  EXPECT_EQ(getEventTypeName(static_cast<es_event_type_t>(9999)), "UNKNOWN");
}

} // namespace
} // namespace osquery