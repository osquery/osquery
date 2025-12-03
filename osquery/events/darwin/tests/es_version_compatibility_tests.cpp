/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/core/flags.h>
#include <osquery/events/darwin/es_event_categories.h>
#include <osquery/events/darwin/es_utils.h>
#include <osquery/utils/status/status.h>
#include <algorithm> // For std::find

// Use the osquery namespace for these functions
using osquery::getEventCategory;
using osquery::getEventSeverity;
using osquery::getEventTypeName;
using osquery::getHighSeverityEventTypes;
using osquery::isEventTypeAvailable;
using osquery::getEnabledEventTypes;

namespace osquery {
namespace {

class EndpointSecurityVersionCompatibilityTests : public testing::Test {
 protected:
  void SetUp() override {
    // Get macOS version
    macos_version_ = getSystemVersion();
  }

  int getSystemVersion() {
    auto result = std::system("sw_vers -productVersion | cut -d. -f1");
    if (result == 0) {
      FILE* pipe = popen("sw_vers -productVersion | cut -d. -f1", "r");
      if (!pipe) {
        return 0;
      }
      char buffer[128];
      std::string result = "";
      while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL) {
          result += buffer;
        }
      }
      pclose(pipe);
      
      try {
        return std::stoi(result);
      } catch (...) {
        return 0;
      }
    }
    return 0;
  }

  bool isVersionSupported(int min_version) {
    return macos_version_ >= min_version;
  }

  int macos_version_{0};
};

TEST_F(EndpointSecurityVersionCompatibilityTests, test_base_process_events) {
  // Process events are supported on all versions 10.15+
  auto supported_events = {
      ES_EVENT_TYPE_NOTIFY_EXEC,
      ES_EVENT_TYPE_NOTIFY_FORK,
      ES_EVENT_TYPE_NOTIFY_EXIT
  };
  
  for (const auto& event : supported_events) {
    EXPECT_TRUE(isEventTypeAvailable(event));
    EXPECT_EQ(getEventCategory(event), "process");
  }
}

TEST_F(EndpointSecurityVersionCompatibilityTests, test_base_file_events) {
  // File events are supported on all versions 10.15+
  auto supported_events = {
      ES_EVENT_TYPE_NOTIFY_CREATE,
      ES_EVENT_TYPE_NOTIFY_OPEN,
      ES_EVENT_TYPE_NOTIFY_CLOSE,
      ES_EVENT_TYPE_NOTIFY_RENAME,
      ES_EVENT_TYPE_NOTIFY_UNLINK,
      ES_EVENT_TYPE_NOTIFY_WRITE
  };
  
  for (const auto& event : supported_events) {
    EXPECT_TRUE(isEventTypeAvailable(event));
    EXPECT_EQ(getEventCategory(event), "filesystem");
  }
}

TEST_F(EndpointSecurityVersionCompatibilityTests, test_memory_protection_events) {
  if (!isVersionSupported(11)) {
    GTEST_SKIP() << "Memory protection events require macOS 11.0+";
  }
  
  auto memory_events = {
      ES_EVENT_TYPE_NOTIFY_MMAP,
      ES_EVENT_TYPE_NOTIFY_MPROTECT
  };
  
  for (const auto& event : memory_events) {
    EXPECT_TRUE(isEventTypeAvailable(event));
  }
}

TEST_F(EndpointSecurityVersionCompatibilityTests, test_uid_gid_operations) {
  if (!isVersionSupported(12)) {
    GTEST_SKIP() << "UID/GID operations require macOS 12.0+";
  }
  
  auto uid_gid_events = {
      ES_EVENT_TYPE_NOTIFY_SETUID,
      ES_EVENT_TYPE_NOTIFY_SETGID,
      ES_EVENT_TYPE_NOTIFY_SETEUID,
      ES_EVENT_TYPE_NOTIFY_SETEGID,
      ES_EVENT_TYPE_NOTIFY_SETREUID,
      ES_EVENT_TYPE_NOTIFY_SETREGID
  };
  
  for (const auto& event : uid_gid_events) {
    EXPECT_TRUE(isEventTypeAvailable(event));
    EXPECT_EQ(getEventCategory(event), "privilege");
  }
}

TEST_F(EndpointSecurityVersionCompatibilityTests, test_authentication_events) {
  if (!isVersionSupported(13)) {
    GTEST_SKIP() << "Authentication events require macOS 13.0+";
  }
  
  auto auth_events = {
      ES_EVENT_TYPE_NOTIFY_AUTHENTICATION,
      ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED,
      ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED,
      ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN,
      ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT,
      ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK,
      ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK,
      ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
      ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT,
      ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH
  };
  
  for (const auto& event : auth_events) {
    EXPECT_TRUE(isEventTypeAvailable(event));
    EXPECT_EQ(getEventCategory(event), "authentication");
  }
}

TEST_F(EndpointSecurityVersionCompatibilityTests, test_xpc_events) {
  if (!isVersionSupported(14)) {
    GTEST_SKIP() << "XPC events require macOS 14.0+";
  }
  
  auto xpc_events = {
      ES_EVENT_TYPE_NOTIFY_XPC_CONNECT
  };
  
  for (const auto& event : xpc_events) {
    EXPECT_TRUE(isEventTypeAvailable(event));
    EXPECT_EQ(getEventCategory(event), "xpc");
  }
}

TEST_F(EndpointSecurityVersionCompatibilityTests, test_su_sudo_events) {
  if (!isVersionSupported(14)) {
    GTEST_SKIP() << "SU/SUDO events require macOS 14.0+";
  }
  
  auto su_sudo_events = {
      ES_EVENT_TYPE_NOTIFY_SU,
      ES_EVENT_TYPE_NOTIFY_SUDO
  };
  
  for (const auto& event : su_sudo_events) {
    EXPECT_TRUE(isEventTypeAvailable(event));
  }
}

TEST_F(EndpointSecurityVersionCompatibilityTests, test_cross_version_helpers) {
  // Test some of the cross-version helper functions to ensure they behave correctly
  // regardless of macOS version
  
  // String token helpers should work on all versions
  es_string_token_t test_token = {
    .data = "test-string", 
    .length = 11
  };
  
  EXPECT_EQ(getStringFromToken(&test_token), "test-string");
  
  // Event name mapping should work for all events
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_EXEC), "EXEC");
  EXPECT_EQ(getEventTypeName(ES_EVENT_TYPE_NOTIFY_FORK), "FORK");
  
  // Event severity mapping should be consistent
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_EXEC), "high");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_MPROTECT), "medium");
  EXPECT_EQ(getEventSeverity(ES_EVENT_TYPE_NOTIFY_OPEN), "low");
}

TEST_F(EndpointSecurityVersionCompatibilityTests, test_enabled_event_types) {
  // Test that the events enabled are appropriate for the current macOS version
  auto enabled_events = getEnabledEventTypes(
    false,  // high_severity_only
    "",     // include_events
    "",     // exclude_events
    true,   // enable_process_events
    true,   // enable_file_events
    true,   // enable_network_events
    isVersionSupported(13)   // enable_authentication_events
  );
  
  // Basic events should always be included
  EXPECT_TRUE(std::find(enabled_events.begin(), enabled_events.end(), ES_EVENT_TYPE_NOTIFY_EXEC) != enabled_events.end());
  EXPECT_TRUE(std::find(enabled_events.begin(), enabled_events.end(), ES_EVENT_TYPE_NOTIFY_FORK) != enabled_events.end());
  EXPECT_TRUE(std::find(enabled_events.begin(), enabled_events.end(), ES_EVENT_TYPE_NOTIFY_EXIT) != enabled_events.end());
  
  // File events should always be included
  EXPECT_TRUE(std::find(enabled_events.begin(), enabled_events.end(), ES_EVENT_TYPE_NOTIFY_CREATE) != enabled_events.end());
  EXPECT_TRUE(std::find(enabled_events.begin(), enabled_events.end(), ES_EVENT_TYPE_NOTIFY_RENAME) != enabled_events.end());
  
  // Memory events should only be included on macOS 11+
  if (isVersionSupported(11)) {
    EXPECT_TRUE(std::find(enabled_events.begin(), enabled_events.end(), ES_EVENT_TYPE_NOTIFY_MMAP) != enabled_events.end());
    EXPECT_TRUE(std::find(enabled_events.begin(), enabled_events.end(), ES_EVENT_TYPE_NOTIFY_MPROTECT) != enabled_events.end());
  } else {
    EXPECT_TRUE(std::find(enabled_events.begin(), enabled_events.end(), ES_EVENT_TYPE_NOTIFY_MMAP) == enabled_events.end());
    EXPECT_TRUE(std::find(enabled_events.begin(), enabled_events.end(), ES_EVENT_TYPE_NOTIFY_MPROTECT) == enabled_events.end());
  }
  
  // Authentication events should only be included on macOS 13+
  if (isVersionSupported(13)) {
    EXPECT_TRUE(std::find(enabled_events.begin(), enabled_events.end(), ES_EVENT_TYPE_NOTIFY_AUTHENTICATION) != enabled_events.end());
  } else {
    EXPECT_TRUE(std::find(enabled_events.begin(), enabled_events.end(), ES_EVENT_TYPE_NOTIFY_AUTHENTICATION) == enabled_events.end());
  }
  
  // XPC events should only be included on macOS 14+
  if (isVersionSupported(14)) {
    EXPECT_TRUE(std::find(enabled_events.begin(), enabled_events.end(), ES_EVENT_TYPE_NOTIFY_XPC_CONNECT) != enabled_events.end());
  } else {
    EXPECT_TRUE(std::find(enabled_events.begin(), enabled_events.end(), ES_EVENT_TYPE_NOTIFY_XPC_CONNECT) == enabled_events.end());
  }
}

TEST_F(EndpointSecurityVersionCompatibilityTests, test_high_severity_events) {
  // Test that high severity events list is appropriate for macOS version
  auto high_severity = getHighSeverityEventTypes();
  
  // These should be high severity on all versions
  EXPECT_TRUE(std::find(high_severity.begin(), high_severity.end(), ES_EVENT_TYPE_NOTIFY_EXEC) != high_severity.end());
  EXPECT_TRUE(std::find(high_severity.begin(), high_severity.end(), ES_EVENT_TYPE_NOTIFY_KEXTLOAD) != high_severity.end());
  
  // These should only be high severity if the version supports them
  if (isVersionSupported(13)) {
    EXPECT_TRUE(std::find(high_severity.begin(), high_severity.end(), ES_EVENT_TYPE_NOTIFY_AUTHENTICATION) != high_severity.end());
  }
  
  if (isVersionSupported(14)) {
    EXPECT_TRUE(std::find(high_severity.begin(), high_severity.end(), ES_EVENT_TYPE_NOTIFY_SU) != high_severity.end());
  }
}

} // namespace
} // namespace osquery