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

namespace osquery {
namespace {

class ESEventCategoriesTests : public testing::Test {};

TEST_F(ESEventCategoriesTests, categorization) {
  // Test basic process events
  EXPECT_EQ("process", getEventCategory(ES_EVENT_TYPE_NOTIFY_EXEC));
  EXPECT_EQ("process", getEventCategory(ES_EVENT_TYPE_NOTIFY_FORK));
  EXPECT_EQ("process", getEventCategory(ES_EVENT_TYPE_NOTIFY_EXIT));

  // Test file events
  EXPECT_EQ("filesystem", getEventCategory(ES_EVENT_TYPE_NOTIFY_CREATE));
  EXPECT_EQ("filesystem", getEventCategory(ES_EVENT_TYPE_NOTIFY_RENAME));
  EXPECT_EQ("filesystem", getEventCategory(ES_EVENT_TYPE_NOTIFY_OPEN));

  // Test authentication events
  EXPECT_EQ("authentication",
            getEventCategory(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION));
  EXPECT_EQ("authentication",
            getEventCategory(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN));
  EXPECT_EQ("authentication", getEventCategory(ES_EVENT_TYPE_NOTIFY_SU));
  EXPECT_EQ("authentication", getEventCategory(ES_EVENT_TYPE_NOTIFY_SUDO));

  // Test security events
  EXPECT_EQ("security",
            getEventCategory(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED));
  EXPECT_EQ("security",
            getEventCategory(ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED));

  // Test network events
  EXPECT_EQ("network", getEventCategory(ES_EVENT_TYPE_NOTIFY_SOCKET));
  EXPECT_EQ("network", getEventCategory(ES_EVENT_TYPE_NOTIFY_CONNECT));
  EXPECT_EQ("network", getEventCategory(ES_EVENT_TYPE_NOTIFY_BIND));

  // Test system events
  EXPECT_EQ("system", getEventCategory(ES_EVENT_TYPE_NOTIFY_KEXTLOAD));
  EXPECT_EQ("system", getEventCategory(ES_EVENT_TYPE_NOTIFY_SYSCTL));

  // Test memory events
  EXPECT_EQ("memory", getEventCategory(ES_EVENT_TYPE_NOTIFY_MMAP));
  EXPECT_EQ("memory", getEventCategory(ES_EVENT_TYPE_NOTIFY_MPROTECT));

  // Test privilege events
  EXPECT_EQ("privilege", getEventCategory(ES_EVENT_TYPE_NOTIFY_SETUID));
  EXPECT_EQ("privilege", getEventCategory(ES_EVENT_TYPE_NOTIFY_SETEUID));

  // Test unknown event
  EXPECT_EQ("unknown", getEventCategory(static_cast<es_event_type_t>(999)));
}

TEST_F(ESEventCategoriesTests, severities) {
  // Test high severity events
  EXPECT_EQ("high", getEventSeverity(ES_EVENT_TYPE_NOTIFY_EXEC));
  EXPECT_EQ("high", getEventSeverity(ES_EVENT_TYPE_NOTIFY_KEXTLOAD));
  EXPECT_EQ("high", getEventSeverity(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION));
  EXPECT_EQ("high", getEventSeverity(ES_EVENT_TYPE_NOTIFY_SETUID));

  // Test medium severity events
  EXPECT_EQ("medium", getEventSeverity(ES_EVENT_TYPE_NOTIFY_FORK));
  EXPECT_EQ("medium", getEventSeverity(ES_EVENT_TYPE_NOTIFY_CREATE));
  EXPECT_EQ("medium", getEventSeverity(ES_EVENT_TYPE_NOTIFY_MMAP));

  // Test low severity events
  EXPECT_EQ("low", getEventSeverity(ES_EVENT_TYPE_NOTIFY_EXIT));
  EXPECT_EQ("low", getEventSeverity(ES_EVENT_TYPE_NOTIFY_CLOSE));

  // Test unknown event defaults to low
  EXPECT_EQ("low", getEventSeverity(static_cast<es_event_type_t>(999)));
}

TEST_F(ESEventCategoriesTests, names) {
  // Test process event names
  EXPECT_EQ("Process execution", getEventName(ES_EVENT_TYPE_NOTIFY_EXEC));
  EXPECT_EQ("Process fork", getEventName(ES_EVENT_TYPE_NOTIFY_FORK));
  EXPECT_EQ("Process exit", getEventName(ES_EVENT_TYPE_NOTIFY_EXIT));

  // Test network event names
  EXPECT_EQ("Socket created", getEventName(ES_EVENT_TYPE_NOTIFY_SOCKET));
  EXPECT_EQ("Network connection", getEventName(ES_EVENT_TYPE_NOTIFY_CONNECT));

  // Test authentication event names
  EXPECT_EQ("SSH login", getEventName(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN));
  EXPECT_EQ("SU command executed", getEventName(ES_EVENT_TYPE_NOTIFY_SU));

  // Test unknown event
  EXPECT_EQ("Unknown event type",
            getEventName(static_cast<es_event_type_t>(999)));
}

TEST_F(ESEventCategoriesTests, enabledEvents) {
  // Test process events (available on all versions)
  auto process_events = getEnabledEventTypes("process");
  ASSERT_GT(process_events.size(), 0U);

  // Verify basic events are included
  EXPECT_NE(std::find(process_events.begin(),
                      process_events.end(),
                      ES_EVENT_TYPE_NOTIFY_EXEC),
            process_events.end());
  EXPECT_NE(std::find(process_events.begin(),
                      process_events.end(),
                      ES_EVENT_TYPE_NOTIFY_FORK),
            process_events.end());
  EXPECT_NE(std::find(process_events.begin(),
                      process_events.end(),
                      ES_EVENT_TYPE_NOTIFY_EXIT),
            process_events.end());

  // Test file events
  auto file_events = getEnabledEventTypes("file");
  ASSERT_GT(file_events.size(), 0U);

  // Verify basic file events are included
  EXPECT_NE(
      std::find(
          file_events.begin(), file_events.end(), ES_EVENT_TYPE_NOTIFY_CREATE),
      file_events.end());
  EXPECT_NE(
      std::find(
          file_events.begin(), file_events.end(), ES_EVENT_TYPE_NOTIFY_RENAME),
      file_events.end());

  // The behavior of the next tests will vary depending on macOS version
  // These tests are structured to pass on any supported macOS version

  // Test authentication events (available on macOS 13+)
  auto auth_events = getEnabledEventTypes("authentication");
  if (__builtin_available(macos 13.0, *)) {
    EXPECT_GT(auth_events.size(), 0U);
  } else {
    EXPECT_EQ(auth_events.size(), 0U);
  }

  // Test memory events (available on macOS 11+)
  auto memory_events = getEnabledEventTypes("memory");
  if (__builtin_available(macos 11.0, *)) {
    EXPECT_GT(memory_events.size(), 0U);
  } else {
    EXPECT_EQ(memory_events.size(), 0U);
  }

  // Test security events (available on macOS 13+)
  auto security_events = getEnabledEventTypes("security");
  if (__builtin_available(macos 13.0, *)) {
    EXPECT_GT(security_events.size(), 0U);
    // Verify security events are included
    if (security_events.size() > 0) {
      EXPECT_NE(std::find(security_events.begin(),
                          security_events.end(),
                          ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED),
                security_events.end());
      EXPECT_NE(std::find(security_events.begin(),
                          security_events.end(),
                          ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED),
                security_events.end());
    }
  } else {
    EXPECT_EQ(security_events.size(), 0U);
  }
}

TEST_F(ESEventCategoriesTests, versionDetection) {
  // Test osSupportsNetworkEvents() - result depends on macOS version
  bool network_supported = osSupportsNetworkEvents();
  if (__builtin_available(macos 10.15, *)) {
    if (__builtin_available(macos 15.0, *)) {
      EXPECT_FALSE(network_supported);
    } else {
      EXPECT_TRUE(network_supported);
    }
  } else {
    EXPECT_FALSE(network_supported);
  }

  // Test useEuidFieldsForSetters() - result depends on macOS version
  bool use_euid = useEuidFieldsForSetters();
  if (__builtin_available(macos 12.0, *)) {
    EXPECT_TRUE(use_euid);
  } else {
    EXPECT_FALSE(use_euid);
  }

  // Test isEventTypeAvailable() for events available on different macOS
  // versions Core events (available on all versions)
  EXPECT_TRUE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_EXEC));
  EXPECT_TRUE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_FORK));
  EXPECT_TRUE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_EXIT));

  // Memory events (available on macOS 11+)
  if (__builtin_available(macos 11.0, *)) {
    EXPECT_TRUE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_MMAP));
    EXPECT_TRUE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_MPROTECT));
  } else {
    EXPECT_FALSE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_MMAP));
    EXPECT_FALSE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_MPROTECT));
  }

  // Authentication events (available on macOS 13+)
  if (__builtin_available(macos 13.0, *)) {
    EXPECT_TRUE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION));
    EXPECT_TRUE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN));
  } else {
    EXPECT_FALSE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_AUTHENTICATION));
    EXPECT_FALSE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN));
  }

  // SU/SUDO events (available on macOS 14+)
  if (__builtin_available(macos 14.0, *)) {
    EXPECT_TRUE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_SU));
    EXPECT_TRUE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_SUDO));
  } else {
    EXPECT_FALSE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_SU));
    EXPECT_FALSE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_SUDO));
  }

  // Custom polyfill events (should return false as they're not actually
  // available at runtime)
  EXPECT_FALSE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_SOCKET));
  EXPECT_FALSE(isEventTypeAvailable(ES_EVENT_TYPE_NOTIFY_CONNECT));
}

} // namespace
} // namespace osquery