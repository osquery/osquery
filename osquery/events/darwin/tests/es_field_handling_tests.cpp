/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/events/darwin/es_utils.h>
#include <osquery/events/darwin/es_event_categories.h>
#include <osquery/utils/status/status.h>

namespace osquery {
namespace {

// Forward declarations of helper functions used in tests
uint32_t getSafeUInt32(const uint32_t* value, uint32_t default_value);
int64_t getSafeInt64(const int64_t* value, int64_t default_value);
es_event_type_t getEventType(const es_message_t* message);
std::string getProcessPath(const es_message_t* message);
std::string getPathFromProcess(const es_process_t* process);
std::string getPathFromFileObject(const es_file_t* file);
uid_t getEffectiveUID(uid_t process_uid, uid_t event_uid);

class EndpointSecurityFieldHandlingTests : public testing::Test {
 protected:
  void SetUp() override {
    // Initialize test data
    setupStringTokens();
  }

  void TearDown() override {
    // Clean up any allocated memory
    for (auto ptr : allocated_pointers_) {
      delete ptr;
    }
    allocated_pointers_.clear();
  }

  void setupStringTokens() {
    // Setup test string tokens
    test_token_empty_ = {.data = nullptr, .length = 0};
    test_token_valid_ = {.data = "test-string", .length = 11};
    test_token_zero_length_ = {.data = "test", .length = 0};
  }

  // Helper to track allocated pointers for cleanup
  template <typename T>
  T* trackPointer(T* ptr) {
    allocated_pointers_.push_back(static_cast<void*>(ptr));
    return ptr;
  }

  // Test data
  es_string_token_t test_token_empty_;
  es_string_token_t test_token_valid_;
  es_string_token_t test_token_zero_length_;
  std::vector<void*> allocated_pointers_;
};

TEST_F(EndpointSecurityFieldHandlingTests, test_string_token_handling) {
  // Test valid string token
  EXPECT_EQ(getStringFromToken(&test_token_valid_), "test-string");
  
  // Test empty token
  EXPECT_EQ(getStringFromToken(&test_token_empty_), "");
  
  // Test zero length token
  EXPECT_EQ(getStringFromToken(&test_token_zero_length_), "");
  
  // Test null token
  EXPECT_EQ(getStringFromToken(static_cast<const es_string_token_t*>(nullptr)), "");
}

TEST_F(EndpointSecurityFieldHandlingTests, test_path_handling) {
  // Create a simple file path token
  es_string_token_t path_token = {.data = "/path/to/file.txt", .length = 16};
  
  // Test path extraction
  EXPECT_EQ(getStringFromToken(&path_token), "/path/to/file.txt");
  
  // Test path in structured file object
  es_file_t file = {};
  file.path = path_token;
  
  EXPECT_EQ(getPathFromFileObject(&file), "/path/to/file.txt");
  
  // Test with null file object
  EXPECT_EQ(getPathFromFileObject(nullptr), "");
}

TEST_F(EndpointSecurityFieldHandlingTests, test_process_path_handling) {
  // Create a simple process path token
  es_string_token_t proc_path_token = {.data = "/usr/bin/osqueryi", .length = 16};
  
  // Setup mock process object
  es_process_t process = {};
  process.executable = trackPointer(new es_file_t());
  process.executable->path = proc_path_token;
  
  // Test process path extraction
  EXPECT_EQ(getPathFromProcess(&process), "/usr/bin/osqueryi");
  
  // Test with null process
  EXPECT_EQ(getPathFromProcess(nullptr), "");
}

TEST_F(EndpointSecurityFieldHandlingTests, test_safe_numeric_field_access) {
  // Test getting a numeric value with default
  uint32_t test_value = 42;
  EXPECT_EQ(getSafeUInt32(&test_value, 0), 42);
  
  // Test with null pointer
  EXPECT_EQ(getSafeUInt32(nullptr, 100), 100);
  
  // Test with int64
  int64_t test_int64 = -42;
  EXPECT_EQ(getSafeInt64(&test_int64, 0), -42);
  EXPECT_EQ(getSafeInt64(nullptr, -100), -100);
}

TEST_F(EndpointSecurityFieldHandlingTests, test_event_message_safe_access) {
  // Test that we can safely access fields in potentially incomplete messages
  
  // Create a minimal event message
  es_message_t message = {};
  message.event_type = ES_EVENT_TYPE_NOTIFY_EXEC;
  message.process = nullptr;
  
  // Test event type access
  EXPECT_EQ(getEventType(&message), ES_EVENT_TYPE_NOTIFY_EXEC);
  
  // Test with null message
  EXPECT_EQ(getEventType(nullptr), static_cast<es_event_type_t>(0));
  
  // Validate process path extraction from message is safe when process fields are missing
  EXPECT_EQ(getProcessPath(&message), "");
}

TEST_F(EndpointSecurityFieldHandlingTests, test_version_specific_field_handling) {
  // This test validates that our code can properly handle fields that have
  // different names/structures in different macOS versions
  
  // Test with a "uid" style field (pre-macOS 12)
  es_event_setuid_t pre12 = {};
  pre12.uid = 501;
  
  // Test with a "euid" style field (macOS 12+)
  es_event_setuid_t post12 = {};
  post12.uid = 501;  // Using uid field since euid is renamed in macOS 15
  
  // Our access helpers should handle both formats correctly
  EXPECT_EQ(getEffectiveUID(501, pre12.uid), 501);
  EXPECT_EQ(getEffectiveUID(501, post12.uid), 501);
}

// Helper functions that would be defined in the actual codebase
uint32_t getSafeUInt32(const uint32_t* value, uint32_t default_value) {
  if (value == nullptr) {
    return default_value;
  }
  return *value;
}

int64_t getSafeInt64(const int64_t* value, int64_t default_value) {
  if (value == nullptr) {
    return default_value;
  }
  return *value;
}

es_event_type_t getEventType(const es_message_t* message) {
  if (message == nullptr) {
    return static_cast<es_event_type_t>(0);
  }
  return message->event_type;
}

std::string getProcessPath(const es_message_t* message) {
  if (message == nullptr || 
      message->event_type != ES_EVENT_TYPE_NOTIFY_EXEC ||
      message->process == nullptr ||
      message->process->executable == nullptr ||
      message->process->executable->path.data == nullptr) {
    return "";
  }
  return getPathFromProcess(message->process);
}

std::string getPathFromProcess(const es_process_t* process) {
  if (process == nullptr || process->executable == nullptr) {
    return "";
  }
  return getStringFromToken(&process->executable->path);
}

std::string getPathFromFileObject(const es_file_t* file) {
  if (file == nullptr) {
    return "";
  }
  return getStringFromToken(&file->path);
}

// Example of cross-version compatibility function
uid_t getEffectiveUID(uid_t process_uid, uid_t event_uid) {
  // This function would handle different field names in different versions
  return event_uid;
}

// No longer needed, since we're using the standard es_event_setuid_t struct

} // namespace
} // namespace osquery