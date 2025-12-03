/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#import <Foundation/Foundation.h>

#include <gtest/gtest.h>

#include <osquery/core/sql/query_data.h>
#include <osquery/core/tables.h>

// Mock Objective-C class that mimics the BTM item structure
// Must be at global scope (Objective-C declarations cannot be in C++
// namespaces)
@interface MockBTMItem : NSObject
@property(nonatomic, strong) NSNumber* type;
@property(nonatomic, strong) NSString* name;
@property(nonatomic, strong) NSNumber* disposition;
@property(nonatomic, strong) NSURL* url;
@property(nonatomic, strong) NSArray* programArguments;
@end

@implementation MockBTMItem
@end

namespace osquery {
namespace tables {

// Forward declaration of parseItem function
void parseItem(const std::string& username, id item, QueryData& results);

class StartupItemsTests : public testing::Test {};

TEST_F(StartupItemsTests, test_parseItem_nil_item) {
  QueryData results;
  parseItem("testuser", nil, results);
  EXPECT_EQ(results.size(), 0U);
}

TEST_F(StartupItemsTests, test_parseItem_with_all_properties) {
  @autoreleasepool {
    MockBTMItem* item = [[MockBTMItem alloc] init];
    item.type = @(0x00004); // LoginItem flag
    item.name = @"TestApp";
    item.disposition = @(0x03); // Enabled | Allowed
    item.url = [NSURL fileURLWithPath:@"/Applications/TestApp.app"];
    item.programArguments = @[ @"/usr/bin/test", @"--arg1", @"--arg2" ];

    QueryData results;
    parseItem("testuser", item, results);

    ASSERT_EQ(results.size(), 1U);
    const Row& row = results[0];

    EXPECT_EQ(row.at("username"), "testuser");
    EXPECT_EQ(row.at("source"), "Background Task Management");
    EXPECT_EQ(row.at("name"), "TestApp");
    EXPECT_EQ(row.at("type"), "login item");
    EXPECT_EQ(row.at("status"), "enabled, allowed");
    EXPECT_EQ(row.at("path"), "/Applications/TestApp.app");
    EXPECT_EQ(row.at("args"), "/usr/bin/test --arg1 --arg2");
  }
}

TEST_F(StartupItemsTests, test_parseItem_minimal_properties) {
  @autoreleasepool {
    MockBTMItem* item = [[MockBTMItem alloc] init];
    item.type = @(0x00001); // UserItem flag

    QueryData results;
    parseItem("minimaluser", item, results);

    ASSERT_EQ(results.size(), 1U);
    const Row& row = results[0];

    EXPECT_EQ(row.at("username"), "minimaluser");
    EXPECT_EQ(row.at("source"), "Background Task Management");
    EXPECT_EQ(row.at("type"), "user item");
    EXPECT_EQ(row.at("status"), "unknown");
  }
}

TEST_F(StartupItemsTests, test_parseItem_skip_developer_item) {
  @autoreleasepool {
    MockBTMItem* item = [[MockBTMItem alloc] init];
    item.type = @(0x00020); // Developer flag

    QueryData results;
    parseItem("testuser", item, results);

    EXPECT_EQ(results.size(), 0U);
  }
}

TEST_F(StartupItemsTests, test_parseItem_skip_quicklook_item) {
  @autoreleasepool {
    MockBTMItem* item = [[MockBTMItem alloc] init];
    item.type = @(0x00800); // Quicklook flag

    QueryData results;
    parseItem("testuser", item, results);

    EXPECT_EQ(results.size(), 0U);
  }
}

TEST_F(StartupItemsTests, test_parseItem_skip_spotlight_item) {
  @autoreleasepool {
    MockBTMItem* item = [[MockBTMItem alloc] init];
    item.type = @(0x00040); // Spotlight flag

    QueryData results;
    parseItem("testuser", item, results);

    EXPECT_EQ(results.size(), 0U);
  }
}

TEST_F(StartupItemsTests, test_parseItem_multiple_type_flags) {
  @autoreleasepool {
    MockBTMItem* item = [[MockBTMItem alloc] init];
    item.type = @(0x00005); // UserItem | LoginItem
    item.name = @"MultiFlagApp";
    item.disposition = @(0x01); // Enabled

    QueryData results;
    parseItem("multiuser", item, results);

    ASSERT_EQ(results.size(), 1U);
    const Row& row = results[0];

    EXPECT_EQ(row.at("username"), "multiuser");
    EXPECT_EQ(row.at("name"), "MultiFlagApp");
    EXPECT_EQ(row.at("type"), "user item, login item");
    EXPECT_EQ(row.at("status"), "enabled");
  }
}

TEST_F(StartupItemsTests, test_parseItem_all_disposition_flags) {
  @autoreleasepool {
    MockBTMItem* item = [[MockBTMItem alloc] init];
    item.type = @(0x00002); // App flag
    item.disposition =
        @(0x0F); // All flags: Enabled | Allowed | Hidden | Notified

    QueryData results;
    parseItem("testuser", item, results);

    ASSERT_EQ(results.size(), 1U);
    const Row& row = results[0];

    EXPECT_EQ(row.at("status"), "enabled, allowed, hidden, notified");
  }
}

TEST_F(StartupItemsTests, test_parseItem_no_program_arguments) {
  @autoreleasepool {
    MockBTMItem* item = [[MockBTMItem alloc] init];
    item.type = @(0x00004); // LoginItem
    item.url = [NSURL fileURLWithPath:@"/usr/bin/testapp"];

    QueryData results;
    parseItem("testuser", item, results);

    ASSERT_EQ(results.size(), 1U);
    const Row& row = results[0];

    EXPECT_EQ(row.at("path"), "/usr/bin/testapp");
    // args should not be present if programArguments is nil
    EXPECT_EQ(row.count("args"), 0U);
  }
}

TEST_F(StartupItemsTests, test_parseItem_empty_program_arguments) {
  @autoreleasepool {
    MockBTMItem* item = [[MockBTMItem alloc] init];
    item.type = @(0x00004); // LoginItem
    item.programArguments = @[];

    QueryData results;
    parseItem("testuser", item, results);

    ASSERT_EQ(results.size(), 1U);
    const Row& row = results[0];

    // args should not be present if programArguments is empty
    EXPECT_EQ(row.count("args"), 0U);
  }
}

TEST_F(StartupItemsTests, test_parseItem_mixed_program_arguments) {
  @autoreleasepool {
    MockBTMItem* item = [[MockBTMItem alloc] init];
    item.type = @(0x00008); // Agent flag
    // Mix of NSString and other types - only NSStrings should be included
    item.programArguments = @[ @"/bin/sh", @(123), @"-c", @"echo test" ];

    QueryData results;
    parseItem("testuser", item, results);

    ASSERT_EQ(results.size(), 1U);
    const Row& row = results[0];

    // Only string arguments should be included
    EXPECT_EQ(row.at("args"), "/bin/sh -c echo test");
  }
}

} // namespace tables
} // namespace osquery
