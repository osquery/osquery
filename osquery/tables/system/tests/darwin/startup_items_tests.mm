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

#include <boost/filesystem.hpp>

#include <osquery/core/sql/query_data.h>
#include <osquery/core/tables.h>
#include <osquery/tables/system/darwin/startup_items.h>

namespace fs = boost::filesystem;

// Mock Objective-C classes that mimic the BTM item and user store structures
// Must be at global scope (Objective-C declarations cannot be in C++
// namespaces)
@interface MockBTMItem : NSObject<NSSecureCoding>
@property(nonatomic, strong) NSNumber* type;
@property(nonatomic, strong) NSString* name;
@property(nonatomic, strong) NSNumber* disposition;
@property(nonatomic, strong) NSURL* url;
@property(nonatomic, strong) NSArray* programArguments;
@end

@implementation MockBTMItem
+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:self.type forKey:@"type"];
  [coder encodeObject:self.name forKey:@"name"];
  [coder encodeObject:self.disposition forKey:@"disposition"];
  [coder encodeObject:self.url forKey:@"url"];
  [coder encodeObject:self.programArguments forKey:@"programArguments"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  if (self = [super init]) {
    self.type = [coder decodeObjectOfClass:[NSNumber class] forKey:@"type"];
    self.name = [coder decodeObjectOfClass:[NSString class] forKey:@"name"];
    self.disposition = [coder decodeObjectOfClass:[NSNumber class]
                                           forKey:@"disposition"];
    self.url = [coder decodeObjectOfClass:[NSURL class] forKey:@"url"];
    self.programArguments =
        [coder decodeObjectOfClasses:[NSSet setWithObjects:[NSArray class],
                                                           [NSString class],
                                                           nil]
                              forKey:@"programArguments"];
  }
  return self;
}
@end

@interface MockBTMUserStore : NSObject<NSSecureCoding>
@property(nonatomic, strong) NSArray* records;
@end

@implementation MockBTMUserStore
+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:self.records forKey:@"records"];
}

- (instancetype)initWithCoder:(NSCoder*)coder {
  if (self = [super init]) {
    self.records =
        [coder decodeObjectOfClasses:[NSSet setWithObjects:[NSArray class],
                                                           [MockBTMItem class],
                                                           nil]
                              forKey:@"records"];
  }
  return self;
}
@end

namespace osquery {
namespace tables {

// Forward declarations of the Objective-C helpers under test
void parseItem(const std::string& username, id item, QueryData& results);
void parseUserStore(const std::string& username,
                    id userStore,
                    QueryData& results);
id decodeBtmArchive(const std::string& path, Class cls, NSString* key);

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

TEST_F(StartupItemsTests, test_selectBtmDatabaseFiles_global_archive) {
  auto files = selectBtmDatabaseFiles({
      "BackgroundItems-v13.btm",
      "BackgroundItems-v16.btm",
  });

  EXPECT_EQ(files.global_filename, "BackgroundItems-v16.btm");
  EXPECT_TRUE(files.user_store_files.empty());
}

TEST_F(StartupItemsTests, test_selectBtmDatabaseFiles_user_store_archives) {
  // Directory listing from a Mac upgraded to macOS 27
  auto files = selectBtmDatabaseFiles({
      "BackgroundItems-v18-FFFFEEEE-DDDD-CCCC-BBBB-AAAAFFFFFFFE.btm",
      "BackgroundItems-v13.btm",
      "BackgroundItems-v18-E7923D33-0FD2-415A-8FFA-25FB57874B5C.btm",
      "BackgroundItems-v16.btm",
      "BackgroundItems-v18.btm",
      "BackgroundItems-v18-FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000.btm",
  });

  EXPECT_EQ(files.global_filename, "BackgroundItems-v18.btm");
  ASSERT_EQ(files.user_store_files.size(), 3U);
  EXPECT_EQ(files.user_store_files[0].filename,
            "BackgroundItems-v18-FFFFEEEE-DDDD-CCCC-BBBB-AAAAFFFFFFFE.btm");
  EXPECT_EQ(files.user_store_files[0].user_identifier,
            "FFFFEEEE-DDDD-CCCC-BBBB-AAAAFFFFFFFE");
  EXPECT_EQ(files.user_store_files[1].user_identifier,
            "E7923D33-0FD2-415A-8FFA-25FB57874B5C");
  EXPECT_EQ(files.user_store_files[2].user_identifier,
            "FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000");
}

TEST_F(StartupItemsTests, test_selectBtmDatabaseFiles_ignores_older_versions) {
  // Listing order must not matter
  for (const auto& filenames : std::vector<std::vector<std::string>>{
           {"BackgroundItems-v18-E7923D33-0FD2-415A-8FFA-25FB57874B5C.btm",
            "BackgroundItems-v19.btm"},
           {"BackgroundItems-v19.btm",
            "BackgroundItems-v18-E7923D33-0FD2-415A-8FFA-25FB57874B5C.btm"},
       }) {
    auto files = selectBtmDatabaseFiles(filenames);

    EXPECT_EQ(files.global_filename, "BackgroundItems-v19.btm");
    EXPECT_TRUE(files.user_store_files.empty());
  }
}

TEST_F(StartupItemsTests, test_selectBtmDatabaseFiles_numeric_versions) {
  auto files = selectBtmDatabaseFiles({
      "BackgroundItems-v13.btm",
      "BackgroundItems-v9.btm",
  });

  EXPECT_EQ(files.global_filename, "BackgroundItems-v13.btm");
}

TEST_F(StartupItemsTests, test_selectBtmDatabaseFiles_ignores_other_files) {
  auto files = selectBtmDatabaseFiles({
      ".DS_Store",
      "other.btm",
      "BackgroundItems-vX.btm",
      "BackgroundItems-v18-.btm",
      "BackgroundItems-v18.btm.tmp",
  });

  EXPECT_TRUE(files.global_filename.empty());
  EXPECT_TRUE(files.user_store_files.empty());
}

TEST_F(StartupItemsTests, test_parseUserStore_nil_store) {
  QueryData results;
  parseUserStore("testuser", nil, results);
  EXPECT_EQ(results.size(), 0U);
}

TEST_F(StartupItemsTests, test_parseUserStore_records) {
  @autoreleasepool {
    MockBTMItem* loginItem = [[MockBTMItem alloc] init];
    loginItem.type = @(0x00004); // LoginItem
    loginItem.name = @"TestApp";

    MockBTMItem* developerItem = [[MockBTMItem alloc] init];
    developerItem.type = @(0x00020); // Developer

    MockBTMUserStore* userStore = [[MockBTMUserStore alloc] init];
    userStore.records = @[ loginItem, developerItem ];

    QueryData results;
    parseUserStore("testuser", userStore, results);

    ASSERT_EQ(results.size(), 1U);
    EXPECT_EQ(results[0].at("username"), "testuser");
    EXPECT_EQ(results[0].at("name"), "TestApp");
    EXPECT_EQ(results[0].at("type"), "login item");
  }
}

class StartupItemsArchiveTests : public testing::Test {
 protected:
  void SetUp() override {
    temp_dir_ = fs::temp_directory_path() /
                fs::unique_path("osquery_startup_items_%%%%-%%%%-%%%%-%%%%");
    fs::create_directories(temp_dir_);
  }

  void TearDown() override {
    fs::remove_all(temp_dir_);
  }

  // Archive a user store with a single login item under the "userStore" key,
  // like a version 18 BackgroundItems-v18-<uuid>.btm file
  std::string writeUserStoreArchive() {
    MockBTMItem* item = [[MockBTMItem alloc] init];
    item.type = @(0x00004); // LoginItem
    item.name = @"TestApp";
    item.disposition = @(0x03); // Enabled | Allowed
    item.url = [NSURL fileURLWithPath:@"/Applications/TestApp.app"];

    MockBTMUserStore* userStore = [[MockBTMUserStore alloc] init];
    userStore.records = @[ item ];

    NSKeyedArchiver* archiver =
        [[NSKeyedArchiver alloc] initRequiringSecureCoding:YES];
    [archiver encodeObject:userStore forKey:@"userStore"];
    [archiver finishEncoding];

    auto path = (temp_dir_ / "BackgroundItems-v18-UUID.btm").string();
    [archiver.encodedData
        writeToFile:[NSString stringWithUTF8String:path.c_str()]
         atomically:YES];
    return path;
  }

  fs::path temp_dir_;
};

TEST_F(StartupItemsArchiveTests, test_decodeBtmArchive_user_store) {
  @autoreleasepool {
    auto path = writeUserStoreArchive();

    id userStore =
        decodeBtmArchive(path, [MockBTMUserStore class], @"userStore");
    ASSERT_TRUE(userStore != nil);

    QueryData results;
    parseUserStore("testuser", userStore, results);

    ASSERT_EQ(results.size(), 1U);
    const Row& row = results[0];
    EXPECT_EQ(row.at("username"), "testuser");
    EXPECT_EQ(row.at("name"), "TestApp");
    EXPECT_EQ(row.at("type"), "login item");
    EXPECT_EQ(row.at("status"), "enabled, allowed");
    EXPECT_EQ(row.at("path"), "/Applications/TestApp.app");
  }
}

TEST_F(StartupItemsArchiveTests, test_decodeBtmArchive_missing_key) {
  @autoreleasepool {
    // Version 18 archives have no "store" key, which used to make the table
    // return no BTM items
    auto path = writeUserStoreArchive();

    EXPECT_TRUE(decodeBtmArchive(path, [MockBTMUserStore class], @"store") ==
                nil);
  }
}

TEST_F(StartupItemsArchiveTests, test_decodeBtmArchive_wrong_class) {
  @autoreleasepool {
    auto path = writeUserStoreArchive();

    EXPECT_TRUE(decodeBtmArchive(path, [MockBTMItem class], @"userStore") ==
                nil);
  }
}

TEST_F(StartupItemsArchiveTests, test_decodeBtmArchive_missing_file) {
  @autoreleasepool {
    auto path = (temp_dir_ / "missing.btm").string();

    EXPECT_TRUE(
        decodeBtmArchive(path, [MockBTMUserStore class], @"userStore") == nil);
  }
}

} // namespace tables
} // namespace osquery
