/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */


#include <fstream>

#include <stdio.h>

#include <gtest/gtest.h>

#include <boost/property_tree/ptree.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>

namespace pt = boost::property_tree;

namespace osquery {

class FilesystemTests : public testing::Test {};

TEST_F(FilesystemTests, test_plugin) {
  std::ofstream test_file("/tmp/osquery-test-file");
  test_file.write("test123\n", sizeof("test123"));
  test_file.close();

  std::string content;
  auto s = readFile("/tmp/osquery-test-file", content);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(content, "test123\n");

  remove("/tmp/osquery-test-file");
}

TEST_F(FilesystemTests, test_list_files_in_directory_not_found) {
  std::vector<std::string> not_found_vector;
  auto not_found = listFilesInDirectory("/foo/bar", not_found_vector);
  EXPECT_FALSE(not_found.ok());
  EXPECT_EQ(not_found.toString(), "Directory not found: /foo/bar");
}

TEST_F(FilesystemTests, test_list_files_in_directory_not_dir) {
  std::vector<std::string> not_dir_vector;
  auto not_dir = listFilesInDirectory("/etc/hosts", not_dir_vector);
  EXPECT_FALSE(not_dir.ok());
  EXPECT_EQ(not_dir.toString(), "Supplied path is not a directory: /etc/hosts");
}

TEST_F(FilesystemTests, test_list_files_in_directorty) {
  std::vector<std::string> results;
  auto s = listFilesInDirectory("/etc", results);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_NE(std::find(results.begin(), results.end(), "/etc/hosts"),
            results.end());
}

TEST_F(FilesystemTests, test_parse_tomcat_user_config) {
  // clang-format off
  std::string config_content = R"(
<?xml version='1.0' encoding='utf-8'?>
<!--
  Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<tomcat-users>
<!--
  NOTE:  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary.
-->
<!--
  NOTE:  The sample user and role entries below are wrapped in a comment
  and thus are ignored when reading this file. Do not forget to remove
  <!.. ..> that surrounds them.
-->
  <role rolename="tomcat"/>
  <user username="tomcat" password="tomcat" roles="tomcat"/>
</tomcat-users>
)";
  // clang-format on

  std::vector<std::pair<std::string, std::string>> credentials;
  auto s = parseTomcatUserConfig(config_content, credentials);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(credentials.size(), (size_t)1);
  EXPECT_EQ(credentials[0].first, "tomcat");
  EXPECT_EQ(credentials[0].second, "tomcat");
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
