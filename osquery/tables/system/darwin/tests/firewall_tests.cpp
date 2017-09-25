/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/tables/system/darwin/firewall.h"
#include "osquery/tests/test_util.h"

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

pt::ptree getALFTree() {
  std::string content;
  readFile(kTestDataPath + "test_alf.plist", content);

  pt::ptree tree;
  parsePlistContent(content, tree);
  return tree;
}

class FirewallTests : public testing::Test {};

TEST_F(FirewallTests, test_parse_alf_tree) {
  pt::ptree tree = getALFTree();
  auto results = parseALFTree(tree);
  osquery::QueryData expected = {
      {
          {"allow_signed_enabled", "1"},
          {"firewall_unload", "0"},
          {"global_state", "0"},
          {"logging_enabled", "0"},
          {"logging_option", "0"},
          {"stealth_enabled", "0"},
          {"version", "1.0a25"},
      },
  };
  EXPECT_EQ(results, expected);
}

TEST_F(FirewallTests, test_parse_alf_exceptions_tree) {
  pt::ptree tree = getALFTree();
  auto results = parseALFExceptionsTree(tree);
  osquery::QueryData expected = {
      {{"path", "/usr/libexec/configd"}, {"state", "3"}},
      {{"path", "/usr/sbin/mDNSResponder"}, {"state", "3"}},
      {{"path", "/usr/sbin/racoon"}, {"state", "3"}},
      {{"path", "/usr/bin/nmblookup"}, {"state", "3"}},
      {{"path",
        "/System/Library/PrivateFrameworks/Admin.framework/Versions/A/"
        "Resources/readconfig"},
       {"state", "3"}},
  };
  EXPECT_EQ(results, expected);
}

TEST_F(FirewallTests, test_parse_alf_explicit_auths_tree) {
  pt::ptree tree = getALFTree();
  auto results = parseALFExplicitAuthsTree(tree);
  osquery::QueryData expected = {
      {{"process", "org.python.python.app"}},
      {{"process", "com.apple.ruby"}},
      {{"process", "com.apple.a2p"}},
      {{"process", "com.apple.javajdk16.cmd"}},
      {{"process", "com.apple.php"}},
      {{"process", "com.apple.nc"}},
      {{"process", "com.apple.ksh"}},
  };
  EXPECT_EQ(results, expected);
}

TEST_F(FirewallTests, test_parse_alf_services_tree) {
  pt::ptree tree = getALFTree();
  auto results = parseALFServicesTree(tree);
  osquery::QueryData expected = {
      {
          {"service", "Apple Remote Desktop"},
          {"process", "AppleVNCServer"},
          {"state", "0"},
      },
      {
          {"service", "FTP"}, {"process", "ftpd"}, {"state", "0"},
      },
      {
          {"service", "ODSAgent"}, {"process", "ODSAgent"}, {"state", "0"},
      },
      {
          {"service", "File Sharing"},
          {"process", "AppleFileServer"},
          {"state", "0"},
      },
      {
          {"service", "Web Sharing"}, {"process", "httpd"}, {"state", "0"},
      },
      {
          {"service", "Printer Sharing"}, {"process", "cupsd"}, {"state", "0"},
      },
      {
          {"service", "Remote Apple Events"},
          {"process", "AEServer"},
          {"state", "0"},
      },
      {
          {"service", "SSH"},
          {"process", "sshd-keygen-wrapper"},
          {"state", "0"},
      },
      {
          {"service", "Samba Sharing"}, {"process", "smbd"}, {"state", "0"},
      },
  };
  EXPECT_EQ(results, expected);
}

TEST_F(FirewallTests, test_errors) {
  pt::ptree tree = getALFTree();
  auto results = parseALFTree(tree);
  ASSERT_THROW(tree.get<int>("foo"), pt::ptree_error);
  ASSERT_THROW(tree.get<int>("version"), pt::ptree_error);
  ASSERT_THROW(tree.get<int>("version"), pt::ptree_bad_data);
  ASSERT_THROW(tree.get_child("foo"), pt::ptree_error);
  ASSERT_THROW(tree.get_child("foo"), pt::ptree_bad_path);
}

TEST_F(FirewallTests, test_on_disk_format) {
  pt::ptree tree;
  auto s = osquery::parsePlist(kALFPlistPath, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  for (const auto& it : kTopLevelIntKeys) {
    EXPECT_NO_THROW(tree.get<int>(it.first));
  }
  for (const auto& it : kTopLevelStringKeys) {
    EXPECT_NO_THROW(tree.get<std::string>(it.first));
  }
  EXPECT_NO_THROW(tree.get_child("firewall"));
}
}
}
