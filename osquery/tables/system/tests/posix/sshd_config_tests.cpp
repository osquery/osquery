/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/system/posix/sshd_config.h>

namespace osquery {
namespace tables {

class SshdConfig : public testing::Test {};

TEST_F(SshdConfig, parseLine) {
  struct TestCase {
    std::string name;
    std::string line;
    std::string match;
    std::string path;
    Row want;
  };

  TestCase testCases[] = {
      {"TestMatch",
       "Match User anoncvs",
       "",
       "/foo/bar/baz",
       Row({{"keyword", "Match/User"},
            {"argument", "anoncvs"},
            {"match", "User anoncvs"},
            {"path", "/foo/bar/baz"}})},
      {"TestMatchArgSpace",
       "Match User anon cvs",
       "",
       "/foo/bar/baz",
       Row({{"keyword", "Match/User"},
            {"argument", "anon cvs"},
            {"match", "User anon cvs"},
            {"path", "/foo/bar/baz"}})},
      {"TestMatchMissingArgs",
       "Match",
       "",
       "/foo/bar/baz",
       Row({{"keyword", "Match"},
            {"argument", ""},
            {"match", ""},
            {"path", "/foo/bar/baz"}})},
      {"TestMatchMissingUser",
       "Match User",
       "",
       "/foo/bar/baz",
       Row({{"keyword", "Match/User"},
            {"argument", ""},
            {"match", "User"},
            {"path", "/foo/bar/baz"}})},
      {"TestStandard",
       "X11Forwarding no",
       "User foobar",
       "/baz/bar/foo",
       Row({{"keyword", "X11Forwarding"},
            {"argument", "no"},
            {"match", "User foobar"},
            {"path", "/baz/bar/foo"}})},
      {"TestSubsystem",
       "Subsystem       sftp    /usr/lib/openssh/sftp-server",
       "",
       "/foo/bar",
       Row({{"keyword", "Subsystem/sftp"},
            {"argument", "/usr/lib/openssh/sftp-server"},
            {"match", ""},
            {"path", "/foo/bar"}})},
      {"TestSubsystemArgSpace",
       "Subsystem       sftp    /usr/lib/open ssh/sftp-server",
       "",
       "/foo/bar",
       Row({{"keyword", "Subsystem/sftp"},
            {"argument", "/usr/lib/open ssh/sftp-server"},
            {"match", ""},
            {"path", "/foo/bar"}})},
      {"TestSubsystemMissingArgs",
       "Subsystem",
       "",
       "/foo/bar",
       Row({{"keyword", "Subsystem"},
            {"argument", ""},
            {"match", ""},
            {"path", "/foo/bar"}})},
      {"TestSubsystemMissingPath",
       "Subsystem       sftp",
       "",
       "/foo/bar",
       Row({{"keyword", "Subsystem/sftp"},
            {"argument", ""},
            {"match", ""},
            {"path", "/foo/bar"}})},
      {"TestTwoArgs",
       "AcceptEnv LANG LC_*",
       "",
       "",
       Row({{"keyword", "AcceptEnv"},
            {"argument", "LANG LC_*"},
            {"match", ""},
            {"path", ""}})},
      {"TestTrailingComment",
       "Port 22 # listen port",
       "",
       "/foo/bar/baz",
       Row({{"keyword", "Port"},
            {"argument", "22"},
            {"match", ""},
            {"path", "/foo/bar/baz"}})},
      {"TestTrailingCommentOnMatch",
       "Match User admin # prod only",
       "",
       "/foo/bar/baz",
       Row({{"keyword", "Match/User"},
            {"argument", "admin"},
            {"match", "User admin"},
            {"path", "/foo/bar/baz"}})},
      {"TestLiteralHash",
       "Banner /etc/motd#1",
       "",
       "/foo/bar/baz",
       Row({{"keyword", "Banner"},
            {"argument", "/etc/motd#1"},
            {"match", ""},
            {"path", "/foo/bar/baz"}})},
      {"TestEqualsSeparator",
       "PasswordAuthentication=no",
       "",
       "/foo/bar/baz",
       Row({{"keyword", "PasswordAuthentication"},
            {"argument", "no"},
            {"match", ""},
            {"path", "/foo/bar/baz"}})},
      {"TestEqualsSeparatorSpaced",
       "PasswordAuthentication = no",
       "",
       "/foo/bar/baz",
       Row({{"keyword", "PasswordAuthentication"},
            {"argument", "no"},
            {"match", ""},
            {"path", "/foo/bar/baz"}})},
      {"TestQuotedArgumentWhitespace",
       "Subsystem sftp \"/srv/two  spaces\"",
       "",
       "/foo/bar/baz",
       Row({{"keyword", "Subsystem/sftp"},
            {"argument", "\"/srv/two  spaces\""},
            {"match", ""},
            {"path", "/foo/bar/baz"}})},
      {"TestHashInQuotesIsLiteral",
       "Banner \"/etc/a # b\"",
       "",
       "/foo/bar/baz",
       Row({{"keyword", "Banner"},
            {"argument", "\"/etc/a # b\""},
            {"match", ""},
            {"path", "/foo/bar/baz"}})}};

  for (TestCase tc : testCases) {
    Row got = sshdconfig::parseLine(tc.line, tc.match, tc.path);

    ASSERT_EQ(got, tc.want) << "Test Case Failed: " << tc.name;
  }
}

TEST_F(SshdConfig, parseContent) {
  struct TestCase {
    std::string name;
    std::string content;
    std::string path;
    QueryData want;
  };

  TestCase testCases[] = {
      {"ContentWithEOL",
       R"(# override default of no subsystems
Subsystem       sftp    /usr/lib/openssh/sftp-server

# Allow client to pass locale environment variables
                 AcceptEnv LANG LC_*            
Match User anoncvs
        X11Forwarding no

Match Group L33T
        X11Forwarding yes
)",
       "/foo/bar/baz",
       QueryData({{{"keyword", "Subsystem/sftp"},
                   {"argument", "/usr/lib/openssh/sftp-server"},
                   {"match", ""},
                   {"path", "/foo/bar/baz"}},
                  {{"keyword", "AcceptEnv"},
                   {"argument", "LANG LC_*"},
                   {"match", ""},
                   {"path", "/foo/bar/baz"}},
                  {{"keyword", "Match/User"},
                   {"argument", "anoncvs"},
                   {"match", "User anoncvs"},
                   {"path", "/foo/bar/baz"}},
                  {{"keyword", "X11Forwarding"},
                   {"argument", "no"},
                   {"match", "User anoncvs"},
                   {"path", "/foo/bar/baz"}},
                  {{"keyword", "Match/Group"},
                   {"argument", "L33T"},
                   {"match", "Group L33T"},
                   {"path", "/foo/bar/baz"}},
                  {{"keyword", "X11Forwarding"},
                   {"argument", "yes"},
                   {"match", "Group L33T"},
                   {"path", "/foo/bar/baz"}}})},
      {"ContentWithoutEOL",
       R"(# override default of no subsystems
Subsystem       sftp    /usr/lib/openssh/sftp-server
AcceptEnv LANG LC_*)",
       "/foo/bar/baz",
       QueryData({{{"keyword", "Subsystem/sftp"},
                   {"argument", "/usr/lib/openssh/sftp-server"},
                   {"match", ""},
                   {"path", "/foo/bar/baz"}},
                  {{"keyword", "AcceptEnv"},
                   {"argument", "LANG LC_*"},
                   {"match", ""},
                   {"path", "/foo/bar/baz"}}})}};

  for (TestCase tc : testCases) {
    QueryData got;

    sshdconfig::parseContent(tc.content, tc.path, got);

    ASSERT_EQ(got, tc.want) << "Test Case Failed: " << tc.name;
  }
}

} // namespace tables
} // namespace osquery
