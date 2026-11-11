/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

// Forward-declare the parsing function under test.
void parseDesktopEntry(const std::string& content, Row& r);

class StartupItemsTests : public testing::Test {};

TEST_F(StartupItemsTests, desktop_entry_simple) {
  const std::string content =
      "[Desktop Entry]\n"
      "Type=Application\n"
      "Name=Example\n"
      "Exec=/usr/bin/example --autostart\n";

  Row r;
  parseDesktopEntry(content, r);
  EXPECT_EQ(r["name"], "Example");
  EXPECT_EQ(r["path"], "/usr/bin/example --autostart");
}

TEST_F(StartupItemsTests, desktop_entry_value_with_equals) {
  const std::string content =
      "[Desktop Entry]\n"
      "Name=Example\n"
      "Exec=env GDK_BACKEND=x11 /usr/bin/example --mode=tray\n";

  Row r;
  parseDesktopEntry(content, r);
  EXPECT_EQ(r["name"], "Example");
  EXPECT_EQ(r["path"], "env GDK_BACKEND=x11 /usr/bin/example --mode=tray");
}

TEST_F(StartupItemsTests, desktop_entry_spaces_around_equals) {
  const std::string content =
      "[Desktop Entry]\n"
      "Name = Example\n"
      "Exec = /usr/bin/example\n";

  Row r;
  parseDesktopEntry(content, r);
  EXPECT_EQ(r["name"], "Example");
  EXPECT_EQ(r["path"], "/usr/bin/example");
}

TEST_F(StartupItemsTests, desktop_entry_ignores_other_groups) {
  const std::string content =
      "# comment line\n"
      "[Desktop Entry]\n"
      "Name=Example\n"
      "Name[de]=Beispiel\n"
      "Exec=/usr/bin/example\n"
      "Actions=new-window;\n"
      "\n"
      "[Desktop Action new-window]\n"
      "Name=New Window\n"
      "Exec=/usr/bin/example --new-window\n";

  Row r;
  parseDesktopEntry(content, r);
  EXPECT_EQ(r["name"], "Example");
  EXPECT_EQ(r["path"], "/usr/bin/example");
}

TEST_F(StartupItemsTests, desktop_entry_crlf_line_endings) {
  const std::string content =
      "[Desktop Entry]\r\n"
      "Name=Example\r\n"
      "Exec=/usr/bin/example --autostart\r\n"
      "\r\n"
      "[Desktop Action new-window]\r\n"
      "Name=New Window\r\n"
      "Exec=/usr/bin/example --new-window\r\n";

  Row r;
  parseDesktopEntry(content, r);
  EXPECT_EQ(r["name"], "Example");
  EXPECT_EQ(r["path"], "/usr/bin/example --autostart");
}

TEST_F(StartupItemsTests, desktop_entry_group_header_trailing_spaces) {
  const std::string content =
      "[Desktop Entry]  \n"
      "Name=Example\n"
      "Exec=/usr/bin/example\n";

  Row r;
  parseDesktopEntry(content, r);
  EXPECT_EQ(r["name"], "Example");
  EXPECT_EQ(r["path"], "/usr/bin/example");
}

TEST_F(StartupItemsTests, desktop_entry_missing_group_header) {
  const std::string content =
      "Name=Example\n"
      "Exec=/usr/bin/example\n";

  Row r;
  parseDesktopEntry(content, r);
  EXPECT_EQ(r["name"], "Example");
  EXPECT_EQ(r["path"], "/usr/bin/example");
}

TEST_F(StartupItemsTests, desktop_entry_no_name_or_exec) {
  const std::string content =
      "[Desktop Entry]\n"
      "Type=Application\n"
      "Hidden=true\n";

  Row r;
  parseDesktopEntry(content, r);
  EXPECT_EQ(r.count("name"), 0U);
  EXPECT_EQ(r.count("path"), 0U);
}

} // namespace tables
} // namespace osquery
