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

Row parsePacmanDesc(const std::string& content);

class PacmanPackagesTests : public testing::Test {};

TEST_F(PacmanPackagesTests, parses_a_complete_entry) {
  auto r = parsePacmanDesc(
      "%NAME%\n"
      "gvfs\n"
      "\n"
      "%VERSION%\n"
      "1.60.1-1\n"
      "\n"
      "%BASE%\n"
      "gvfs\n"
      "\n"
      "%DESC%\n"
      "Virtual filesystem implementation for GIO\n"
      "\n"
      "%URL%\n"
      "https://gitlab.gnome.org/GNOME/gvfs\n"
      "\n"
      "%ARCH%\n"
      "x86_64\n"
      "\n"
      "%BUILDDATE%\n"
      "1782428050\n"
      "\n"
      "%INSTALLDATE%\n"
      "1784305014\n"
      "\n"
      "%PACKAGER%\n"
      "Jan Alexander Steffens (heftig) <heftig@archlinux.org>\n"
      "\n"
      "%SIZE%\n"
      "5504179\n"
      "\n"
      "%REASON%\n"
      "1\n"
      "\n"
      "%GROUPS%\n"
      "gnome\n"
      "\n"
      "%LICENSE%\n"
      "LGPL-2.0-only\n"
      "\n"
      "%VALIDATION%\n"
      "pgp\n");

  EXPECT_EQ(r["name"], "gvfs");
  EXPECT_EQ(r["version"], "1.60.1-1");
  EXPECT_EQ(r["source"], "gvfs");
  EXPECT_EQ(r["description"], "Virtual filesystem implementation for GIO");
  EXPECT_EQ(r["url"], "https://gitlab.gnome.org/GNOME/gvfs");
  EXPECT_EQ(r["arch"], "x86_64");
  EXPECT_EQ(r["build_time"], "1782428050");
  EXPECT_EQ(r["install_time"], "1784305014");
  EXPECT_EQ(r["packager"],
            "Jan Alexander Steffens (heftig) <heftig@archlinux.org>");
  EXPECT_EQ(r["size"], "5504179");
  EXPECT_EQ(r["install_reason"], "dependency");
  EXPECT_EQ(r["groups"], "gnome");
  EXPECT_EQ(r["licenses"], "LGPL-2.0-only");
  EXPECT_EQ(r["validation"], "pgp");
}

TEST_F(PacmanPackagesTests, joins_fields_holding_several_values) {
  auto r = parsePacmanDesc(
      "%NAME%\n"
      "example\n"
      "\n"
      "%LICENSE%\n"
      "GPL2\n"
      "custom\n"
      "\n"
      "%VALIDATION%\n"
      "sha256\n"
      "pgp\n"
      "\n"
      "%GROUPS%\n"
      "base-devel\n"
      "gnome\n");

  EXPECT_EQ(r["licenses"], "GPL2,custom");
  EXPECT_EQ(r["validation"], "sha256,pgp");
  EXPECT_EQ(r["groups"], "base-devel,gnome");
}

TEST_F(PacmanPackagesTests, takes_only_the_first_line_of_a_single_value_field) {
  // libalpm reads one line for these fields. Joining extra lines would put a
  // list into a column that is meant to hold a single, and here numeric, value.
  auto r = parsePacmanDesc(
      "%NAME%\n"
      "example\n"
      "\n"
      "%SIZE%\n"
      "123\n"
      "456\n"
      "\n"
      "%DESC%\n"
      "first line\n"
      "second line\n");

  EXPECT_EQ(r["size"], "123");
  EXPECT_EQ(r["description"], "first line");
}

TEST_F(PacmanPackagesTests, a_missing_reason_means_explicitly_installed) {
  auto r = parsePacmanDesc(
      "%NAME%\n"
      "example\n"
      "\n"
      "%VERSION%\n"
      "1.0-1\n");

  EXPECT_EQ(r["install_reason"], "explicit");
}

TEST_F(PacmanPackagesTests, a_recorded_reason_of_zero_is_explicit) {
  auto r = parsePacmanDesc(
      "%NAME%\n"
      "example\n"
      "\n"
      "%REASON%\n"
      "0\n");

  EXPECT_EQ(r["install_reason"], "explicit");
}

TEST_F(PacmanPackagesTests, an_unrecognized_reason_is_left_empty) {
  auto r = parsePacmanDesc(
      "%NAME%\n"
      "example\n"
      "\n"
      "%REASON%\n"
      "7\n");

  EXPECT_EQ(r["name"], "example");
  EXPECT_EQ(r["install_reason"], "");
}

TEST_F(PacmanPackagesTests, keeps_an_epoch_in_the_version) {
  auto r = parsePacmanDesc(
      "%NAME%\n"
      "example\n"
      "\n"
      "%VERSION%\n"
      "2:2.4.19-1\n");

  EXPECT_EQ(r["version"], "2:2.4.19-1");
}

TEST_F(PacmanPackagesTests, reports_a_missing_size_as_zero) {
  // Metapackages such as 'base' install no files and record no size, which
  // libalpm reports as zero.
  auto r = parsePacmanDesc(
      "%NAME%\n"
      "base\n"
      "\n"
      "%VERSION%\n"
      "3-3\n");

  EXPECT_EQ(r["name"], "base");
  EXPECT_EQ(r["size"], "0");
}

TEST_F(PacmanPackagesTests, skips_keys_that_are_not_mapped_to_a_column) {
  // A field this table does not expose must not have its values folded into
  // whichever field happens to follow it.
  auto r = parsePacmanDesc(
      "%NAME%\n"
      "example\n"
      "\n"
      "%DEPENDS%\n"
      "glibc\n"
      "libgcc\n"
      "\n"
      "%XDATA%\n"
      "pkgtype=pkg\n"
      "\n"
      "%ARCH%\n"
      "x86_64\n");

  EXPECT_EQ(r["name"], "example");
  EXPECT_EQ(r["arch"], "x86_64");
  EXPECT_EQ(r.count("depends"), 0U);
  EXPECT_EQ(r.count("xdata"), 0U);
}

TEST_F(PacmanPackagesTests, skips_an_unknown_key_from_a_newer_database) {
  auto r = parsePacmanDesc(
      "%NAME%\n"
      "example\n"
      "\n"
      "%SOMETHINGNEW%\n"
      "surprising\n"
      "\n"
      "%VERSION%\n"
      "1.0-1\n");

  EXPECT_EQ(r["name"], "example");
  EXPECT_EQ(r["version"], "1.0-1");
}

TEST_F(PacmanPackagesTests, parses_an_entry_without_blank_separators) {
  // libalpm ends a list at a blank line. Reading a field up to the next key
  // instead gives the same result for the entries pacman writes, and still
  // parses one that was written without the usual blank line between fields.
  auto r = parsePacmanDesc(
      "%NAME%\n"
      "example\n"
      "%VERSION%\n"
      "1.0-1\n"
      "%ARCH%\n"
      "any\n");

  EXPECT_EQ(r["name"], "example");
  EXPECT_EQ(r["version"], "1.0-1");
  EXPECT_EQ(r["arch"], "any");
}

TEST_F(PacmanPackagesTests, ignores_lines_holding_only_whitespace) {
  // A blank line written with CRLF endings reaches the parser as whitespace
  // and must not be recorded as an additional value for the current field.
  auto r = parsePacmanDesc(
      "%NAME%\r\n"
      "example\r\n"
      "\r\n"
      "%VERSION%\r\n"
      "1.0-1\r\n");

  EXPECT_EQ(r["name"], "example");
  EXPECT_EQ(r["version"], "1.0-1");
}

TEST_F(PacmanPackagesTests,
       returns_nothing_useful_for_an_entry_without_a_name) {
  // An interrupted transaction can leave a database entry behind that does not
  // describe an installed package.
  auto r = parsePacmanDesc(
      "%VERSION%\n"
      "1.0-1\n");

  EXPECT_EQ(r.count("name"), 0U);
}

TEST_F(PacmanPackagesTests, returns_nothing_useful_for_empty_content) {
  auto r = parsePacmanDesc("");

  EXPECT_EQ(r.count("name"), 0U);
}

TEST_F(PacmanPackagesTests, ignores_values_before_any_key) {
  auto r = parsePacmanDesc(
      "stray\n"
      "%NAME%\n"
      "example\n");

  EXPECT_EQ(r["name"], "example");
}
} // namespace tables
} // namespace osquery
