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

// Forward-declare the parsing functions under test.
std::unordered_map<std::string, std::string> parseFlatpakMetadata(
    const std::string& content);
void parseFlatpakAppStream(const std::string& content, Row& r);

class FlatpakPackagesTests : public testing::Test {};

// ---------------------------------------------------------------------------
// parseFlatpakMetadata tests
// ---------------------------------------------------------------------------

TEST_F(FlatpakPackagesTests, metadata_parses_application_section) {
  const std::string content =
      "[Application]\n"
      "name=org.gnome.Gedit\n"
      "runtime=org.gnome.Platform/x86_64/46\n"
      "sdk=org.gnome.Sdk/x86_64/46\n"
      "command=gedit\n";

  const auto meta = parseFlatpakMetadata(content);
  EXPECT_EQ(meta.at("Application.name"), "org.gnome.Gedit");
  EXPECT_EQ(meta.at("Application.runtime"), "org.gnome.Platform/x86_64/46");
  EXPECT_EQ(meta.at("Application.sdk"), "org.gnome.Sdk/x86_64/46");
  EXPECT_EQ(meta.at("Application.command"), "gedit");
}

TEST_F(FlatpakPackagesTests, metadata_parses_runtime_section) {
  const std::string content =
      "[Runtime]\n"
      "name=org.freedesktop.Platform\n"
      "runtime=org.freedesktop.Platform/x86_64/23.08\n"
      "sdk=org.freedesktop.Sdk/x86_64/23.08\n";

  const auto meta = parseFlatpakMetadata(content);
  EXPECT_EQ(meta.at("Runtime.name"), "org.freedesktop.Platform");
  EXPECT_EQ(meta.at("Runtime.runtime"),
            "org.freedesktop.Platform/x86_64/23.08");
}

TEST_F(FlatpakPackagesTests, metadata_ignores_comments) {
  const std::string content =
      "# This is a comment\n"
      "[Application]\n"
      "; another comment style\n"
      "name=org.example.App\n";

  const auto meta = parseFlatpakMetadata(content);
  EXPECT_EQ(meta.at("Application.name"), "org.example.App");
  EXPECT_EQ(meta.count("# This is a comment"), 0u);
}

TEST_F(FlatpakPackagesTests, metadata_ignores_locale_specific_keys) {
  // Keys like "Name[de]=..." should be skipped; they are locale variants.
  const std::string content =
      "[Application]\n"
      "name=org.example.App\n"
      "Name[de]=Beispiel-App\n";

  const auto meta = parseFlatpakMetadata(content);
  EXPECT_EQ(meta.at("Application.name"), "org.example.App");
  EXPECT_EQ(meta.count("Application.Name[de]"), 0u);
}

TEST_F(FlatpakPackagesTests, metadata_handles_multiple_sections) {
  const std::string content =
      "[Application]\n"
      "name=org.gnome.Gedit\n"
      "command=gedit\n"
      "\n"
      "[Context]\n"
      "shared=ipc;network;\n"
      "filesystems=host;\n";

  const auto meta = parseFlatpakMetadata(content);
  EXPECT_EQ(meta.at("Application.name"), "org.gnome.Gedit");
  EXPECT_EQ(meta.at("Context.shared"), "ipc;network;");
  EXPECT_EQ(meta.at("Context.filesystems"), "host;");
}

TEST_F(FlatpakPackagesTests, metadata_returns_empty_for_empty_input) {
  const auto meta = parseFlatpakMetadata("");
  EXPECT_TRUE(meta.empty());
}

TEST_F(FlatpakPackagesTests, metadata_skips_keys_outside_any_section) {
  const std::string content =
      "orphan_key=value\n"
      "[Application]\n"
      "name=org.example.App\n";

  const auto meta = parseFlatpakMetadata(content);
  EXPECT_EQ(meta.count("orphan_key"), 0u);
  EXPECT_EQ(meta.at("Application.name"), "org.example.App");
}

TEST_F(FlatpakPackagesTests, metadata_first_value_wins_for_duplicate_key) {
  const std::string content =
      "[Application]\n"
      "name=org.example.First\n"
      "name=org.example.Second\n";

  const auto meta = parseFlatpakMetadata(content);
  EXPECT_EQ(meta.at("Application.name"), "org.example.First");
}

// ---------------------------------------------------------------------------
// parseFlatpakAppStream tests
// ---------------------------------------------------------------------------

TEST_F(FlatpakPackagesTests, appstream_parses_basic_fields) {
  const std::string xml =
      "<?xml version=\"1.0\"?>\n"
      "<component type=\"desktop\">\n"
      "  <id>org.gnome.Gedit</id>\n"
      "  <name>gedit</name>\n"
      "  <summary>GNOME text editor</summary>\n"
      "  <project_license>GPL-2.0+</project_license>\n"
      "  <developer_name>The GNOME Project</developer_name>\n"
      "  <url type=\"homepage\">https://wiki.gnome.org/Apps/Gedit</url>\n"
      "  <releases>\n"
      "    <release version=\"46.2\" date=\"2024-04-21\"/>\n"
      "  </releases>\n"
      "</component>\n";

  Row r;
  parseFlatpakAppStream(xml, r);

  EXPECT_EQ(r["name"], "gedit");
  EXPECT_EQ(r["summary"], "GNOME text editor");
  EXPECT_EQ(r["license"], "GPL-2.0+");
  EXPECT_EQ(r["developer_name"], "The GNOME Project");
  EXPECT_EQ(r["homepage"], "https://wiki.gnome.org/Apps/Gedit");
  EXPECT_EQ(r["version"], "46.2");
}

TEST_F(FlatpakPackagesTests, appstream_parses_description_paragraphs) {
  const std::string xml =
      "<?xml version=\"1.0\"?>\n"
      "<component>\n"
      "  <description>\n"
      "    <p>First paragraph.</p>\n"
      "    <p>Second paragraph.</p>\n"
      "  </description>\n"
      "</component>\n";

  Row r;
  parseFlatpakAppStream(xml, r);

  EXPECT_NE(r["description"].find("First paragraph"), std::string::npos);
  EXPECT_NE(r["description"].find("Second paragraph"), std::string::npos);
}

TEST_F(FlatpakPackagesTests, appstream_uses_first_release_version) {
  const std::string xml =
      "<?xml version=\"1.0\"?>\n"
      "<component>\n"
      "  <releases>\n"
      "    <release version=\"2.0\" date=\"2024-01-01\"/>\n"
      "    <release version=\"1.0\" date=\"2023-01-01\"/>\n"
      "  </releases>\n"
      "</component>\n";

  Row r;
  parseFlatpakAppStream(xml, r);
  EXPECT_EQ(r["version"], "2.0");
}

TEST_F(FlatpakPackagesTests, appstream_ignores_non_homepage_urls) {
  const std::string xml =
      "<?xml version=\"1.0\"?>\n"
      "<component>\n"
      "  <url type=\"bugtracker\">https://bugs.example.com</url>\n"
      "  <url type=\"homepage\">https://home.example.com</url>\n"
      "</component>\n";

  Row r;
  parseFlatpakAppStream(xml, r);
  EXPECT_EQ(r["homepage"], "https://home.example.com");
}

TEST_F(FlatpakPackagesTests, appstream_handles_no_releases) {
  const std::string xml =
      "<?xml version=\"1.0\"?>\n"
      "<component>\n"
      "  <summary>No release info</summary>\n"
      "</component>\n";

  Row r;
  parseFlatpakAppStream(xml, r);
  EXPECT_EQ(r["summary"], "No release info");
  EXPECT_EQ(r.count("version"), 0u);
}

TEST_F(FlatpakPackagesTests, appstream_tolerates_malformed_xml) {
  Row r;
  parseFlatpakAppStream("this is not xml <", r);
  // Must not crash; row should remain unmodified.
  EXPECT_EQ(r.count("summary"), 0u);
}

TEST_F(FlatpakPackagesTests, appstream_handles_empty_input) {
  Row r;
  parseFlatpakAppStream("", r);
  EXPECT_EQ(r.count("summary"), 0u);
}

TEST_F(FlatpakPackagesTests, appstream_parses_legacy_application_root) {
  // Older AppStream format uses <application> as the root element.
  const std::string xml =
      "<?xml version=\"1.0\"?>\n"
      "<application>\n"
      "  <summary>Legacy app</summary>\n"
      "  <project_license>MIT</project_license>\n"
      "</application>\n";

  Row r;
  parseFlatpakAppStream(xml, r);
  EXPECT_EQ(r["summary"], "Legacy app");
  EXPECT_EQ(r["license"], "MIT");
}

TEST_F(FlatpakPackagesTests, appstream_parses_appstream_1_developer_element) {
  // AppStream 1.0 moved developer name inside <developer><name>.
  const std::string xml =
      "<?xml version=\"1.0\"?>\n"
      "<component>\n"
      "  <developer>\n"
      "    <name>GNOME Project</name>\n"
      "  </developer>\n"
      "</component>\n";

  Row r;
  parseFlatpakAppStream(xml, r);
  EXPECT_EQ(r["developer_name"], "GNOME Project");
}

} // namespace tables
} // namespace osquery
