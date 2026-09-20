/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <unordered_map>

#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

Row parseSnapYaml(const std::string& content);

struct SnapStateInfo {
  std::string revision;
  std::string channel;
  std::string snap_id;
};

std::unordered_map<std::string, SnapStateInfo> parseSnapdState(
    const std::string& json_content);

class SnapPackagesTests : public testing::Test {};

TEST_F(SnapPackagesTests, nested_name_does_not_overwrite_snap_name) {
  // A 'name:' key nested inside slots/apps/etc. must not overwrite the
  // top-level snap name.
  auto r = parseSnapYaml(
      "name: mysnap\n"
      "version: 1.0\n"
      "slots:\n"
      "  dbus-service:\n"
      "    interface: dbus\n"
      "    bus: session\n"
      "    name: com.example.mysnap\n"
      "confinement: strict\n");

  EXPECT_EQ(r["name"], "mysnap");
  EXPECT_EQ(r["version"], "1.0");
  EXPECT_EQ(r["confinement"], "strict");
}

TEST_F(SnapPackagesTests, parses_a_complete_snap_yaml) {
  auto r = parseSnapYaml(
      "name: hello-world\n"
      "version: \"6.4\"\n"
      "summary: Make your first snap\n"
      "description: |\n"
      "  The 'hello-world' snap shows how to use various\n"
      "  Snapcraft features.\n"
      "type: app\n"
      "confinement: strict\n"
      "grade: stable\n"
      "base: core20\n"
      "license: MIT\n");

  EXPECT_EQ(r["name"], "hello-world");
  EXPECT_EQ(r["version"], "6.4");
  EXPECT_EQ(r["summary"], "Make your first snap");
  EXPECT_EQ(r["type"], "app");
  EXPECT_EQ(r["confinement"], "strict");
  EXPECT_EQ(r["grade"], "stable");
  EXPECT_EQ(r["base"], "core20");
  EXPECT_EQ(r["license"], "MIT");
  // Description begins with the first line of the block scalar.
  EXPECT_FALSE(r["description"].empty());
  EXPECT_NE(r["description"].find("hello-world"), std::string::npos);
}

TEST_F(SnapPackagesTests, strips_double_quotes_from_version) {
  auto r = parseSnapYaml(
      "name: mysnap\n"
      "version: \"2.0+git\"\n");

  EXPECT_EQ(r["version"], "2.0+git");
}

TEST_F(SnapPackagesTests, strips_single_quotes_from_value) {
  auto r = parseSnapYaml(
      "name: mysnap\n"
      "license: 'GPL-2.0'\n");

  EXPECT_EQ(r["license"], "GPL-2.0");
}

TEST_F(SnapPackagesTests, parses_simple_architecture_list) {
  auto r = parseSnapYaml(
      "name: mysnap\n"
      "architectures:\n"
      "- amd64\n"
      "- arm64\n");

  EXPECT_EQ(r["architectures"], "amd64,arm64");
}

TEST_F(SnapPackagesTests, parses_inline_flow_sequence_architecture) {
  auto r = parseSnapYaml(
      "name: mysnap\n"
      "architectures: [amd64]\n");

  EXPECT_EQ(r["architectures"], "amd64");
}

TEST_F(SnapPackagesTests, parses_complex_architecture_objects) {
  // build-on/run-on objects: only the run-on architecture is reported.
  auto r = parseSnapYaml(
      "name: mysnap\n"
      "architectures:\n"
      "- build-on: amd64\n"
      "  run-on: amd64\n");

  EXPECT_EQ(r["name"], "mysnap");
  EXPECT_EQ(r["architectures"], "amd64");
}

TEST_F(SnapPackagesTests, ignores_comment_lines) {
  auto r = parseSnapYaml(
      "# This is a comment\n"
      "name: mysnap\n"
      "# version comment\n"
      "version: 1.0\n");

  EXPECT_EQ(r["name"], "mysnap");
  EXPECT_EQ(r["version"], "1.0");
}

TEST_F(SnapPackagesTests, block_scalar_with_literal_style) {
  auto r = parseSnapYaml(
      "name: mysnap\n"
      "description: |\n"
      "  First line.\n"
      "  Second line.\n"
      "version: 1.0\n");

  EXPECT_NE(r["description"].find("First line"), std::string::npos);
  EXPECT_NE(r["description"].find("Second line"), std::string::npos);
  EXPECT_EQ(r["version"], "1.0");
}

TEST_F(SnapPackagesTests, block_scalar_stripped_style) {
  auto r = parseSnapYaml(
      "name: mysnap\n"
      "description: |-\n"
      "  Stripped block.\n"
      "version: 2.0\n");

  EXPECT_NE(r["description"].find("Stripped block"), std::string::npos);
  EXPECT_EQ(r["version"], "2.0");
}

TEST_F(SnapPackagesTests, unrecognized_keys_are_silently_ignored) {
  auto r = parseSnapYaml(
      "name: mysnap\n"
      "version: 1.0\n"
      "assumes:\n"
      "- snapd2.38\n"
      "confinement: strict\n");

  EXPECT_EQ(r["name"], "mysnap");
  EXPECT_EQ(r["version"], "1.0");
  EXPECT_EQ(r["confinement"], "strict");
  EXPECT_EQ(r.count("assumes"), 0u);
}

TEST_F(SnapPackagesTests, returns_empty_name_for_empty_input) {
  auto r = parseSnapYaml("");
  EXPECT_EQ(r.count("name"), 0u);
}

TEST_F(SnapPackagesTests, type_defaults_absent_when_not_in_yaml) {
  auto r = parseSnapYaml(
      "name: mysnap\n"
      "version: 1.0\n");

  // "type" is optional in snap.yaml; expect it to be absent from the Row.
  EXPECT_EQ(r.count("type"), 0u);
}

TEST_F(SnapPackagesTests, parses_snapd_type_snap) {
  auto r = parseSnapYaml(
      "name: snapd\n"
      "version: 2.60\n"
      "type: snapd\n"
      "confinement: strict\n");

  EXPECT_EQ(r["type"], "snapd");
}

TEST_F(SnapPackagesTests, parses_snapd_state_for_current_revision) {
  const auto states = parseSnapdState(
      R"json({
        "data": {
          "snaps": {
            "hello-world": {
              "current": "42",
              "channel": "stable",
              "sequence": [
                {"revision": "41", "snap-id": "old-id"},
                {"revision": "42", "snap-id": "current-id"}
              ]
            },
            "fallback": {
              "current": "7",
              "snap-id": "fallback-id"
            }
          }
        }
      })json");

  ASSERT_EQ(states.count("hello-world"), 1u);
  EXPECT_EQ(states.at("hello-world").revision, "42");
  EXPECT_EQ(states.at("hello-world").channel, "stable");
  EXPECT_EQ(states.at("hello-world").snap_id, "current-id");

  ASSERT_EQ(states.count("fallback"), 1u);
  EXPECT_EQ(states.at("fallback").revision, "7");
  EXPECT_EQ(states.at("fallback").snap_id, "fallback-id");
}

} // namespace tables
} // namespace osquery
