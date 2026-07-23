/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for agent_skills
// Spec file: specs/agent_skills.table

#include <osquery/filesystem/filesystem.h>
#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

namespace fs = boost::filesystem;

class AgentSkills : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();

    // resolveFilePattern canonicalizes the path up to the first wildcard
    // (e.g. /var/... -> /private/var/... on macOS, since /var is a symlink);
    // canonicalize here too so the `directory` constraint this test queries
    // with matches what the table's own discovery will produce. Uses the
    // non-throwing overload since the throwing one would abort the test
    // runner on failure instead of reporting a clean assertion failure.
    boost::system::error_code ec;
    fs::path canonical_tmp = fs::canonical(fs::temp_directory_path(), ec);
    ASSERT_FALSE(ec) << "Failed to canonicalize temp directory: "
                     << ec.message();
    project_dir =
        canonical_tmp / fs::unique_path("osquery.tests.agent_skills.%%%%-%%%%");
    skill_dir = project_dir / ".claude" / "skills" / "test-skill";
    block_scalar_skill_dir =
        project_dir / ".cursor" / "skills" / "block-scalar-skill";

    ASSERT_TRUE(createDirectory(skill_dir / "scripts", true).ok());
    ASSERT_TRUE(writeTextFile(skill_dir / "SKILL.md", kSkillMarkdown).ok());
    ASSERT_TRUE(
        writeTextFile(skill_dir / "scripts" / "helper.sh", "#!/bin/sh\n")
            .ok());

    ASSERT_TRUE(createDirectory(block_scalar_skill_dir, true).ok());
    ASSERT_TRUE(writeTextFile(block_scalar_skill_dir / "SKILL.md",
                              kBlockScalarSkillMarkdown)
                    .ok());
  }

void TearDown() override {
  if (project_dir.empty()) {
    return;
  }

  boost::system::error_code ec;
  fs::remove_all(project_dir, ec);
  EXPECT_FALSE(ec) << "Failed to remove " << project_dir.string() << ": "
                   << ec.message();
}

  fs::path project_dir;
  fs::path skill_dir;
  fs::path block_scalar_skill_dir;

  static const std::string kSkillMarkdown;
  static const std::string kBlockScalarSkillMarkdown;
};

const std::string AgentSkills::kSkillMarkdown = R"(---
name: test-skill
description: A skill used only for osquery's own integration test.
license: MIT
allowed-tools: Read Bash(git:*)
metadata:
  version: "1.2.3"
---

Do the thing under test.
)";

// Real-world SKILL.md files commonly use YAML block-scalar descriptions
// (folded `>-`), observed while validating this table's discovery logic
// against actual installed skills; this fixture pins that parsing.
const std::string AgentSkills::kBlockScalarSkillMarkdown = R"(---
name: block-scalar-skill
description: >-
  This description spans
  multiple folded lines. Use when testing
  the frontmatter parser.
---

Body content.
)";

namespace {
const Row& findRowByPath(const QueryData& data, const std::string& path) {
  static const Row kEmptyRow;
  for (const auto& row : data) {
    if (row.at("path") == path) {
      return row;
    }
  }
  ADD_FAILURE() << "No row found with path " << path;
  // data.front() would be undefined behavior if data is empty; fall back to
  // an empty row so callers still fail loudly (via Row::at() throwing)
  // instead of crashing the test runner.
  return data.empty() ? kEmptyRow : data.front();
}
} // namespace

TEST_F(AgentSkills, test_sanity) {
  auto const data = execute_query(
      "select *, content from agent_skills where directory = '" +
      project_dir.string() + "'");

  ASSERT_EQ(data.size(), 2ul);

  ValidationMap row_map = {
      {"name", NormalType},
      {"description", NormalType},
      {"content", NormalType},
      {"version", NormalType},
      {"license", NormalType},
      {"compatibility", NormalType},
      {"allowed_tools", NormalType},
      {"agent", NonEmptyString},
      {"scope", NonEmptyString},
      {"directory", NonEmptyString},
      {"path", NonEmptyString},
      {"sha256", NonEmptyString},
      {"size", NonNegativeInt},
      {"mtime", NonNegativeInt},
      {"resource_count", NonNegativeInt},
      {"script_count", NonNegativeInt},
      {"uid", NormalType},
      {"username", NormalType},
  };
  validate_rows(data, row_map);

  const auto& row = findRowByPath(data, (skill_dir / "SKILL.md").string());
  EXPECT_EQ(row.at("name"), "test-skill");
  EXPECT_EQ(row.at("description"),
            "A skill used only for osquery's own integration test.");
  EXPECT_EQ(row.at("license"), "MIT");
  EXPECT_EQ(row.at("version"), "1.2.3");
  EXPECT_EQ(row.at("agent"), "claude");
  EXPECT_EQ(row.at("scope"), "project");
  EXPECT_EQ(row.at("directory"), project_dir.string());
  EXPECT_EQ(row.at("content"), "Do the thing under test.");
  EXPECT_EQ(row.at("script_count"), "1");
  EXPECT_EQ(row.at("resource_count"), "1");
  EXPECT_TRUE(row.at("uid").empty());
  EXPECT_TRUE(row.at("username").empty());
}

TEST_F(AgentSkills, test_block_scalar_description) {
  auto const data = execute_query(
      "select * from agent_skills where directory = '" +
      project_dir.string() + "'");

  const auto& row =
      findRowByPath(data, (block_scalar_skill_dir / "SKILL.md").string());
  EXPECT_EQ(row.at("name"), "block-scalar-skill");
  EXPECT_EQ(row.at("agent"), "cursor");
  EXPECT_EQ(row.at("description"),
            "This description spans multiple folded lines. Use when "
            "testing the frontmatter parser.");
}

TEST_F(AgentSkills, test_unconstrained_query_excludes_project_scope) {
  auto const data = execute_query("select * from agent_skills");

  for (const auto& row : data) {
    EXPECT_NE(row.at("directory"), project_dir.string());
  }
}

} // namespace table_tests
} // namespace osquery
