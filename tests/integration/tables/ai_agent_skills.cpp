/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for ai_agent_skills
// Spec file: specs/ai_agent_skills.table

#include <osquery/dispatcher/dispatcher.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/tests/test_util.h>

namespace osquery {
namespace table_tests {

namespace fs = boost::filesystem;

class AIAgentSkills : public testing::Test {
 protected:
#ifdef OSQUERY_WINDOWS
  // The table reads users via usersFromContext, and on Windows the users
  // table throws unless its services are running, so every query here
  // would fail with "no state" without this.
  static void SetUpTestSuite() {
    initUsersAndGroupsServices(true, false);
  }

  static void TearDownTestSuite() {
    Dispatcher::stopServices();
    Dispatcher::joinServices();
    deinitUsersAndGroupsServices(true, false);
    Dispatcher::instance().resetStopping();
  }
#endif

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
    project_dir = canonical_tmp /
                  fs::unique_path("osquery.tests.ai_agent_skills.%%%%-%%%%");
    skill_dir = project_dir / ".claude" / "skills" / "test-skill";
    block_scalar_skill_dir =
        project_dir / ".cursor" / "skills" / "block-scalar-skill";
    empty_frontmatter_skill_dir =
        project_dir / ".agents" / "skills" / "empty-frontmatter-skill";
    structured_skill_dir =
        project_dir / ".github" / "skills" / "structured-skill";
    hidden_entries_skill_dir =
        project_dir / ".claude" / "skills" / "hidden-entries-skill";
    // Not a typo: a *directory* named SKILL.md, which the discovery glob
    // must not match.
    skill_md_directory_dir =
        project_dir / ".claude" / "skills" / "skill-md-is-a-directory";
    alias_skill_dir = project_dir / ".claude" / "skills" / "alias-skill";

    ASSERT_TRUE(createDirectory(skill_dir / "scripts", true).ok());
    ASSERT_TRUE(writeTextFile(skill_dir / "SKILL.md", kSkillMarkdown).ok());
    ASSERT_TRUE(
        writeTextFile(skill_dir / "scripts" / "helper.sh", "#!/bin/sh\n").ok());

    ASSERT_TRUE(createDirectory(block_scalar_skill_dir, true).ok());
    ASSERT_TRUE(writeTextFile(block_scalar_skill_dir / "SKILL.md",
                              kBlockScalarSkillMarkdown)
                    .ok());

    ASSERT_TRUE(createDirectory(empty_frontmatter_skill_dir, true).ok());
    ASSERT_TRUE(writeTextFile(empty_frontmatter_skill_dir / "SKILL.md",
                              kEmptyFrontmatterSkillMarkdown)
                    .ok());

    ASSERT_TRUE(createDirectory(structured_skill_dir, true).ok());
    ASSERT_TRUE(writeTextFile(structured_skill_dir / "SKILL.md",
                              kStructuredSkillMarkdown)
                    .ok());

    // One visible resource alongside a dot-prefixed file and a dot-prefixed
    // directory with a file in it. Only the visible one counts, on every
    // platform.
    ASSERT_TRUE(
        createDirectory(hidden_entries_skill_dir / ".hidden-dir", true).ok());
    ASSERT_TRUE(writeTextFile(hidden_entries_skill_dir / "SKILL.md",
                              kHiddenEntriesSkillMarkdown)
                    .ok());
    ASSERT_TRUE(
        writeTextFile(hidden_entries_skill_dir / "visible.txt", "v\n").ok());
    ASSERT_TRUE(
        writeTextFile(hidden_entries_skill_dir / ".hidden-file", "h\n").ok());
    ASSERT_TRUE(
        writeTextFile(hidden_entries_skill_dir / ".hidden-dir" / "nested.txt",
                      "n\n")
            .ok());

    ASSERT_TRUE(
        createDirectory(skill_md_directory_dir / "SKILL.md", true).ok());
    ASSERT_TRUE(writeTextFile(skill_md_directory_dir / "SKILL.md" / "inner.txt",
                              "not frontmatter\n")
                    .ok());

    ASSERT_TRUE(createDirectory(alias_skill_dir, true).ok());
    ASSERT_TRUE(
        writeTextFile(alias_skill_dir / "SKILL.md", aliasSkillMarkdown()).ok());
  }

  void writeSkillMarkdown(const fs::path& directory,
                          const std::string& content) {
    ASSERT_TRUE(createDirectory(directory, true).ok());
    ASSERT_TRUE(writeTextFile(directory / "SKILL.md", content).ok());
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
  fs::path empty_frontmatter_skill_dir;
  fs::path structured_skill_dir;
  fs::path hidden_entries_skill_dir;
  fs::path skill_md_directory_dir;
  fs::path alias_skill_dir;

  static const std::string kSkillMarkdown;
  static const std::string kBlockScalarSkillMarkdown;
  static const std::string kEmptyFrontmatterSkillMarkdown;
  static const std::string kStructuredSkillMarkdown;
  static const std::string kHiddenEntriesSkillMarkdown;

  // A 16 KiB anchored scalar repeated through 1024 aliases: about 20 KiB on
  // disk, 16 MiB once every alias is expanded. Every reported metadata field
  // is otherwise valid so the test proves the whole frontmatter is rejected.
  static std::string aliasSkillMarkdown() {
    std::string markdown =
        "---\nname: alias-skill\ndescription: Alias rejection fixture\n"
        "license: MIT\ncompatibility: osquery\nmetadata:\n  version: "
        "1.2.3\nx: &a " +
        std::string(16 * 1024, 'A') + "\nallowed-tools: [*a";
    for (int i = 1; i < 1024; ++i) {
      markdown += ", *a";
    }
    return markdown + "]\n---\n\nBody content.\n";
  }
};

const std::string AIAgentSkills::kSkillMarkdown = R"(---
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
const std::string AIAgentSkills::kBlockScalarSkillMarkdown = R"(---
name: block-scalar-skill
description: >-
  This description spans
  multiple folded lines. Use when testing
  the frontmatter parser.
---

Body content.
)";

// An empty frontmatter block: the closing fence's "\n" coincides with the
// opening fence's own trailing "\n" (no lines in between), so `close` ends
// up less than `fence_len`. This pins two things: the closing fence is
// still detected (a regression would make the parser treat the whole file,
// delimiters included, as frontmatter), and the frontmatter substring is
// computed as empty rather than underflowing to "the rest of the file"
// (a regression there would parse the body's "license: MIT" line as if it
// were real frontmatter, since the body deliberately starts with a line
// that matches a recognized key -- the earlier version of this fixture had
// no colon in its body at all, so it couldn't have caught that bug).
const std::string AIAgentSkills::kEmptyFrontmatterSkillMarkdown = R"(---
---

license: MIT
Body after an empty frontmatter block.
)";

// Frontmatter values that are not flat strings: `allowed-tools` as a YAML
// sequence and `compatibility` as a mapping, both shapes the Agent Skills
// spec allows, plus a double-quoted description carrying characters that
// are YAML-significant unquoted. These are what a real YAML parser buys
// over line splitting, so pin how each one lands in its column.
const std::string AIAgentSkills::kStructuredSkillMarkdown = R"(---
name: structured-skill
description: "Quoted: with a colon, and #hash"
compatibility:
  product: claude-code
  network: false
allowed-tools:
  - Read
  - Bash(git:*)
metadata:
  version: 2.0.0
---

Body content.
)";

const std::string AIAgentSkills::kHiddenEntriesSkillMarkdown = R"(---
name: hidden-entries-skill
---

Body content.
)";

namespace {
std::string makeNestedSkillMarkdown(const std::string& name,
                                    size_t sequence_depth) {
  return "---\nname: " + name +
         "\ncompatibility: " + std::string(sequence_depth, '[') + "supported" +
         std::string(sequence_depth, ']') + "\n---\n";
}

std::string makeNestedMapSkillMarkdown(const std::string& name,
                                       size_t map_depth) {
  std::string nested_value;
  for (size_t i = 0; i < map_depth; ++i) {
    nested_value += "{level: ";
  }
  nested_value += "supported";
  nested_value += std::string(map_depth, '}');

  return "---\nname: " + name + "\ncompatibility: " + nested_value +
         "\n---\n";
}

std::string makeSizedSkillMarkdown(const std::string& name, size_t total_size) {
  const std::string prefix = "---\nname: " + name + "\npadding: ";
  const std::string suffix = "\n---";
  EXPECT_GE(total_size, prefix.size() + suffix.size());
  return prefix + std::string(total_size - prefix.size() - suffix.size(), 'a') +
         suffix;
}

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

void expectFrontmatterColumnsEmpty(const Row& row) {
  EXPECT_TRUE(row.at("name").empty());
  EXPECT_TRUE(row.at("description").empty());
  EXPECT_TRUE(row.at("version").empty());
  EXPECT_TRUE(row.at("license").empty());
  EXPECT_TRUE(row.at("compatibility").empty());
  EXPECT_TRUE(row.at("allowed_tools").empty());
}
} // namespace

TEST_F(AIAgentSkills, test_sanity) {
  auto const data =
      execute_query("select * from ai_agent_skills where directory = '" +
                    project_dir.string() + "'");

  ASSERT_EQ(data.size(), 6ul);

  ValidationMap row_map = {
      {"name", NormalType},
      {"description", NormalType},
      {"version", NormalType},
      {"license", NormalType},
      {"compatibility", NormalType},
      {"allowed_tools", NormalType},
      {"agent", NonEmptyString},
      {"scope", NonEmptyString},
      {"directory", NonEmptyString},
      {"path", NonEmptyString},
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
  EXPECT_EQ(row.at("script_count"), "1");
  EXPECT_EQ(row.at("resource_count"), "1");
  EXPECT_TRUE(row.at("uid").empty());
  EXPECT_TRUE(row.at("username").empty());
}

TEST_F(AIAgentSkills, test_block_scalar_description) {
  auto const data =
      execute_query("select * from ai_agent_skills where directory = '" +
                    project_dir.string() + "'");

  const auto& row =
      findRowByPath(data, (block_scalar_skill_dir / "SKILL.md").string());
  EXPECT_EQ(row.at("name"), "block-scalar-skill");
  EXPECT_EQ(row.at("agent"), "cursor");
  EXPECT_EQ(row.at("description"),
            "This description spans multiple folded lines. Use when "
            "testing the frontmatter parser.");
}

TEST_F(AIAgentSkills, test_empty_frontmatter_block) {
  auto const data =
      execute_query("select * from ai_agent_skills where directory = '" +
                    project_dir.string() + "'");

  const auto& row =
      findRowByPath(data, (empty_frontmatter_skill_dir / "SKILL.md").string());
  // No metadata to parse from an empty frontmatter block, and the closing
  // fence must still be detected.
  EXPECT_TRUE(row.at("name").empty());
  EXPECT_TRUE(row.at("description").empty());
  // The body's "license: MIT" line must NOT be parsed as frontmatter: it
  // would be if the (empty) frontmatter substring computation underflowed
  // and silently became "the rest of the file" instead of "".
  EXPECT_TRUE(row.at("license").empty());
}

TEST_F(AIAgentSkills, test_structured_frontmatter_values) {
  auto const data =
      execute_query("select * from ai_agent_skills where directory = '" +
                    project_dir.string() + "'");

  const auto& row =
      findRowByPath(data, (structured_skill_dir / "SKILL.md").string());
  EXPECT_EQ(row.at("name"), "structured-skill");
  EXPECT_EQ(row.at("agent"), "copilot");
  EXPECT_EQ(row.at("description"), "Quoted: with a colon, and #hash");
  EXPECT_EQ(row.at("version"), "2.0.0");
  // A sequence reads better as a joined list than as YAML syntax.
  EXPECT_EQ(row.at("allowed_tools"), "Read, Bash(git:*)");
  // Anything structured is emitted in flow style, so it stays on one line.
  EXPECT_EQ(row.at("compatibility"), "{product: claude-code, network: false}");
}

TEST_F(AIAgentSkills, test_aliases_are_not_expanded_when_joined) {
  auto const data =
      execute_query("select * from ai_agent_skills where directory = '" +
                    project_dir.string() + "'");

  const auto& row =
      findRowByPath(data, (alias_skill_dir / "SKILL.md").string());
  expectFrontmatterColumnsEmpty(row);
  EXPECT_EQ(row.at("path"), (alias_skill_dir / "SKILL.md").string());
  EXPECT_EQ(row.at("agent"), "claude");
  EXPECT_EQ(row.at("scope"), "project");
  EXPECT_EQ(row.at("directory"), project_dir.string());
}

TEST_F(AIAgentSkills, test_yaml_sequence_nesting_budget) {
  const auto supported_dir =
      project_dir / ".claude" / "skills" / "supported-nesting";
  const auto excessive_dir =
      project_dir / ".claude" / "skills" / "excessive-nesting";

  // The top-level map plus 31 sequences reaches the 32-collection limit.
  writeSkillMarkdown(supported_dir,
                     makeNestedSkillMarkdown("supported-nesting", 31));
  // One more nested sequence must be rejected before YAML::Load.
  writeSkillMarkdown(excessive_dir,
                     makeNestedSkillMarkdown("excessive-nesting", 32));

  const auto data =
      execute_query("select * from ai_agent_skills where directory = '" +
                    project_dir.string() + "'");

  const auto& supported =
      findRowByPath(data, (supported_dir / "SKILL.md").string());
  EXPECT_EQ(supported.at("name"), "supported-nesting");
  EXPECT_FALSE(supported.at("compatibility").empty());

  const auto& excessive =
      findRowByPath(data, (excessive_dir / "SKILL.md").string());
  expectFrontmatterColumnsEmpty(excessive);
}

TEST_F(AIAgentSkills, test_yaml_map_nesting_budget) {
  const auto supported_dir =
      project_dir / ".claude" / "skills" / "supported-map-nesting";
  const auto excessive_dir =
      project_dir / ".claude" / "skills" / "excessive-map-nesting";

  // The root mapping counts as one collection, so 31 nested mappings are
  // accepted at the 32-collection limit and 32 nested mappings are rejected.
  writeSkillMarkdown(supported_dir,
                     makeNestedMapSkillMarkdown("supported-map-nesting", 31));
  writeSkillMarkdown(excessive_dir,
                     makeNestedMapSkillMarkdown("excessive-map-nesting", 32));

  const auto data =
      execute_query("select * from ai_agent_skills where directory = '" +
                    project_dir.string() + "'");

  const auto& supported =
      findRowByPath(data, (supported_dir / "SKILL.md").string());
  EXPECT_EQ(supported.at("name"), "supported-map-nesting");
  EXPECT_FALSE(supported.at("compatibility").empty());

  const auto& excessive =
      findRowByPath(data, (excessive_dir / "SKILL.md").string());
  expectFrontmatterColumnsEmpty(excessive);
  EXPECT_EQ(excessive.at("path"), (excessive_dir / "SKILL.md").string());
  EXPECT_EQ(excessive.at("agent"), "claude");
  EXPECT_EQ(excessive.at("scope"), "project");
  EXPECT_EQ(excessive.at("directory"), project_dir.string());
}

TEST_F(AIAgentSkills, test_yaml_anchors_and_aliases_are_rejected) {
  const auto anchor_dir = project_dir / ".claude" / "skills" / "anchor-only";
  const auto aliases_dir =
      project_dir / ".claude" / "skills" / "repeated-aliases";

  writeSkillMarkdown(anchor_dir, R"(---
name: anchor-only
description: Anchor rejection fixture
license: MIT
compatibility: &requirements
  product: codex
allowed-tools: Read
metadata:
  version: 1.2.3
---
)");
  writeSkillMarkdown(aliases_dir, R"(---
name: repeated-aliases
a: &a [x, x, x, x, x, x, x, x]
b: &b [*a, *a, *a, *a, *a, *a, *a, *a]
c: &c [*b, *b, *b, *b, *b, *b, *b, *b]
compatibility: *c
---
)");

  const auto data =
      execute_query("select * from ai_agent_skills where directory = '" +
                    project_dir.string() + "'");

  const auto& anchor =
      findRowByPath(data, (anchor_dir / "SKILL.md").string());
  expectFrontmatterColumnsEmpty(anchor);

  const auto& aliases =
      findRowByPath(data, (aliases_dir / "SKILL.md").string());
  EXPECT_TRUE(aliases.at("name").empty());
  EXPECT_TRUE(aliases.at("compatibility").empty());
}

TEST_F(AIAgentSkills, test_malformed_yaml_is_rejected) {
  const auto malformed_dir =
      project_dir / ".claude" / "skills" / "malformed-yaml";
  writeSkillMarkdown(malformed_dir, R"(---
name: malformed-yaml
compatibility: [unterminated
---
)");

  const auto data =
      execute_query("select * from ai_agent_skills where directory = '" +
                    project_dir.string() + "'");
  const auto& row = findRowByPath(data, (malformed_dir / "SKILL.md").string());
  EXPECT_TRUE(row.at("name").empty());
  EXPECT_TRUE(row.at("compatibility").empty());
}

TEST_F(AIAgentSkills, test_frontmatter_file_size_boundary) {
  const auto within_limit_dir =
      project_dir / ".claude" / "skills" / "within-size-limit";
  const auto over_limit_dir =
      project_dir / ".claude" / "skills" / "over-size-limit";
  constexpr size_t kFrontmatterReadLimit = 256 * 1024;

  // The closing fence is entirely inside the read prefix at the exact limit.
  writeSkillMarkdown(
      within_limit_dir,
      makeSizedSkillMarkdown("within-size-limit", kFrontmatterReadLimit));
  // Moving it one byte farther means the bounded prefix has no closing fence.
  writeSkillMarkdown(
      over_limit_dir,
      makeSizedSkillMarkdown("over-size-limit", kFrontmatterReadLimit + 1));

  const auto data =
      execute_query("select * from ai_agent_skills where directory = '" +
                    project_dir.string() + "'");
  const auto& within =
      findRowByPath(data, (within_limit_dir / "SKILL.md").string());
  EXPECT_EQ(within.at("name"), "within-size-limit");
  const auto& over =
      findRowByPath(data, (over_limit_dir / "SKILL.md").string());
  EXPECT_TRUE(over.at("name").empty());
}

TEST_F(AIAgentSkills, test_unicode_frontmatter) {
  const auto unicode_dir =
      project_dir / ".claude" / "skills" / "unicode-metadata";
  writeSkillMarkdown(unicode_dir, R"(---
name: café
description: 安全なスキル 🔐
---
)");

  const auto data =
      execute_query("select * from ai_agent_skills where directory = '" +
                    project_dir.string() + "'");
  const auto& row = findRowByPath(data, (unicode_dir / "SKILL.md").string());
  EXPECT_EQ(row.at("name"), "café");
  EXPECT_EQ(row.at("description"), "安全なスキル 🔐");
}

TEST_F(AIAgentSkills, test_hidden_entries_are_not_counted) {
  auto const data =
      execute_query("select * from ai_agent_skills where directory = '" +
                    project_dir.string() + "'");

  const auto& row =
      findRowByPath(data, (hidden_entries_skill_dir / "SKILL.md").string());
  EXPECT_EQ(row.at("name"), "hidden-entries-skill");
  // visible.txt only: .hidden-file and everything under .hidden-dir/ are
  // excluded. POSIX glob("*") drops dot entries on its own, but the Windows
  // directory iteration does not, so without an explicit filter this would
  // be 3 there and 1 here.
  EXPECT_EQ(row.at("resource_count"), "1");
}

TEST_F(AIAgentSkills, test_directory_named_skill_md_is_not_a_skill) {
  auto const data =
      execute_query("select * from ai_agent_skills where directory = '" +
                    project_dir.string() + "'");

  // The discovery glob matches files only. A directory named SKILL.md has no
  // frontmatter to read, so matching it would emit a row with every
  // frontmatter column blank.
  const auto unwanted = (skill_md_directory_dir / "SKILL.md").string();
  for (const auto& row : data) {
    EXPECT_NE(row.at("path"), unwanted);
  }
}

TEST_F(AIAgentSkills, test_unconstrained_query_excludes_project_scope) {
  auto const data = execute_query("select * from ai_agent_skills");

  for (const auto& row : data) {
    EXPECT_NE(row.at("directory"), project_dir.string());
  }
}

} // namespace table_tests
} // namespace osquery
