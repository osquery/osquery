/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sys/stat.h>

#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/filesystem.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/hashing/hashing.h>
#include <osquery/tables/system/system_utils.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

namespace {

// A skill discovery root: a path relative to some base (a home directory,
// or an operator-supplied project directory) and the agent runtime it's
// associated with, per that runtime's own documented discovery convention.
struct SkillRoot {
  std::string relative_path;
  std::string agent;
};

const std::vector<SkillRoot> kUserSkillRoots = {
    {".claude/skills", "claude"},
    {".cursor/skills", "cursor"},
    // Observed in practice (not in Cursor's own docs, which say
    // .cursor/skills/): some Cursor installs sync another tool's skills
    // into .cursor/skills-<source>/ (a .sync-manifest.json marks it as a
    // sync target). Kept alongside the documented path since it holds real,
    // loadable skill content.
    {".cursor/skills-cursor", "cursor"},
    {".copilot/skills", "copilot"},
    {".agents/skills", "agents"},
};

const std::vector<SkillRoot> kProjectSkillRoots = {
    {".claude/skills", "claude"},
    {".cursor/skills", "cursor"},
    {".github/skills", "copilot"},
    {".agents/skills", "agents"},
};

// Relative to "/"; POSIX-only (there is no documented Windows equivalent).
const std::string kSystemSkillRootRelative = "etc/codex/skills";
const std::string kSystemSkillAgent = "codex";

// SKILL.md files are recommended to stay under 500 lines / ~5000 tokens.
// Anything far larger than that is capped rather than parsed, to bound
// per-row cost; such rows still get path/hash/size/mtime/counts.
const size_t kMaxFrontmatterFileSize = 256 * 1024;

// Skill directories are inherently shallow (SKILL.md plus scripts/,
// references/, assets/); these bound resource/script counting cost without
// exposing a query-configurable knob like npm_packages' max_depth.
const int kMaxResourceScanDepth = 8;
const size_t kMaxResourceScanFiles = 5000;

// Claude Code plugin installs put skills several directories deep under
// ~/.claude/plugins/ (marketplace source checkouts under marketplaces/, an
// active copy under cache/), and how deep depends on how each marketplace
// repo organizes its own plugins -- there is no single fixed glob shape
// across marketplaces the way there is for kUserSkillRoots, so this root is
// walked (bounded, pruning .git/node_modules) instead of glob-matched.
const std::string kClaudePluginsRootRelative = ".claude/plugins";
const int kMaxPluginScanDepth = 12;
const size_t kMaxPluginScanEntries = 20000;

struct ParsedSkill {
  std::string name;
  std::string description;
  std::string license;
  std::string compatibility;
  std::string allowed_tools;
  std::string version;
  std::string content;
};

std::string trim(const std::string& value) {
  auto start = value.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return "";
  }
  auto end = value.find_last_not_of(" \t\r\n");
  return value.substr(start, end - start + 1);
}

std::string stripQuotes(const std::string& value) {
  auto trimmed = trim(value);
  if (trimmed.size() >= 2 &&
      ((trimmed.front() == '"' && trimmed.back() == '"') ||
       (trimmed.front() == '\'' && trimmed.back() == '\''))) {
    trimmed = trimmed.substr(1, trimmed.size() - 2);
  }
  return trimmed;
}

// Consumes a YAML block scalar (`>`/`>-`/`>+` folded, `|`/`|-`/`|+`
// literal) starting at lines[start], whose continuation lines are indented
// further than `key_indent`. Returns the assembled value and advances
// `next_index` past the consumed lines. Folded lines join with spaces;
// literal lines keep their newlines; blank lines become a paragraph break
// either way. Chomping indicators (-/+) are not distinguished: trailing
// whitespace is trimmed regardless, which is a fine approximation for the
// short description-style values this table cares about.
std::string consumeBlockScalar(const std::vector<std::string>& lines,
                               size_t start,
                               size_t key_indent,
                               bool folded,
                               size_t& next_index) {
  std::string value;
  size_t i = start;
  for (; i < lines.size(); ++i) {
    const std::string& line = lines[i];
    if (trim(line).empty()) {
      value += "\n";
      continue;
    }

    size_t indent = line.find_first_not_of(" \t");
    if (indent == std::string::npos || indent <= key_indent) {
      break;
    }

    if (!value.empty() && value.back() != '\n') {
      value += folded ? " " : "\n";
    }
    value += trim(line);
  }
  next_index = i;
  return trim(value);
}

// A minimal frontmatter reader, not a general YAML parser: osquery does not
// vendor a YAML library. Handles the flat scalar keys the Agent Skills open
// standard (agentskills.io/specification) defines at the top level (name,
// description, license, compatibility, allowed-tools), plus one level of
// nesting to pull `version` out of a `metadata:` block, per that spec's own
// documented convention for where version numbers live, plus YAML block
// scalars (`>`/`|`) since real-world descriptions commonly use them.
// Unrecognized keys are dropped rather than surfaced as a partial blob.
void parseFrontmatter(const std::string& file_content, ParsedSkill& skill) {
  if (file_content.compare(0, 4, "---\n") != 0) {
    skill.content = file_content;
    return;
  }

  auto close = file_content.find("\n---", 3);
  if (close == std::string::npos) {
    skill.content = file_content;
    return;
  }

  auto body_start = file_content.find('\n', close + 1);
  skill.content = (body_start == std::string::npos)
                      ? ""
                      : trim(file_content.substr(body_start + 1));

  std::string frontmatter = file_content.substr(4, close - 4);
  std::vector<std::string> lines;
  {
    std::istringstream stream(frontmatter);
    std::string line;
    while (std::getline(stream, line)) {
      lines.push_back(line);
    }
  }

  bool in_metadata = false;
  for (size_t i = 0; i < lines.size(); ++i) {
    const std::string& line = lines[i];
    if (trim(line).empty()) {
      continue;
    }

    bool indented = line[0] == ' ' || line[0] == '\t';
    if (!indented) {
      in_metadata = false;
    }

    auto colon = line.find(':');
    if (colon == std::string::npos) {
      continue;
    }

    std::string key = trim(line.substr(0, colon));
    std::string raw_value = trim(line.substr(colon + 1));

    std::string value;
    if (!raw_value.empty() && (raw_value[0] == '>' || raw_value[0] == '|') &&
        (raw_value.size() == 1 || raw_value[1] == '-' || raw_value[1] == '+')) {
      size_t key_indent = line.find_first_not_of(" \t");
      size_t next_index = i + 1;
      value = consumeBlockScalar(
          lines, i + 1, key_indent, raw_value[0] == '>', next_index);
      i = next_index - 1;
    } else {
      value = stripQuotes(raw_value);
    }

    if (!indented) {
      if (key == "name") {
        skill.name = value;
      } else if (key == "description") {
        skill.description = value;
      } else if (key == "license") {
        skill.license = value;
      } else if (key == "compatibility") {
        skill.compatibility = value;
      } else if (key == "allowed-tools" || key == "allowed_tools") {
        skill.allowed_tools = value;
      } else if (key == "metadata") {
        in_metadata = true;
      }
    } else if (in_metadata && key == "version") {
      skill.version = value;
    }
  }
}

bool statSkillFile(const std::string& path, int64_t& size, int64_t& mtime) {
#ifdef WIN32
  WINDOWS_STAT file_stat;
  if (!platformStat(path, &file_stat).ok()) {
    return false;
  }
  size = static_cast<int64_t>(file_stat.size);
  mtime = static_cast<int64_t>(file_stat.mtime);
#else
  struct stat file_stat;
  if (stat(path.c_str(), &file_stat) != 0) {
    return false;
  }
  size = static_cast<int64_t>(file_stat.st_size);
  mtime = static_cast<int64_t>(file_stat.st_mtime);
#endif
  return true;
}

// Symlink-loop-safe directory traversal, modeled on npm_packages.cpp's
// dirs_to_search queue + inode-tracking pattern (there is no existing
// depth-limited counting utility in osquery/filesystem/filesystem.h).
bool isDirVisited(std::unordered_set<int>& visited_inos,
                  const std::string& path) {
  if (path.empty()) {
    return true;
  }

  struct stat d_stat;
  if (!platformLstat(path, d_stat).ok()) {
    return false;
  }

  auto [_, inserted] = visited_inos.emplace(d_stat.st_ino);
  return !inserted;
}

// Counts files under `root` (or under `root/scripts` when scripts_only),
// depth-limited and symlink-loop-safe.
int countFiles(const fs::path& root, bool scripts_only) {
  fs::path start = scripts_only ? root / "scripts" : root;
  if (!isDirectory(start).ok()) {
    return 0;
  }

  size_t count = 0;
  std::unordered_set<int> visited_inos;
  std::vector<std::pair<std::string, int>> dirs_to_search;
  dirs_to_search.emplace_back(start.string(), 0);

  while (!dirs_to_search.empty() && count < kMaxResourceScanFiles) {
    auto [current_dir, depth] = dirs_to_search.back();
    dirs_to_search.pop_back();

    if (isDirVisited(visited_inos, current_dir)) {
      continue;
    }

    std::vector<std::string> files;
    if (listFilesInDirectory(current_dir, files, false).ok()) {
      count += files.size();
    }

    if (depth < kMaxResourceScanDepth) {
      std::vector<std::string> subdirs;
      if (listDirectoriesInDirectory(current_dir, subdirs, false).ok()) {
        for (const auto& subdir : subdirs) {
          dirs_to_search.emplace_back(subdir, depth + 1);
        }
      }
    }
  }

  return static_cast<int>(count);
}

// Bounded, symlink-loop-safe recursive search for SKILL.md files under
// `root`, pruning `.git`/`node_modules` subtrees. Used for plugin-cache
// discovery, where skill depth varies per marketplace repo layout and a
// single glob pattern (as used for kUserSkillRoots) can't cover it.
std::vector<std::string> findSkillMdFiles(const fs::path& root,
                                          int max_depth,
                                          size_t max_entries) {
  std::vector<std::string> found;
  if (!isDirectory(root).ok()) {
    return found;
  }

  size_t visited_entries = 0;
  std::unordered_set<int> visited_inos;
  std::vector<std::pair<std::string, int>> dirs_to_search;
  dirs_to_search.emplace_back(root.string(), 0);

  while (!dirs_to_search.empty() && visited_entries < max_entries) {
    auto [current_dir, depth] = dirs_to_search.back();
    dirs_to_search.pop_back();

    if (isDirVisited(visited_inos, current_dir)) {
      continue;
    }
    visited_entries++;

    std::vector<std::string> files;
    if (listFilesInDirectory(current_dir, files, false).ok()) {
      for (const auto& file : files) {
        if (fs::path(file).filename() == "SKILL.md") {
          found.push_back(file);
        }
      }
    }

    if (depth < max_depth) {
      std::vector<std::string> subdirs;
      if (listDirectoriesInDirectory(current_dir, subdirs, false).ok()) {
        for (const auto& subdir : subdirs) {
          auto name = fs::path(subdir).filename().string();
          if (name == ".git" || name == "node_modules") {
            continue;
          }
          dirs_to_search.emplace_back(subdir, depth + 1);
        }
      }
    }
  }

  return found;
}

// `directory_override`, when non-empty, is used as the row's `directory`
// column instead of the skill's own folder. This matters because SQLite
// residually re-checks EQUALS constraints against the values a table
// returns (osquery's xBestIndex never sets the `omit` flag - see
// osquery/sql/virtual_table.cpp) - so for project-scope rows, `directory`
// must echo back exactly the constraint value that triggered the scan
// (mirroring npm_packages' `directory` column), or `WHERE directory = 'X'`
// would silently return zero rows despite the scan finding real matches.
// User/system-scope rows aren't driven by that constraint, so they use the
// more informative per-skill folder instead.
void addSkillRow(const std::string& skill_md_path,
                 const std::string& agent,
                 std::string scope,
                 const std::string& uid,
                 const std::string& username,
                 const std::string& directory_override,
                 QueryData& results) {
  fs::path path(skill_md_path);
  fs::path skill_dir = path.parent_path();

  Row r;
  r["path"] = skill_md_path;
  r["directory"] =
      directory_override.empty() ? skill_dir.string() : directory_override;
  r["agent"] = agent;

  // A skill folder that also carries a `.claude-plugin/plugin.json`
  // manifest loads as a plugin, per Claude Code's "skills-directory
  // plugins" behavior; reclassify scope accordingly rather than hardcoding
  // an unstable plugin-cache root.
  if (pathExists(skill_dir / ".claude-plugin" / "plugin.json").ok()) {
    scope = "plugin";
  }
  r["scope"] = scope;

  r["sha256"] = hashFromFile(HASH_TYPE_SHA256, skill_md_path);

  int64_t size = 0;
  int64_t mtime = 0;
  bool stat_ok = statSkillFile(skill_md_path, size, mtime);
  r["size"] = BIGINT(size);
  r["mtime"] = BIGINT(mtime);

  ParsedSkill parsed;
  if (stat_ok && size > 0 &&
      static_cast<size_t>(size) <= kMaxFrontmatterFileSize) {
    std::string content;
    if (readFile(path, content, false).ok()) {
      parseFrontmatter(content, parsed);
    }
  }
  r["name"] = parsed.name;
  r["description"] = parsed.description;
  r["content"] = parsed.content;
  r["version"] = parsed.version;
  r["license"] = parsed.license;
  r["compatibility"] = parsed.compatibility;
  r["allowed_tools"] = parsed.allowed_tools;

  auto resources = countFiles(skill_dir, false);
  r["resource_count"] = INTEGER(resources > 0 ? resources - 1 : 0);
  r["script_count"] = INTEGER(countFiles(skill_dir, true));

  r["uid"] = uid;
  r["username"] = username;

  results.push_back(std::move(r));
}

void scanRoots(const fs::path& base,
              const std::vector<SkillRoot>& roots,
              const std::string& scope,
              const std::string& uid,
              const std::string& username,
              const std::string& directory_override,
              QueryData& results) {
  for (const auto& root : roots) {
    std::vector<std::string> matches;
    resolveFilePattern(base / root.relative_path / "%" / "SKILL.md", matches);
    for (const auto& match : matches) {
      addSkillRow(
          match, root.agent, scope, uid, username, directory_override, results);
    }
  }
}

} // namespace

QueryData genAgentSkills(QueryContext& context) {
  QueryData results;

  // User scope: personal skill directories under every home directory the
  // caller is allowed to see (usersFromContext honors a uid constraint, and
  // is restricted to the running user when unprivileged and unconstrained).
  auto users = usersFromContext(context);
  for (const auto& user : users) {
    auto uid = user.find("uid");
    auto username = user.find("username");
    auto directory = user.find("directory");
    if (uid == user.end() || username == user.end() ||
        directory == user.end() || directory->second.empty()) {
      continue;
    }

    scanRoots(fs::path(directory->second),
             kUserSkillRoots,
             "user",
             uid->second,
             username->second,
             "",
             results);

    auto plugin_skills =
        findSkillMdFiles(fs::path(directory->second) / kClaudePluginsRootRelative,
                        kMaxPluginScanDepth,
                        kMaxPluginScanEntries);
    for (const auto& skill_md : plugin_skills) {
      addSkillRow(
          skill_md, "claude", "plugin", uid->second, username->second, "", results);
    }
  }

  // System scope: the one admin-installed system location documented by a
  // vendor (OpenAI Codex's own docs). POSIX-only; there is no equivalent
  // documented Windows system root.
#if !defined(WIN32)
  scanRoots(fs::path("/"),
           {{kSystemSkillRootRelative, kSystemSkillAgent}},
           "system",
           "",
           "",
           "",
           results);
#endif

  // Project scope: never walked implicitly. Only scanned when the caller
  // supplies a directory constraint, matching npm_packages' `directory`
  // pattern, so this table never recurses through arbitrary checkouts.
  if (context.hasConstraint("directory", EQUALS)) {
    auto directories = context.constraints["directory"].getAll(EQUALS);
    for (const auto& directory : directories) {
      scanRoots(fs::path(directory),
               kProjectSkillRoots,
               "project",
               "",
               "",
               directory,
               results);
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery
