/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <set>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <boost/filesystem.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
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

// Subdirectory names pruned entirely from any bounded walk below: a skill
// installed from (or bundling) a git checkout or vendored JS dependencies
// can otherwise make resource/script counting expensive and inflate counts
// with unrelated files, potentially exhausting the scan budget before
// reaching the skill's own content.
const std::unordered_set<std::string> kPrunedDirNames = {
    ".git",
    "node_modules",
};

// SKILL.md files are recommended to stay under 500 lines / ~5000 tokens, so
// frontmatter is always near the start of the file. Rather than skipping
// parsing entirely for oversized files (which would silently blank out
// name/description/etc. for an otherwise-valid, just-large SKILL.md), only
// this many leading bytes are ever read: enough for any real frontmatter
// block, bounding per-row cost regardless of total file size. The body
// past it is never needed, since it is not reported.
const size_t kMaxFrontmatterFileSize = 256 * 1024;

// Skill directories are inherently shallow (SKILL.md plus scripts/,
// references/, assets/); these bound resource/script counting cost without
// exposing a query-configurable knob like npm_packages' max_depth.
const int kMaxResourceScanDepth = 8;
const size_t kMaxResourceScanDirs = 5000;

// Claude Code plugin installs put skills several directories deep under
// ~/.claude/plugins/ (marketplace source checkouts under marketplaces/, an
// active copy under cache/), and how deep depends on how each marketplace
// repo organizes its own plugins -- there is no single fixed glob shape
// across marketplaces the way there is for kUserSkillRoots, so this root is
// walked (bounded, pruning .git/node_modules) instead of glob-matched.
const std::string kClaudePluginsRootRelative = ".claude/plugins";
const int kMaxPluginScanDepth = 12;
const size_t kMaxPluginScanDirs = 20000;

struct ParsedSkill {
  std::string name;
  std::string description;
  std::string license;
  std::string compatibility;
  std::string allowed_tools;
  std::string version;
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
// Accepts both LF and CRLF line endings for the frontmatter fence itself;
// embedded CRLFs within the frontmatter body are handled by the per-line
// trim() calls below, which strip trailing '\r' along with other whitespace.
// Unrecognized keys are dropped rather than surfaced as a partial blob.
void parseFrontmatter(const std::string& file_content, ParsedSkill& skill) {
  size_t fence_len = 0;
  if (file_content.compare(0, 4, "---\n") == 0) {
    fence_len = 4;
  } else if (file_content.compare(0, 5, "---\r\n") == 0) {
    fence_len = 5;
  } else {
    return;
  }

  size_t close = std::string::npos;
  size_t fence_eol = std::string::npos;

  // Start the search one character before fence_len: for an empty
  // frontmatter block ("---\n---\n..."), the closing fence's leading '\n'
  // is the very same '\n' that ends the opening fence line, at index
  // fence_len - 1. Starting at fence_len would skip past it entirely.
  for (size_t search_pos = fence_len - 1;;) {
    auto pos = file_content.find("\n---", search_pos);
    if (pos == std::string::npos) {
      break;
    }

    const auto after = pos + 4; // just after "\n---"
    if (after == file_content.size()) {
      close = pos;
      fence_eol = after;
      break;
    } else if (file_content[after] == '\n') {
      close = pos;
      fence_eol = after + 1;
      break;
    } else if (file_content[after] == '\r' && after + 1 < file_content.size() &&
               file_content[after + 1] == '\n') {
      close = pos;
      fence_eol = after + 2;
      break;
    }

    search_pos = after;
  }

  if (close == std::string::npos) {
    return;
  }

  // close can be less than fence_len for an empty frontmatter block
  // ("---\n---\n..."), where the closing fence is found at fence_len - 1;
  // close - fence_len would underflow (both are size_t) and substr's clamped
  // count would silently turn the rest of the file into `frontmatter`.
  std::string frontmatter =
      close > fence_len ? file_content.substr(fence_len, close - fence_len)
                        : "";
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

// Inode-tracking loop guard, modeled on npm_packages.cpp's dirs_to_search
// queue + inode-tracking pattern (there is no existing depth-limited
// counting utility in osquery/filesystem/filesystem.h). platformLstat() is
// a stub that always fails on Windows (osquery/filesystem/windows/fileops.cpp),
// so this check is inert there -- a genuine symlink cycle would do
// redundant re-visiting rather than being caught here, bounded only by
// max_depth/max_dirs in the callers below, same as npm_packages.cpp today.
// A directory is identified by (device, inode). An inode number is only
// unique within its own filesystem, so the device has to be part of the
// key, and both are wider than an int on the platforms this runs on.
// Same shape as the recursive-glob visited set in
// osquery/filesystem/filesystem.cpp.
using DirIdentifier = std::pair<dev_t, ino_t>;

bool isDirVisited(std::set<DirIdentifier>& visited_dir_ids,
                  const std::string& path) {
  if (path.empty()) {
    return true;
  }

  struct stat d_stat;
  if (!platformLstat(path, d_stat).ok()) {
    return false;
  }

  auto [_, inserted] = visited_dir_ids.emplace(d_stat.st_dev, d_stat.st_ino);
  return !inserted;
}

// True if `candidate` is `root` itself or a path-segment-aligned descendant
// of it. A plain string-prefix check would wrongly accept "/a/bc" as being
// under "/a/b"; this requires the next character after the shared prefix
// to be a path separator.
bool isUnderRoot(const fs::path& root, const fs::path& candidate) {
  const auto root_str = root.string();
  const auto candidate_str = candidate.string();

  if (candidate_str == root_str) {
    return true;
  }

  if (root_str.empty() || candidate_str.size() <= root_str.size() ||
      candidate_str.compare(0, root_str.size(), root_str) != 0) {
    return false;
  }

  // If the root already ends with a separator (e.g. "/"), a prefix match is
  // sufficient.
  const char last = root_str.back();
  if (last == '/' || last == '\\') {
    return true;
  }

  const char next = candidate_str[root_str.size()];
  return next == '/' || next == '\\';
}

struct WalkedDir {
  std::string path;
  int depth;
  std::vector<std::string> files;
};

// Bounded and containment-checked directory walk shared by the per-skill
// resource/script counter and the plugin-cache SKILL.md finder below (each
// previously carried its own copy of this traversal). A subdirectory whose
// canonical path resolves outside `root` -- e.g. a symlink pointing
// elsewhere on disk -- is skipped rather than followed, so
// a skill directory can't use a symlink to pull unrelated parts of the
// filesystem into the scan. `skip_dir_names` subdirectory names are pruned
// entirely (e.g. ".git").
std::vector<WalkedDir> walkBounded(
    const fs::path& root,
    int max_depth,
    size_t max_dirs,
    const std::unordered_set<std::string>& skip_dir_names) {
  std::vector<WalkedDir> result;
  if (!isDirectory(root).ok()) {
    return result;
  }

  boost::system::error_code ec;
  fs::path root_canonical = fs::canonical(root, ec);
  if (ec) {
    return result;
  }

  size_t visited_dirs = 0;
  std::set<DirIdentifier> visited_dir_ids;
  std::vector<std::pair<std::string, int>> dirs_to_search;
  dirs_to_search.emplace_back(root.string(), 0);

  while (!dirs_to_search.empty() && visited_dirs < max_dirs) {
    auto [current_dir, depth] = dirs_to_search.back();
    dirs_to_search.pop_back();

    if (isDirVisited(visited_dir_ids, current_dir)) {
      continue;
    }
    visited_dirs++;

    // Individual files are canonicalized and containment-checked too, not
    // just subdirectories: a file entry can itself be a symlink (e.g. one
    // named SKILL.md pointing outside root), and callers like
    // findSkillMdFiles() read/hash whatever path is returned here.
    std::vector<std::string> files;
    if (!listFilesInDirectory(current_dir, files, false).ok()) {
      continue;
    }
    std::vector<std::string> contained_files;
    contained_files.reserve(files.size());
    for (const auto& file : files) {
      fs::path file_canonical = fs::canonical(file, ec);
      if (ec || !isUnderRoot(root_canonical, file_canonical)) {
        continue;
      }
      contained_files.push_back(file_canonical.string());
    }

    result.push_back(WalkedDir{current_dir, depth, std::move(contained_files)});

    if (depth >= max_depth) {
      continue;
    }

    std::vector<std::string> subdirs;
    if (!listDirectoriesInDirectory(current_dir, subdirs, false).ok()) {
      continue;
    }

    for (const auto& subdir : subdirs) {
      if (skip_dir_names.count(fs::path(subdir).filename().string())) {
        continue;
      }

      fs::path subdir_canonical = fs::canonical(subdir, ec);
      if (ec || !isUnderRoot(root_canonical, subdir_canonical)) {
        continue;
      }

      // Queued canonical: pushing the symlink's own path would let a
      // link to a sibling directory (ln -s ../references refs) be walked
      // twice, once under each name, double counting every file below it.
      dirs_to_search.emplace_back(subdir_canonical.string(), depth + 1);
    }
  }

  return result;
}

struct SkillCounts {
  int resource_count = 0;
  int script_count = 0;
};

// Counts bundled resources (every file under the skill directory, excluding
// any SKILL.md file) and files under scripts/, in a single traversal rather
// than two full passes over the same directory tree. A skill directory can
// legitimately contain more than one SKILL.md -- e.g. an example or
// reference file bundled by a skill-authoring plugin -- so all of them are
// excluded from resource_count, not just the first one found.
SkillCounts countSkillFiles(const fs::path& skill_dir) {
  SkillCounts counts;
  fs::path scripts_dir = skill_dir / "scripts";

  size_t total = 0;
  size_t skill_md_count = 0;
  for (const auto& dir : walkBounded(skill_dir,
                                     kMaxResourceScanDepth,
                                     kMaxResourceScanDirs,
                                     kPrunedDirNames)) {
    total += dir.files.size();
    if (isUnderRoot(scripts_dir, fs::path(dir.path))) {
      counts.script_count += static_cast<int>(dir.files.size());
    }
    for (const auto& file : dir.files) {
      if (fs::path(file).filename() == "SKILL.md") {
        skill_md_count++;
      }
    }
  }

  counts.resource_count =
      total > skill_md_count ? static_cast<int>(total - skill_md_count) : 0;
  return counts;
}

// Bounded recursive search for SKILL.md files under `root`, pruning
// `.git`/`node_modules` subtrees. Used for plugin-cache discovery, where
// skill depth varies per marketplace repo layout and a single glob pattern
// (as used for kUserSkillRoots) can't cover it.
std::vector<std::string> findSkillMdFiles(const fs::path& root,
                                          int max_depth,
                                          size_t max_dirs) {
  std::vector<std::string> found;
  for (const auto& dir :
       walkBounded(root, max_depth, max_dirs, kPrunedDirNames)) {
    for (const auto& file : dir.files) {
      if (fs::path(file).filename() == "SKILL.md") {
        found.push_back(file);
      }
    }
  }
  return found;
}

// Reads up to `max_bytes` of `path`'s content. Used to bound the cost of
// frontmatter parsing on a large SKILL.md.
//
// Opened non-blocking, the way osquery's own readFile() does, and special
// files are skipped rather than read: anyone who can write to a skills
// directory can leave a FIFO named SKILL.md there, and a blocking open on
// one with no writer never returns, which would hang the query for good
// without burning the CPU the watchdog reaps a worker for.
bool readFilePrefix(const std::string& path,
                    size_t max_bytes,
                    std::string& content) {
  PlatformFile file(path, PF_OPEN_EXISTING | PF_READ | PF_NONBLOCK);
  if (!file.isValid() || file.isSpecialFile()) {
    return false;
  }

  content.resize(max_bytes);
  auto bytes_read = file.read(&content[0], max_bytes);
  if (bytes_read < 0) {
    content.clear();
    return false;
  }

  content.resize(static_cast<size_t>(bytes_read));
  return true;
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

  // The hash, size and modification time of SKILL.md are what the file
  // table already reports, and are joinable on path, so they are not
  // repeated here.
  ParsedSkill parsed;
  std::string file_content;
  if (readFilePrefix(skill_md_path, kMaxFrontmatterFileSize, file_content)) {
    parseFrontmatter(file_content, parsed);
  }

  r["name"] = parsed.name;
  r["description"] = parsed.description;
  r["version"] = parsed.version;
  r["license"] = parsed.license;
  r["compatibility"] = parsed.compatibility;
  r["allowed_tools"] = parsed.allowed_tools;

  auto counts = countSkillFiles(skill_dir);
  r["resource_count"] = INTEGER(counts.resource_count);
  r["script_count"] = INTEGER(counts.script_count);

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
    fs::path expected_root = base / root.relative_path;

    // Canonicalize the expected root once; a symlink at this level (e.g. a
    // dotfile-managed ~/.claude) is a legitimate, common setup. What isn't
    // legitimate is a *matched* SKILL.md resolving somewhere else entirely,
    // which is checked below per match.
    boost::system::error_code ec;
    fs::path expected_root_canonical = fs::canonical(expected_root, ec);
    if (ec) {
      continue;
    }

    std::vector<std::string> matches;
    resolveFilePattern(expected_root / "%" / "SKILL.md", matches);
    for (const auto& match : matches) {
      fs::path match_canonical = fs::canonical(match, ec);
      if (ec || !isUnderRoot(expected_root_canonical, match_canonical)) {
        continue;
      }

      addSkillRow(match_canonical.string(),
                  root.agent,
                  scope,
                  uid,
                  username,
                  directory_override,
                  results);
    }
  }
}

} // namespace

QueryData genAIAgentSkills(QueryContext& context) {
  QueryData results;

  // User scope: personal skill directories under each home directory.
  // usersFromContext honors a uid constraint; without one it returns only
  // the user osquery is running as, whatever its privilege, so an
  // unconstrained query on a root daemon reports root's skills alone. Ask
  // for a uid, or join the users table, to reach anybody else's.
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

    auto plugin_skills = findSkillMdFiles(
        fs::path(directory->second) / kClaudePluginsRootRelative,
        kMaxPluginScanDepth,
        kMaxPluginScanDirs);
    for (const auto& skill_md : plugin_skills) {
      addSkillRow(skill_md,
                  "claude",
                  "plugin",
                  uid->second,
                  username->second,
                  "",
                  results);
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
