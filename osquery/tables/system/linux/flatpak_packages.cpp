/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/trim.h>

namespace osquery {
namespace tables {

namespace {
const std::string kFlatpakSystemBase{"/var/lib/flatpak"};
const std::string kFlatpakUserSuffix{".local/share/flatpak"};
} // namespace

/**
 * @brief Parse a flatpak GLib-keyfile style metadata file.
 *
 * Returns a map of "Section.key" -> value for every key in the file. Only
 * the first value of a key within a section is stored; duplicate keys
 * (unusual in practice) are silently ignored.
 */
std::unordered_map<std::string, std::string> parseFlatpakMetadata(
    const std::string& content) {
  std::unordered_map<std::string, std::string> result;
  std::string current_section;

  for (const auto& raw_line : split(content, "\n")) {
    const std::string_view line = trim(raw_line);

    // Skip blank lines and comments.
    if (line.empty() || line[0] == '#' || line[0] == ';') {
      continue;
    }

    if (line[0] == '[') {
      const auto end = line.find(']');
      if (end != std::string::npos && end > 1) {
        current_section = line.substr(1, end - 1);
      }
      continue;
    }

    if (current_section.empty()) {
      continue;
    }

    const auto eq = line.find('=');
    if (eq == std::string::npos) {
      continue;
    }

    std::string key{line.substr(0, eq)};
    // Skip locale-specific keys like "Name[de]".
    if (key.find('[') != std::string::npos) {
      continue;
    }

    const std::string full_key = current_section + "." + key;
    if (result.count(full_key) == 0) {
      result[full_key] = line.substr(eq + 1);
    }
  }

  return result;
}

/**
 * @brief Recursively extract plain text from a boost XML ptree node.
 *
 * Walks all non-attribute, non-comment children and concatenates their
 * text data with a single space separator, producing a plain-text
 * representation of the element's content.
 */
static std::string extractXmlText(const boost::property_tree::ptree& node) {
  std::string result = node.data();

  for (const auto& child : node) {
    if (child.first == "<xmlattr>" || child.first == "<xmlcomment>") {
      continue;
    }
    const std::string child_text = extractXmlText(child.second);
    if (!child_text.empty()) {
      if (!result.empty()) {
        result += ' ';
      }
      result += child_text;
    }
  }

  // Collapse runs of whitespace introduced by multiline XML indentation.
  std::string out;
  out.reserve(result.size());
  bool last_space = false;
  for (char c : result) {
    if (c == '\n' || c == '\r' || c == '\t') {
      c = ' ';
    }
    if (c == ' ') {
      if (!last_space && !out.empty()) {
        out += c;
      }
      last_space = true;
    } else {
      out += c;
      last_space = false;
    }
  }

  // Trim trailing space.
  return std::string(trim(out));
}

/**
 * @brief Parse an AppStream metainfo or appdata XML file into a Row.
 *
 * Fills in the "version", "summary", "description", "license",
 * "homepage", and "developer_name" columns when present.
 */
void parseFlatpakAppStream(const std::string& content, Row& r) {
  namespace pt = boost::property_tree;

  pt::ptree tree;
  try {
    std::istringstream ss(content);
    pt::read_xml(ss, tree);
  } catch (const pt::xml_parser::xml_parser_error& e) {
    VLOG(1) << "flatpak_packages: failed to parse AppStream XML: " << e.what();
    return;
  }

  // The root element can be <component> or the older <application>.
  const pt::ptree* comp = nullptr;
  for (const auto& root_key : {"component", "application"}) {
    auto opt = tree.get_child_optional(root_key);
    if (opt) {
      comp = &opt.get();
      break;
    }
  }
  if (comp == nullptr) {
    return;
  }

  auto get_text = [&comp](const char* key) -> std::string {
    auto opt = comp->get_child_optional(key);
    if (!opt) {
      return "";
    }
    return opt->data();
  };

  r["name"] = get_text("name");
  r["summary"] = get_text("summary");
  r["license"] = get_text("project_license");
  r["developer_name"] = get_text("developer_name");
  // AppStream 1.0 moved developer name inside <developer><name>.
  if (r["developer_name"].empty()) {
    r["developer_name"] = get_text("developer.name");
  }

  // Find the "homepage" URL from <url type="homepage">.
  for (const auto& item : *comp) {
    if (item.first == "url") {
      const auto url_type = item.second.get<std::string>("<xmlattr>.type", "");
      if (url_type == "homepage") {
        r["homepage"] = item.second.data();
        break;
      }
    }
  }

  // Description: join text from all immediate <p> and <li> children.
  auto desc_node = comp->get_child_optional("description");
  if (desc_node) {
    std::string desc;
    for (const auto& child : *desc_node) {
      if (child.first == "<xmlattr>" || child.first == "<xmlcomment>") {
        continue;
      }
      const std::string text = extractXmlText(child.second);
      if (text.empty()) {
        continue;
      }
      if (!desc.empty()) {
        desc += ' ';
      }
      desc += text;
    }
    r["description"] = desc;
  }

  // Version from the most-recently listed <release>.
  auto releases_node = comp->get_child_optional("releases");
  if (releases_node) {
    for (const auto& release : *releases_node) {
      if (release.first == "release") {
        const std::string ver =
            release.second.get<std::string>("<xmlattr>.version", "");
        if (!ver.empty()) {
          r["version"] = ver;
          break;
        }
      }
    }
  }
}

/**
 * @brief Return the path of the AppStream metadata file for @p app_id under
 * the given @p files_dir, or an empty string if none is found.
 *
 * Checks the AppStream 1.0 metainfo/ location first, then the legacy
 * appdata/ location.
 */
static std::string findAppStreamPath(const boost::filesystem::path& files_dir,
                                     const std::string& app_id) {
  namespace fs = boost::filesystem;

  const auto metainfo =
      files_dir / "share" / "metainfo" / (app_id + ".metainfo.xml");
  if (fs::exists(metainfo)) {
    return metainfo.string();
  }

  const auto appdata =
      files_dir / "share" / "appdata" / (app_id + ".appdata.xml");
  if (fs::exists(appdata)) {
    return appdata.string();
  }

  return "";
}

// Returns the last path component, handling paths with a trailing separator.
static std::string filenameOf(const boost::filesystem::path& p) {
  const auto f = p.filename();
  return (f == "." ? p.parent_path().filename() : f).string();
}

// Origin is encoded in the binary OSTree deploy GVariant, not a plain file;
// the same information is readable from the OSTree remote tracking refs.
static std::string findFlatpakOrigin(const std::string& base_path,
                                     const std::string& type,
                                     const std::string& app_id,
                                     const std::string& arch,
                                     const std::string& branch,
                                     const std::string& commit) {
  namespace fs = boost::filesystem;

  const fs::path remotes_dir =
      fs::path(base_path) / "repo" / "refs" / "remotes";

  std::vector<std::string> remote_dirs;
  if (!resolveFilePattern(
           (remotes_dir / kSQLGlobWildcard).string(), remote_dirs, GLOB_FOLDERS)
           .ok()) {
    return "";
  }

  for (const auto& remote_dir_str : remote_dirs) {
    const fs::path remote_dir(remote_dir_str);
    const fs::path ref_path = remote_dir / type / app_id / arch / branch;

    std::string ref_content;
    if (!readFile(ref_path.string(), ref_content, false).ok()) {
      continue;
    }
    if (std::string(trim(ref_content)) == commit) {
      return filenameOf(remote_dir);
    }
  }

  return "";
}

/**
 * @brief Generate rows for every installed Flatpak package under @p base_path.
 *
 * Enumerates both the "app" and "runtime" subdirectories.  For each
 * deployment the function reads:
 *   - the GLib-keyfile metadata for name/runtime/type,
 *   - the OSTree repo refs for the remote name,
 *   - the AppStream XML file (metainfo or appdata) for version/summary/
 *     description/license/homepage/developer_name.
 */
static void genFlatpakFromBase(const std::string& base_path,
                               const std::string& installation,
                               QueryData& results) {
  namespace fs = boost::filesystem;

  for (const auto* type : {"app", "runtime"}) {
    const fs::path type_dir = fs::path(base_path) / type;
    if (!isDirectory(type_dir.string()).ok()) {
      continue;
    }

    std::vector<std::string> id_dirs;
    if (!resolveFilePattern(
             (type_dir / kSQLGlobWildcard).string(), id_dirs, GLOB_FOLDERS)
             .ok()) {
      continue;
    }

    for (const auto& id_dir_str : id_dirs) {
      const fs::path id_dir(id_dir_str);
      const std::string app_id = filenameOf(id_dir);
      if (app_id.empty()) {
        continue;
      }

      std::vector<std::string> arch_dirs;
      if (!resolveFilePattern(
               (id_dir / kSQLGlobWildcard).string(), arch_dirs, GLOB_FOLDERS)
               .ok()) {
        continue;
      }

      for (const auto& arch_dir_str : arch_dirs) {
        const fs::path arch_dir(arch_dir_str);
        const std::string arch = filenameOf(arch_dir);

        std::vector<std::string> branch_dirs;
        if (!resolveFilePattern((arch_dir / kSQLGlobWildcard).string(),
                                branch_dirs,
                                GLOB_FOLDERS)
                 .ok()) {
          continue;
        }

        for (const auto& branch_dir_str : branch_dirs) {
          const fs::path branch_dir(branch_dir_str);
          const std::string branch = filenameOf(branch_dir);

          // Resolve the current commit from the "active" symlink.
          boost::system::error_code ec;
          const auto active_target =
              fs::read_symlink(branch_dir / "active", ec);
          if (ec) {
            VLOG(1) << "flatpak_packages: no active symlink for " << app_id
                    << "/" << arch << "/" << branch;
            continue;
          }
          const std::string commit = active_target.filename().string();
          if (commit.empty()) {
            continue;
          }

          const fs::path deploy_dir = branch_dir / commit;

          // Locale sub-deployments append a "-<locale>" suffix to the
          // OSTree checksum (e.g. "abc123...-en"); strip it for ref lookups.
          const auto suffix_start =
              commit.find_first_not_of("0123456789abcdef");
          const std::string commit_hash = commit.substr(0, suffix_start);

          // Read and parse the metadata INI file.
          std::string metadata_content;
          if (!readFile(
                   (deploy_dir / "metadata").string(), metadata_content, false)
                   .ok()) {
            VLOG(1) << "flatpak_packages: cannot read metadata for " << app_id;
            continue;
          }

          const auto meta = parseFlatpakMetadata(metadata_content);

          // Determine the metadata section name ([Application] or [Runtime]).
          const std::string meta_section =
              (std::string_view(type) == "app") ? "Application" : "Runtime";

          Row r;
          r["name"] = "";
          r["app_id"] = app_id;
          r["version"] = "";
          r["arch"] = arch;
          r["branch"] = branch;
          r["commit"] = commit_hash;
          r["origin"] = "";
          r["runtime"] = "";
          r["type"] = type;
          r["installation"] = installation;
          r["summary"] = "";
          r["description"] = "";
          r["license"] = "";
          r["homepage"] = "";
          r["developer_name"] = "";

          const auto runtime_it = meta.find(meta_section + ".runtime");
          r["runtime"] = (runtime_it != meta.end()) ? runtime_it->second : "";

          r["origin"] = findFlatpakOrigin(
              base_path, type, app_id, arch, branch, commit_hash);

          // Parse AppStream XML when available.
          const std::string appstream_path =
              findAppStreamPath(deploy_dir / "files", app_id);
          if (!appstream_path.empty()) {
            std::string appstream_content;
            if (readFile(appstream_path, appstream_content, false).ok()) {
              parseFlatpakAppStream(appstream_content, r);
            }
          }

          results.push_back(std::move(r));
        }
      }
    }
  }
}

QueryData genFlatpakPackages(QueryContext& context) {
  QueryData results;

  genFlatpakFromBase(kFlatpakSystemBase, "system", results);

  // Enumerate per-user installations from ~/.local/share/flatpak.
  const auto users = usersFromContext(context, /* all= */ true);
  for (const auto& user : users) {
    const auto dir_it = user.find("directory");
    if (dir_it == user.end() || dir_it->second.empty()) {
      continue;
    }
    genFlatpakFromBase(
        dir_it->second + "/" + kFlatpakUserSuffix, "user", results);
  }

  return results;
}

} // namespace tables
} // namespace osquery
