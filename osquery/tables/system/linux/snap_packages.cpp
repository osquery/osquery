/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <unordered_map>
#include <vector>

#include <yaml-cpp/yaml.h>

#include <boost/filesystem.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/json/json.h>

namespace osquery {
namespace tables {

const std::string kSnapdStatePath{"/var/lib/snapd/state.json"};
const std::vector<std::string> kSnapMountRoots{"/snap", "/var/lib/snapd/snap"};

struct SnapStateInfo {
  std::string revision;
  std::string channel;
  std::string snap_id;
};

/**
 * @brief Parse a snap.yaml string into a Row using yaml-cpp.
 */
Row parseSnapYaml(const std::string& content) {
  Row r;

  YAML::Node doc;
  try {
    doc = YAML::Load(content);
  } catch (const YAML::Exception& e) {
    VLOG(1) << "snap_packages: failed to parse snap.yaml: " << e.what();
    return r;
  }

  if (!doc.IsMap()) {
    return r;
  }

  static const std::unordered_map<std::string, std::string> kScalarColumns = {
      {"name", "name"},
      {"version", "version"},
      {"summary", "summary"},
      {"description", "description"},
      {"type", "type"},
      {"confinement", "confinement"},
      {"base", "base"},
      {"license", "license"},
      {"grade", "grade"},
  };

  for (const auto& [yaml_key, col_name] : kScalarColumns) {
    const auto& node = doc[yaml_key];
    if (node && node.IsScalar()) {
      r[col_name] = node.as<std::string>();
    }
  }

  // architectures may be a simple list or a list of build-on/run-on maps.
  const auto& archs_node = doc["architectures"];
  if (archs_node && archs_node.IsSequence()) {
    std::vector<std::string> archs;
    for (const auto& item : archs_node) {
      if (item.IsScalar()) {
        archs.push_back(item.as<std::string>());
      } else if (item.IsMap()) {
        const auto& run_on = item["run-on"];
        if (run_on && run_on.IsScalar()) {
          archs.push_back(run_on.as<std::string>());
        } else if (run_on && run_on.IsSequence()) {
          for (const auto& a : run_on) {
            archs.push_back(a.as<std::string>());
          }
        }
      }
    }
    r["architectures"] = join(archs, ",");
  }

  return r;
}

/**
 * @brief Parse /var/lib/snapd/state.json for per-snap state.
 *
 * Returns a map from snap name to SnapStateInfo containing the current
 * revision, tracking channel, and snap-id flags.
 */
static std::unordered_map<std::string, SnapStateInfo> parseSnapdState(
    const std::string& json_content) {
  std::unordered_map<std::string, SnapStateInfo> result;

  auto doc = JSON::newObject();
  if (!doc.fromString(json_content).ok() || !doc.doc().IsObject()) {
    return result;
  }

  if (!doc.doc().HasMember("data") || !doc.doc()["data"].IsObject()) {
    return result;
  }

  const auto& data = doc.doc()["data"];
  if (!data.HasMember("snaps") || !data["snaps"].IsObject()) {
    return result;
  }

  const auto& snaps = data["snaps"];
  for (auto it = snaps.MemberBegin(); it != snaps.MemberEnd(); ++it) {
    if (!it->value.IsObject()) {
      continue;
    }

    SnapStateInfo info;
    const auto& snap = it->value;

    if (snap.HasMember("current") && snap["current"].IsString()) {
      info.revision = snap["current"].GetString();
    }

    if (snap.HasMember("channel") && snap["channel"].IsString()) {
      info.channel = snap["channel"].GetString();
    }

    // snap-id lives inside each sequence element; find the current revision.
    if (snap.HasMember("sequence") && snap["sequence"].IsArray()) {
      for (const auto& seq_elem : snap["sequence"].GetArray()) {
        if (!seq_elem.IsObject()) {
          continue;
        }
        const bool revision_matches =
            seq_elem.HasMember("revision") && seq_elem["revision"].IsString() &&
            seq_elem["revision"].GetString() == info.revision;
        if (revision_matches && seq_elem.HasMember("snap-id") &&
            seq_elem["snap-id"].IsString()) {
          info.snap_id = seq_elem["snap-id"].GetString();
          break;
        }
      }
    }

    // Fallback: snap-id may also appear at the snap-state level.
    if (info.snap_id.empty() && snap.HasMember("snap-id") &&
        snap["snap-id"].IsString()) {
      info.snap_id = snap["snap-id"].GetString();
    }

    result[it->name.GetString()] = std::move(info);
  }

  return result;
}

QueryData genSnapPackages(QueryContext& context) {
  QueryData results;

  boost::filesystem::path snap_mount_root;
  for (const auto& root : kSnapMountRoots) {
    if (isDirectory(root).ok()) {
      snap_mount_root = root;
      break;
    }
  }

  if (snap_mount_root.empty()) {
    return results;
  }

  // Parse state.json for channel, revision, and snap-id flags.
  // This file is root-readable only; missing state is handled gracefully.
  std::unordered_map<std::string, SnapStateInfo> snap_states;
  {
    std::string state_json;
    if (readFile(kSnapdStatePath, state_json, false).ok()) {
      snap_states = parseSnapdState(state_json);
    }
  }

  // Enumerate installed snaps from <snap mount root>/<name>/ directories.
  std::vector<std::string> snap_dirs;
  if (!resolveFilePattern(
           snap_mount_root / kSQLGlobWildcard, snap_dirs, GLOB_FOLDERS)
           .ok()) {
    VLOG(1) << "snap_packages: could not list " << snap_mount_root.string();
    return results;
  }

  for (const auto& snap_dir_str : snap_dirs) {
    const boost::filesystem::path snap_dir(snap_dir_str);
    // boost path::filename() returns "." for paths with a trailing separator.
    const std::string snap_name =
        snap_dir.filename() == "." ? snap_dir.parent_path().filename().string()
                                   : snap_dir.filename().string();

    // /snap/bin holds command symlinks, not a snap package.
    if (snap_name == "bin" || snap_name.empty()) {
      continue;
    }

    // Determine the current revision from state.json or the 'current' symlink.
    std::string revision;
    const auto state_it = snap_states.find(snap_name);
    if (state_it != snap_states.end() && !state_it->second.revision.empty()) {
      revision = state_it->second.revision;
    } else {
      boost::system::error_code ec;
      const auto target =
          boost::filesystem::read_symlink(snap_dir / "current", ec);
      if (ec) {
        VLOG(1) << "snap_packages: no revision for " << snap_name;
        continue;
      }
      revision = target.filename().string();
    }

    if (revision.empty()) {
      continue;
    }

    // Read the snap metadata from the mounted squashfs.
    const auto yaml_path = snap_dir / revision / "meta" / "snap.yaml";
    std::string yaml_content;
    if (!readFile(yaml_path.string(), yaml_content, false).ok()) {
      VLOG(1) << "snap_packages: could not read snap.yaml for " << snap_name;
      continue;
    }

    Row r = parseSnapYaml(yaml_content);

    if (!r.count("name") || r["name"].empty()) {
      r["name"] = snap_name;
    }

    r["revision"] = revision;

    if (state_it != snap_states.end()) {
      r["channel"] = state_it->second.channel;
      r["snap_id"] = state_it->second.snap_id;
    } else {
      if (!r.count("type") || r["type"].empty()) {
        r["type"] = "app";
      }
      if (!r.count("confinement") || r["confinement"].empty()) {
        r["confinement"] = "strict";
      }
      if (!r.count("grade") || r["grade"].empty()) {
        r["grade"] = "stable";
      }
    }

    results.push_back(std::move(r));
  }

  return results;
}

} // namespace tables
} // namespace osquery
