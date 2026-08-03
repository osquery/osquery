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
#include <unordered_set>
#include <vector>

#include <boost/filesystem/path.hpp>

#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>

namespace osquery {
namespace tables {

/// Default pacman database path, matching pacman's own default DBPath.
const std::string kPacmanDbPath{"/var/lib/pacman"};

/// Installed packages are recorded in this subdirectory of the database path.
const std::string kPacmanLocalDir{"local"};

/// Metadata for an installed package is stored in this file.
const std::string kPacmanDescFile{"desc"};

/// Separator used to flatten fields that may hold more than one value.
const std::string kPacmanValueSeparator{","};

/// Maps a key in a local database 'desc' file to the column it populates.
const std::unordered_map<std::string, std::string> kPacmanDescColumns = {
    {"%NAME%", "name"},
    {"%VERSION%", "version"},
    {"%BASE%", "source"},
    {"%DESC%", "description"},
    {"%URL%", "url"},
    {"%LICENSE%", "licenses"},
    {"%GROUPS%", "groups"},
    {"%ARCH%", "arch"},
    {"%SIZE%", "size"},
    {"%PACKAGER%", "packager"},
    {"%BUILDDATE%", "build_time"},
    {"%INSTALLDATE%", "install_time"},
    {"%VALIDATION%", "validation"},
};

/// Fields libalpm reads as a list. Every other field holds a single value.
const std::unordered_set<std::string> kPacmanDescListFields = {
    "%LICENSE%",
    "%GROUPS%",
    "%VALIDATION%",
};

/**
 * @brief Determine whether a 'desc' file line introduces a new field.
 *
 * Keys are written as the field name wrapped in '%', for example '%NAME%'.
 * Any line of that shape starts a new field, including keys this table does
 * not map to a column, so that a database written by a newer pacman is still
 * parsed correctly rather than having unrecognized values folded into the
 * preceding field.
 */
static inline bool isPacmanDescKey(const std::string& line) {
  return line.size() > 2 && line.front() == '%' && line.back() == '%';
}

/**
 * @brief Translate a '%REASON%' value into the install_reason column.
 *
 * libalpm records '0' for a package the user asked for and '1' for one pulled
 * in to satisfy a dependency. The field is omitted for explicitly installed
 * packages in practice, and libalpm treats a missing value as explicit, so
 * that is the default applied by the caller.
 */
static std::string pacmanInstallReason(const std::string& reason) {
  if (reason == "0") {
    return "explicit";
  } else if (reason == "1") {
    return "dependency";
  }

  return "";
}

/**
 * @brief Parse the contents of a local database 'desc' file into a Row.
 *
 * The file is a sequence of keys, each followed by its value lines. A field
 * runs until the next key, which tolerates an entry written without the blank
 * line that libalpm uses to end a list. Fields libalpm reads as a list are
 * flattened into a comma separated value; every other field takes only its
 * first line, so a column never holds a joined value where one was not
 * intended.
 *
 * A Row without a 'name' is returned when the file does not describe a usable
 * package, which happens for a database entry left incomplete by an
 * interrupted transaction.
 */
Row parsePacmanDesc(const std::string& content) {
  std::unordered_map<std::string, std::vector<std::string>> fields;
  std::string key;

  // Each line arrives trimmed, so a key is matched exactly and values have no
  // surrounding whitespace. A line holding only whitespace, which is what a
  // blank line written with CRLF endings becomes, trims away to nothing and
  // carries no value.
  for (const auto& line : osquery::split(content, "\n")) {
    if (line.empty()) {
      continue;
    } else if (isPacmanDescKey(line)) {
      key = line;
    } else if (!key.empty()) {
      fields[key].push_back(line);
    }
  }

  Row r;
  if (fields.count("%NAME%") == 0) {
    return r;
  }

  for (const auto& field : fields) {
    const auto& column = kPacmanDescColumns.find(field.first);
    if (column == kPacmanDescColumns.end() || field.second.empty()) {
      continue;
    }

    if (kPacmanDescListFields.count(field.first) > 0) {
      r[column->second] = osquery::join(field.second, kPacmanValueSeparator);
    } else {
      r[column->second] = field.second.front();
    }
  }

  // A package the user requested has no recorded reason, so report the value
  // libalpm would infer. An unrecognized reason is left empty rather than
  // guessed at.
  auto reason = fields.find("%REASON%");
  if (reason == fields.end()) {
    r["install_reason"] = "explicit";
  } else if (!reason->second.empty()) {
    r["install_reason"] = pacmanInstallReason(reason->second.front());
  }

  // Packages that install no files of their own, such as the 'base' group
  // metapackage, record no size. libalpm reports these as zero.
  if (r.count("size") == 0) {
    r["size"] = "0";
  }

  return r;
}

QueryData genPacmanPackages(QueryContext& context) {
  QueryData results;

  std::vector<std::string> dbpaths;
  if (context.hasConstraint("dbpath", EQUALS)) {
    for (const auto& dbpath : context.constraints["dbpath"].getAll(EQUALS)) {
      dbpaths.push_back(dbpath);
    }
  } else {
    dbpaths.push_back(kPacmanDbPath);
  }

  for (const auto& dbpath : dbpaths) {
    const auto local_dir = boost::filesystem::path(dbpath) / kPacmanLocalDir;
    if (!isDirectory(local_dir.string()).ok()) {
      // Not a pacman based system, or a database path that does not exist.
      continue;
    }

    // Every installed package is a directory here. The database also holds a
    // version file alongside them, which resolving only folders skips.
    std::vector<std::string> package_dirs;
    if (!resolveFilePattern((local_dir / kSQLGlobWildcard).string(),
                            package_dirs,
                            GLOB_FOLDERS)
             .ok()) {
      VLOG(1) << "Could not list the pacman local database: "
              << local_dir.string();
      continue;
    }

    for (const auto& package_dir : package_dirs) {
      std::string content;
      const auto desc_path =
          boost::filesystem::path(package_dir) / kPacmanDescFile;
      if (!readFile(desc_path.string(), content).ok()) {
        // An entry without metadata cannot describe an installed package.
        continue;
      }

      auto r = parsePacmanDesc(content);
      if (r.count("name") == 0) {
        VLOG(1) << "Skipping malformed pacman database entry: " << package_dir;
        continue;
      }

      r["dbpath"] = dbpath;
      results.push_back(std::move(r));
    }
  }

  return results;
}
} // namespace tables
} // namespace osquery
