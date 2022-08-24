/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>

#include <osquery/tables/system/posix/authorized_keys.h>
#include <osquery/tables/system/system_utils.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/system/system.h>
#include <osquery/worker/ipc/platform_table_container_ipc.h>

namespace osquery {
namespace tables {

const std::vector<std::string> kSSHAuthorizedkeys = {".ssh/authorized_keys",
                                                     ".ssh/authorized_keys2"};
const std::string kKeyRingLabelOptionPrefix = "zos-key-ring-label=";
const std::vector<std::string> kSSHKeyTypes = {"ssh-rsa",
                                               "ssh-ed25519",
                                               "ecdsa-sha2-nistp256",
                                               "ecdsa-sha2-nistp384",
                                               "ecdsa-sha2-nistp521"};
const std::string kWhitespace{"\t "};

bool KeyRingLabelOptExists(const std::string& line) {
  for (const auto& option : split(line, ",")) {
    if (option.compare(0,
                       kKeyRingLabelOptionPrefix.size(),
                       kKeyRingLabelOptionPrefix) == 0) {
      return true;
    }
  }

  return false;
}

void GenerateKeyRow(const std::string& line,
                    const std::string& key_type,
                    const std::string& uid,
                    const std::string& keys_file,
                    size_t key_type_pos,
                    QueryData& results) {
  Row r;

  // Check if current line has options before the actual key.
  if (key_type_pos > 0) {
    std::string options = line.substr(0, key_type_pos);
    r["options"] = line.substr(0, options.find_last_not_of(kWhitespace) + 1);
  }

  // Find where the actual key starts.
  size_t key_start_pos =
      line.find_first_not_of(kWhitespace, key_type_pos + key_type.length());
  if (key_start_pos == std::string::npos) {
    return;
  }

  // Extract the key comment.
  size_t key_end_pos = line.find_first_of(kWhitespace, key_start_pos);
  if (key_end_pos != std::string::npos) {
    size_t comment_start_pos = line.find_first_not_of(kWhitespace, key_end_pos);
    if (key_end_pos != std::string::npos) {
      r["comment"] = line.substr(comment_start_pos);
      r["key"] = line.substr(key_start_pos, key_end_pos - key_start_pos);
    }
  } else {
    r["key"] = line.substr(key_start_pos);
  }

  r["algorithm"] = key_type;
  r["key_file"] = keys_file;
  r["uid"] = uid;
  r["pid_with_namespace"] = "0";
  results.push_back(r);
}

void genSSHkeysForUser(const std::string& uid,
                       const std::string& gid,
                       const std::string& directory,
                       QueryData& results,
                       Logger& logger) {
  for (const auto& kfile : kSSHAuthorizedkeys) {
    boost::filesystem::path keys_file = directory;
    keys_file /= kfile;

    std::string keys_content;

    if (!pathExists(keys_file).ok()) {
      // no authorized key file present, keep going
      continue;
    }

    auto s = forensicReadFile(keys_file, keys_content, false, false);
    if (!s.ok()) {
      // Cannot read a specific keys file.
      logger.log(google::GLOG_ERROR, s.getMessage());
      return;
    }

    // Protocol 1 public key consist of: options, bits, exponent, modulus,
    // comment; Protocol 2 public key consist of: options, keytype,
    // base64-encoded key, comment.
    for (const auto& line : split(keys_content, "\n")) {
      if (!line.empty() && line[0] != '#') {
        bool key_type_found = false;
        // Iterate over known key types.
        for (const auto& key_type : kSSHKeyTypes) {
          auto key_type_start_pos = line.find(key_type);
          if (key_type_start_pos == std::string::npos) {
            continue;
          }

          auto key_type_end_pos = key_type_start_pos + key_type.length();
          // Make sure key type is fully matched.
          if (line[key_type_end_pos] != ' ' && line[key_type_end_pos] != '\t') {
            continue;
          }

          GenerateKeyRow(line,
                         key_type,
                         uid,
                         keys_file.string(),
                         key_type_start_pos,
                         results);

          key_type_found = true;
          break;
        }

        // If key type can't be found and options are supplied,
        // Check the existence of the 'zos-key-ring-label' parameter in the
        // options section. If so, only options should be set in current row.
        if (!key_type_found && KeyRingLabelOptExists(line)) {
          Row r = {{"uid", uid},
                   {"options", line},
                   {"key_file", keys_file.string()},
                   {"pid_with_namespace", "0"}};
          results.push_back(r);
        }
      }
    }
  }
}

QueryData getAuthorizedKeysImpl(QueryContext& context, Logger& logger) {
  QueryData results;

  // Iterate over each user
  QueryData users = usersFromContext(context);
  for (const auto& row : users) {
    auto uid = row.find("uid");
    auto gid = row.find("gid");
    auto directory = row.find("directory");
    if (uid != row.end() && gid != row.end() && directory != row.end()) {
      genSSHkeysForUser(
          uid->second, gid->second, directory->second, results, logger);
    }
  }

  return results;
}

QueryData getAuthorizedKeys(QueryContext& context) {
  if (hasNamespaceConstraint(context)) {
    return generateInNamespace(
        context, "authorized_keys", getAuthorizedKeysImpl);
  } else {
    GLOGLogger logger;
    return getAuthorizedKeysImpl(context, logger);
  }
}
}
}
