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

const std::vector<std::string> kSSHKeyTypes = {"ssh-rsa",
                                               "ssh-ed25519",
                                               "ecdsa-sha2-nistp256",
                                               "ecdsa-sha2-nistp384",
                                               "ecdsa-sha2-nistp521"};

bool isKeyRingLabelOptExist(const std::string& line) {
  const std::string keyRingLabelOptionPrefix = "zos-key-ring-label=";
  for (const auto& option : split(line, ",")) {
    if (option.compare(0,
                       keyRingLabelOptionPrefix.size(),
                       keyRingLabelOptionPrefix) == 0) {
      return true;
    }
  }

  return false;
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
        auto splitted_line = split(line, " ");

        auto splitted_line_part = splitted_line.begin();
        for (; splitted_line_part != splitted_line.end();
             splitted_line_part++) {
          if (find(kSSHKeyTypes.begin(),
                   kSSHKeyTypes.end(),
                   *splitted_line_part) != kSSHKeyTypes.end()) {
            break;
          }
        }

        // The current line does not contain key type.
        if (splitted_line_part == splitted_line.end()) {
          // rest of the line after 'zos-key-ring-label' should be ignored.
          if (isKeyRingLabelOptExist(line)) {
            Row r = {{"uid", uid},
                     {"options", line},
                     {"key_file", keys_file.string()},
                     {"pid_with_namespace", "0"}};
            results.push_back(r);
          }
          continue;
        }

        // Key type does not exist in the current line.
        if (++splitted_line_part == splitted_line.end()) {
          continue;
        }

        std::string options;
        std::string key_type;
        std::string key;
        std::string comment;

        // Check if options are supplied for the current line.
        if (splitted_line_part != splitted_line.begin()) {
          std::vector<std::string> options_parts{splitted_line.begin(),
                                                 --splitted_line_part};
          options = osquery::join(options_parts, " ");
        }

        key_type = *splitted_line_part;
        if (++splitted_line_part == splitted_line.end()) {
          // Actual key is required.
          continue;
        }

        key = *splitted_line_part;
        if (++splitted_line_part != splitted_line.end()) {
          std::vector<std::string> comment_parts{splitted_line_part,
                                                 splitted_line.end()};
          comment = osquery::join(comment_parts, " ");
        }

        Row r = {{"uid", uid},
                 {"options", options},
                 {"algorithm", key_type},
                 {"key", key},
                 {"comment", comment},
                 {"key_file", keys_file.string()},
                 {"pid_with_namespace", "0"}};
        results.push_back(r);
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
