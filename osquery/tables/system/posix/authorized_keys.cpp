/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>
#include <vector>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/system_utils.h"

namespace osquery {
namespace tables {

const std::vector<std::string> kSSHAuthorizedkeys = {".ssh/authorized_keys",
                                                     ".ssh/authorized_keys2"};

void genSSHkeysForUser(const std::string& uid,
                       const std::string& directory,
                       QueryData& results) {
  for (const auto& kfile : kSSHAuthorizedkeys) {
    boost::filesystem::path keys_file = directory;
    keys_file /= kfile;

    std::string keys_content;
    if (!osquery::forensicReadFile(keys_file, keys_content).ok()) {
      // Cannot read a specific keys file.
      continue;
    }
    // Protocol 1 public key consist of: options, bits, exponent, modulus,
    // comment; Protocol 2 public key consist of: options, keytype,
    // base64-encoded key, comment.
    for (const auto& line : split(keys_content, "\n")) {
      if (!line.empty() && line[0] != '#') {
        Row r;
        r["uid"] = uid;
        r["key"] = line;
        r["key_file"] = keys_file.string();
        results.push_back(r);
      }
    }
  }
}

QueryData getAuthorizedKeys(QueryContext& context) {
  QueryData results;

  // Iterate over each user
  QueryData users = usersFromContext(context);
  for (const auto& row : users) {
    if (row.count("uid") > 0 && row.count("directory") > 0) {
      genSSHkeysForUser(row.at("uid"), row.at("directory"), results);
    }
  }

  return results;
}
}
}
