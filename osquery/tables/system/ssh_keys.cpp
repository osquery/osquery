#include <string>
#include <vector>

#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/system_utils.h"

namespace osquery {
namespace tables {

const std::vector<std::string> kSSHUserKeys = {".ssh/id_rsa"};

void genSSHkeyForHosts(const std::string& uid,
                        const std::string& directory,
                        QueryData& results) {
  for (const auto& kfile : kSSHUserKeys) {
    boost::filesystem::path keys_file = directory;
    keys_file /= kfile;
	
    std::string keys_content;
    if (!forensicReadFile(keys_file, keys_content).ok()) {
      // Cannot read a specific keys file.
      continue;
    }
    
    //file exists, create record for it
    Row r;
    r["uid"] = uid;
    r["key_file"] = keys_file.string();
    r["is_encrypted"] = INTEGER(0);

    // check to see if the file is encrypted
    if (keys_content.find("ENCRYPTED") != std::string::npos) {
      r["is_encrypted"] = INTEGER(1);
    }
    results.push_back(r);
    
    
  }
}

QueryData getSshKeys(QueryContext& context) {
  QueryData results;

  // Iterate over each user
  auto users = usersFromContext(context);
  for (const auto& row : users) {
    if (row.count("uid") > 0 && row.count("directory") > 0) {
      genSSHkeyForHosts(row.at("uid"), row.at("directory"), results);
    }
  }

  return results;
}
}
}
