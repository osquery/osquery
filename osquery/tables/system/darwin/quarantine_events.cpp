// Copyright 2004-present Facebook. All Rights Reserved.

#include <CoreFoundation/CoreFoundation.h>

#include <boost/algorithm/string/trim.hpp>
#include <boost/lexical_cast.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"

#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/replace.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

#include <iostream> // I/O
#include <utility>

namespace osquery {
namespace tables {

typedef std::pair<std::string, std::string> UserAndDatabase;

// http://www.forensicswiki.org/wiki/Mac_OS_X#Quarantine_event_database
const std::vector<std::string> kDatabasePaths = {
    "/Users/$USER/Library/Preferences/"
    "com.apple.LaunchServices.QuarantineEvents",
    "/Users/$USER/Library/Preferences/"
    "com.apple.LaunchServices.QuarantineEventsV2"};

std::vector<std::string> getUsers() {

  std::vector<std::string> users;
  std::vector<std::string> home_dirs;
  auto home_dirs_s = osquery::listFilesInDirectory("/Users", home_dirs);
  if (home_dirs_s.ok()) {
    for (const auto& home_dir : home_dirs) {
      auto bits = osquery::split(home_dir, "/");
      users.push_back(bits[bits.size() - 1]);
    }
  }

  return users;
}

std::vector<UserAndDatabase> getQuarantineEventDatabasesPlistPaths() {
  std::vector<UserAndDatabase> results;
  std::vector<std::string> users = getUsers();

  int useDatabase = -1;

  for (const auto& user : users) {
    try {
      // we don't know which DB pattern use
      if (useDatabase < 0) {
        int index = 0;
        for (const auto& pattern : kDatabasePaths) {
          std::string path = std::string(pattern);
          boost::replace_first(path, "$USER", user);

          if (boost::filesystem::exists(path)) {
            useDatabase = index;
            break;
          }
          index++;
        }
      }

      if (useDatabase >= 0) {
        std::string path = std::string(kDatabasePaths[useDatabase]);
        boost::replace_first(path, "$USER", user);
        if (boost::filesystem::exists(path)) {
          results.push_back(UserAndDatabase(user, path));
        }
      }
    } catch (const boost::filesystem::filesystem_error& ex) {
      // if we are trying to check some file for we don't have permission
      // then exception is thrown
      // std::cerr << ex.what() << '\n';
    }
  }

  return results;
}

QueryData genQuarantineEvents() {

  QueryData results;

  std::vector<UserAndDatabase> databases =
      getQuarantineEventDatabasesPlistPaths();
  std::cerr << "Databases: " << databases.size();
  for (const auto& database : databases) {
    Row r;
    r["user"] = database.first;
    r["quarantine_event_identifier"] = database.second;
    r["quarantine_time_stamp"] = 1.0,
    r["quarantine_agent_bundle_identifier"] = "a";
    r["quarantine_agent_name"] = "a";
    r["quarantine_data_URL_string"] = "a";
    r["quarantine_sender_name"] = "a";
    r["quarantine_sender_address"] = "a";
    r["quarantine_type_number"] = "a";
    r["quarantine_origin_title"] = "a";
    r["quarantine_origin_URL_string"] = "a";

    results.push_back(r);
  }

  std::cerr << "\nResult size: " << results.size();

  return results;
}
}
}
