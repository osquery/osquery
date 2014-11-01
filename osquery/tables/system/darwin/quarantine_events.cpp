// Copyright 2004-present Facebook. All Rights Reserved.

#include <utility>
#include <map>

#include <CoreFoundation/CoreFoundation.h>

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <glog/logging.h>

#include "osquery/core.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"
#include "osquery/core/sqlite_util.h"


// http://www.forensicswiki.org/wiki/Mac_OS_X#Quarantine_event_database
// sqlite3 /Users/$USER/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 'SELECT * FROM sqlite_master WHERE type="table";'
// table|LSQuarantineEvent|LSQuarantineEvent|2|CREATE TABLE LSQuarantineEvent (  LSQuarantineEventIdentifier TEXT PRIMARY KEY NOT NULL,  LSQuarantineTimeStamp REAL,  LSQuarantineAgentBundleIdentifier TEXT,  LSQuarantineAgentName TEXT,  LSQuarantineDataURLString TEXT,  LSQuarantineSenderName TEXT,  LSQuarantineSenderAddress TEXT,  LSQuarantineTypeNumber INTEGER,  LSQuarantineOriginTitle TEXT,  LSQuarantineOriginURLString TEXT,  LSQuarantineOriginAlias BLOB )

// LSQuarantineEventIdentifier TEXT PRIMARY KEY NOT NULL,
// LSQuarantineTimeStamp REAL,
// LSQuarantineAgentBundleIdentifier TEXT,
// LSQuarantineAgentName TEXT,
// LSQuarantineDataURLString TEXT,
// LSQuarantineSenderName TEXT,
// LSQuarantineSenderAddress TEXT,
// LSQuarantineTypeNumber INTEGER,
// LSQuarantineOriginTitle TEXT,
// LSQuarantineOriginURLString TEXT,
// LSQuarantineOriginAlias BLOB )

namespace osquery {
namespace tables {
const std::map<std::string, std::string> kQuarantineColumnsMapping = {
    {"LSQuarantineEventIdentifier", "quarantine_event_identifier"},
    {"LSQuarantineTimeStamp", "quarantine_time_stamp"},
    {"LSQuarantineAgentBundleIdentifier", "QuarantineAgentBundleIdentifier"},
    {"LSQuarantineAgentName", "QuarantineAgentName"},
    {"LSQuarantineDataURLString", "QuarantineDataURLString"},
    {"LSQuarantineSenderName", "QuarantineSenderName"},
    {"LSQuarantineSenderAddress", "QuarantineSenderAddress"},
    {"LSQuarantineTypeNumber", "QuarantineTypeNumber"},
    {"LSQuarantineOriginTitle", "QuarantineOriginTitle"},
    {"LSQuarantineOriginURLString", "QuarantineOriginURLString"},
};

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

sqlite3* createTestDB() {
  sqlite3* db = createDB();
  char* err = nullptr;
  std::vector<std::string> queries = {
      "CREATE TABLE LSQuarantineEvent ("
      "LSQuarantineEventIdentifier varchar(30) primary key, "
      "LSQuarantineTimeStamp REAL"
      ")",
      "INSERT INTO LSQuarantineEvent VALUES (\"mike\", 23.2)",
      "INSERT INTO LSQuarantineEvent VALUES (\"matt\", 24.6)"};
  for (auto q : queries) {
    sqlite3_exec(db, q.c_str(), nullptr, nullptr, &err);
    if (err != nullptr) {
      LOG(ERROR) << "Error creating test database: " << err;
      return nullptr;
    }
  }

  return db;
}

QueryData getQueryEventsData(const std::string db_path) {
  LOG(ERROR) << "AAAAA\n";

  // HELP!!! HELP!!!
  // If I use createTestDB - everything is working
  sqlite3* db = createTestDB();

  // but if I use this open function
  // it crashes with error 139 => 128 + 11 => some bad access to memory
  // and it never gets to print out CCCC
  // sqlite3* db = openDB(db_path.c_str());
  int error = 0;
  LOG(ERROR) << "BBBB - DB: " << db << "\n";
  QueryData data = query("SELECT * FROM LSQuarantineEvent", error, db);
  LOG(ERROR) << "Error code: " << error << "; records: " << data.size() << "\n";
  // TODO: add some error checking
  LOG(ERROR) << "CCCC\n";
  return data;
}

QueryData genQuarantineEvents() {
  QueryData results;

  std::vector<UserAndDatabase> records =
      getQuarantineEventDatabasesPlistPaths();
  LOG(ERROR) << "Databases: " << records.size() << "\n";
  for (const auto& record : records) {

    QueryData events = getQueryEventsData(record.second);
    for (const auto& row : events) {
      Row r;
      r["user"] = record.first;
      for (std::map<std::string, std::string>::const_iterator it = row.begin();
           it != row.end();
           ++it) {
        std::map<std::string, std::string>::const_iterator k =
            kQuarantineColumnsMapping.find(it->first);
        if (k != kQuarantineColumnsMapping.end()) {
          r[kQuarantineColumnsMapping.at(it->first)] = it->second;
        } else {
          LOG(ERROR) << "Unknown key-value: " << it->first << " - " << it->second;
        }
      }
      results.push_back(r);
    }
    /*
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
        results.
    */
  }

  LOG(ERROR) << "\nResult size: " << results.size();

  return results;
}
}
}
