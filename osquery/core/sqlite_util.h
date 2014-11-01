// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

namespace osquery {

// returns data corresponding to executing query q on database db
QueryData query(const std::string& q, int& error_return, sqlite3* db);

// opens SQLite database
sqlite3* openDB(const std::string& file_name);

// closes SQLite database
int closeDB(sqlite3* db);

namespace core {

// the callback for populating a std::vector<row> set of results. "argument"
// should be a non-const reference to a std::vector<row>
int query_data_callback(void* argument, int argc, char* argv[], char* column[]);
}
}
