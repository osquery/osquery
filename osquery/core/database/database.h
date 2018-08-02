/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <cstdint>

#include <osquery/debug/debug_only.h>
#include <osquery/error.h>
#include <osquery/expected.h>
#include <osquery/logger.h>

namespace osquery {

enum class DatabaseError {
  // Unknown error, currently unused
  Unknown = 1,
  DatabaseIsNotOpen = 2,
  DatabasePathDoesNotExists = 3,
  FailToDestroyDB = 4,
  FailToOpenDatabase = 5,
  FailToReadData = 6,
  FailToWriteData = 7,
  KeyNotFound = 8,
  DomainNotFound = 9,
  // Corruption or other unrecoverable error after DB can't be longer used
  // Database should be closed, destroyed and opened again
  // If this error was received during data access, then aplication
  // is likely to die soon
  // See message and/or underlying error for details
  Panic = 10,
};

class Database {
 public:
  explicit Database(std::string name) : name_(std::move(name)){};
  virtual ~Database() = default;

  const std::string& getName() const {
    return name_;
  }

  virtual ExpectedSuccess<DatabaseError> open() = 0;
  virtual ExpectedSuccess<DatabaseError> destroyDB() = 0;
  virtual void close() = 0;

  // Return default value in case of NotFound error
  Expected<int32_t, DatabaseError> getInt32Or(const std::string& domain,
                                              const std::string& key,
                                              const int32_t default_value = 0);
  Expected<std::string, DatabaseError> getStringOr(
      const std::string& domain,
      const std::string& key,
      const std::string& default_value = "");

  virtual Expected<int32_t, DatabaseError> getInt32(const std::string& domain,
                                                    const std::string& key);
  virtual Expected<std::string, DatabaseError> getString(
      const std::string& domain, const std::string& key) = 0;

  virtual ExpectedSuccess<DatabaseError> putInt32(const std::string& domain,
                                                  const std::string& key,
                                                  const int32_t value);
  virtual ExpectedSuccess<DatabaseError> putString(
      const std::string& domain,
      const std::string& key,
      const std::string& value) = 0;

  virtual Expected<std::vector<std::string>, DatabaseError> getKeys(
      const std::string& domain, const std::string& prefix = "") = 0;

  // This function designed to write batch of data as one operation and get
  // as much performance as possbile. Becuase of this, db may not guarantee
  // data consistency or atomic nature of operation
  // Please see actual function implementaion for details and limitations
  virtual ExpectedSuccess<DatabaseError> putStringsUnsafe(
      const std::string& domain,
      std::vector<std::pair<std::string, std::string>>& data) = 0;

  void panic(const Error<DatabaseError>& error) {
    LOG(ERROR) << "Database did panic: " << error.getFullMessageRecursive();
    debug_only::fail("Database did panic");
  }

 private:
  const std::string name_;
};

} // namespace osquery
