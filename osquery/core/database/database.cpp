/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/core/database/database.h>
#include <osquery/utils/conversions/tryto.h>

namespace osquery {

Expected<int32_t, DatabaseError> Database::getInt32(const std::string& domain,
                                                    const std::string& key) {
  Expected<std::string, DatabaseError> string_value = getString(domain, key);
  if (string_value) {
    auto value = tryTo<int32_t>(*string_value);
    if (value) {
      return *value;
    } else {
      return createError(DatabaseError::FailToReadData, value.takeError())
             << "Failed to convert string to int";
    }
  } else {
    return string_value.takeError();
  }
}

ExpectedSuccess<DatabaseError> Database::putInt32(const std::string& domain,
                                                  const std::string& key,
                                                  const int32_t value) {
  std::string buffer = std::to_string(value);
  return putString(domain, key, buffer);
}

Expected<int32_t, DatabaseError> Database::getInt32Or(
    const std::string& domain,
    const std::string& key,
    const int32_t default_value) {
  auto result = getInt32(domain, key);
  if (!result && result.getError() == DatabaseError::KeyNotFound) {
    return default_value;
  }
  return result;
}

Expected<std::string, DatabaseError> Database::getStringOr(
    const std::string& domain,
    const std::string& key,
    const std::string& default_value) {
  auto result = getString(domain, key);
  if (!result && result.getError() == DatabaseError::KeyNotFound) {
    return default_value;
  }
  return result;
}

} // namespace osquery
