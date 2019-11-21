/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>

#include <osquery/core/sql/query_data.h>
#include <osquery/tables.h>
#include <osquery/worker/logging/logger.h>

namespace osquery {

using TableGeneratePtr = QueryData (*)(QueryContext& query_context,
                                       Logger& logger_);

inline bool hasNamespaceConstraint(const QueryContext&) {
  return false;
}

inline QueryData generateInNamespace(const QueryContext&,
                                     const std::string&,
                                     TableGeneratePtr) {
  throw std::logic_error("generateInNamespace not implemented!");

  return QueryData();
}
} // namespace osquery
