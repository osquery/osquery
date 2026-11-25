/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#include <osquery/core/sql/query_data.h>
#include <osquery/core/tables.h>
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
