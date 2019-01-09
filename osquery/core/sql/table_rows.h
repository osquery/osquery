/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include "query_data.h"

namespace osquery {

// For now TableRows is just an alias for QueryData, but as we introduce
// type-safe generated table row classes for tables it will change to be its own
// thing.
using TableRows = QueryData;

/// Converts a QueryData struct to TableRows. Intended for use only in
/// generated code.
TableRows tableRowsFromQueryData(QueryData&& rows);

} // namespace osquery
