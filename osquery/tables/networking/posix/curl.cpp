/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/tables.h>

namespace osquery {
namespace tables {

void processRequest(const std::string& request, const QueryData& results) {
}

QueryData genCurl(QueryContext& context) {
	QueryData results;

	auto requests = context.constraints["url"].getAll(EQUALS);

  for (const auto& request : requests) {
    processRequest(request, results);
  }

	return results;
}
}
}
