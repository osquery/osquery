/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/tables/system/darwin/asl_utils.h>

namespace osquery {
namespace tables {

// macOS ASL is deprecated in 10.12
_Pragma("clang diagnostic push");
_Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"");

QueryData genAsl(QueryContext& context) {
  QueryData results;

  aslmsg query = createAslQuery(context);
  aslresponse result = asl_search(nullptr, query);

  aslmsg row = nullptr;
  while ((row = asl_next(result)) != nullptr) {
    Row r;
    readAslRow(row, r);
    results.push_back(r);
  }
  asl_release(result);
  asl_release(query);

  return results;
}

_Pragma("clang diagnostic pop");
}
}
