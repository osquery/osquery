/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/tables/system/darwin/asl_utils.h"

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
