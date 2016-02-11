/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

QueryData genArpCache() {
  QueryData results;

  throw std::domain_error("Table not implemented for FreeBSD");

  return results;
}

QueryData genRoutes() {
  QueryData results;

  throw std::domain_error("Table not implemented for FreeBSD");

  return results;
}
}
}
