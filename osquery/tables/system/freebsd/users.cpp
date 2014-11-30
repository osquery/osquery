// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"
#include "osquery/tables.h"

namespace osquery {
namespace tables {

QueryData genUsers(QueryContext& context) {
  QueryData results;

  throw std::domain_error("Table not implemented for FreeBSD");

  return results;
}
}
}
