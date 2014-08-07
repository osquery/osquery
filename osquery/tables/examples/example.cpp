// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/database.h"

using namespace osquery::db;

namespace osquery { namespace tables {

QueryData genExample() {

  Row row1;
  row1["name"] = "Mike";
  row1["age"] = "21";
  row1["gender"] = "male";

  Row row2;
  row2["name"] = "Marie";
  row2["age"] = "21";
  row2["gender"] = "female";

  return {row1, row2};
}

}}
