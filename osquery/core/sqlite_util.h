// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

namespace osquery {
namespace core {

// the callback for populating a std::vector<row> set of results. "argument"
// should be a non-const reference to a std::vector<row>
int query_data_callback(void *argument, int argc, char *argv[], char *column[]);
}
}
