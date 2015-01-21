/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

namespace osquery {

// the callback for populating a std::vector<row> set of results. "argument"
// should be a non-const reference to a std::vector<row>
int query_data_callback(void *argument, int argc, char *argv[], char *column[]);
}
