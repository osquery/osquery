// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

namespace osquery {
namespace scheduler {

// initialize is the entry point for osquery's scheduler. One needs to simply
// launch a new thread with `initialize` as the target and the scheduler will
// begin executing and aggregating scheduled queries
void initialize();
}
}
