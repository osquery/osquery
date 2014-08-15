// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_SCHEDULER_H
#define OSQUERY_SCHEDULER_H

namespace osquery {
namespace scheduler {

// initialize is the entry point for osquery's scheduler. One needs to simply
// launch a new thread with `initialize` as the target and the scheduler will
// begin executing and aggregating scheduled queries
void initialize();
}
}

#endif /* OSQUERY_SCHEDULER_H */
