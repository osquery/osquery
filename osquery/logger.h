// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_LOGGER_H
#define OSQUERY_LOGGER_H

#include <future>
#include <string>
#include <vector>

#include "osquery/status.h"
#include "osquery/database.h"

namespace osquery {
namespace logger {

// kDefaultLogReceiverName is a const std::string which represents the "name"
// of the default log receiver
extern const std::string kDefaultLogReceiverName;

// logString accepts a const reference to a string and logs it to a specified
// upstream receiver. If no receiver is specified, it will fail back to what
// was defined via the command-line flags. If none was defined, it will fail
// back to using the default log receiver.
osquery::Status logString(const std::string &s);
osquery::Status logString(const std::string &s, const std::string &receiver);

// logScheduledQueryLogItem accepts a const reference to a
// ScheduledQueryLogItem struct and logs it to a specified upstream receiver.
osquery::Status
logScheduledQueryLogItem(const osquery::db::ScheduledQueryLogItem &item);
osquery::Status
logScheduledQueryLogItem(const osquery::db::ScheduledQueryLogItem &item,
                         const std::string &receiver);
}
}

#endif /* OSQUERY_LOGGER_H */
