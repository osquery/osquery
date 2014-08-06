// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef OSQUERY_TABLES_SYSTEM_PROCESSES_H
#define OSQUERY_TABLES_SYSTEM_PROCESSES_H

#include <string>

#include "osquery/database.h"

namespace osquery { namespace tables {

// genProcesses is the entry point for the processes table
osquery::db::QueryData genProcesses();

}}

#endif /* OSQUERY_TABLES_SYSTEM_PROCESSES_H */
