// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef TABLES_IMPLEMENTATIONS_PROCESSES_H
#define TABLES_IMPLEMENTATIONS_PROCESSES_H

#include <string>

#include "osquery/database.h"

namespace osquery { namespace tables {

// genProcesses is the entry point for the processes table
osquery::db::QueryData genProcesses();

}}

#endif
