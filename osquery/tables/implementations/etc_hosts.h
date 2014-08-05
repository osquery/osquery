// Copyright 2004-present Facebook. All Rights Reserved.

#ifndef TABLES_IMPLEMENTATIONS_ETC_HOSTS_H
#define TABLES_IMPLEMENTATIONS_ETC_HOSTS_H

#include <string>

#include "osquery/database.h"

namespace osquery { namespace tables {

// genEtcHosts is the entry point for the etc_hosts file
osquery::db::QueryData genEtcHosts();

// parseEtcHostsContent return a QueryData result of a parsed /etc/hosts file
// given the contents of the file as a string
osquery::db::QueryData parseEtcHostsContent(const std::string& content);


}}

#endif
