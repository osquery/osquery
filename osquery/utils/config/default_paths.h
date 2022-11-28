/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

/**
 * @brief A series of platform-specific home folders.
 *
 * There are several platform-specific folders where osquery reads and writes
 * content. Most of the variance is due to legacy support.
 *
 * OSQUERY_HOME: Configuration, flagfile, extensions and module autoload.
 * OSQUERY_DB_HOME: Location of RocksDB persistent storage.
 * OSQUERY_LOG_HOME: Location of log data when the filesystem plugin is used.
 */

#pragma once

#if defined(__linux__)
#define OSQUERY_HOME "/etc/osquery/"
#define OSQUERY_DB_HOME "/var/osquery/"
#define OSQUERY_SOCKET OSQUERY_DB_HOME
#define OSQUERY_PIDFILE "/var/run/"
#define OSQUERY_LOG_HOME "/var/log/osquery/"
#define OSQUERY_CERTS_HOME "/opt/osquery/share/osquery/certs/"
#elif defined(WIN32)
#define OSQUERY_HOME "\\Program Files\\osquery\\"
#define OSQUERY_DB_HOME OSQUERY_HOME
#define OSQUERY_SOCKET "\\\\.\\pipe\\"
#define OSQUERY_PIDFILE OSQUERY_DB_HOME
#define OSQUERY_LOG_HOME OSQUERY_HOME "log\\"
#define OSQUERY_CERTS_HOME OSQUERY_HOME "certs\\"
#elif defined(FREEBSD)
#define OSQUERY_HOME "/var/db/osquery/"
#define OSQUERY_DB_HOME OSQUERY_HOME
#define OSQUERY_SOCKET "/var/run/"
#define OSQUERY_PIDFILE "/var/run/"
#define OSQUERY_LOG_HOME "/var/log/osquery/"
#define OSQUERY_CERTS_HOME "/etc/ssl/"
#else
#define OSQUERY_HOME "/var/osquery/"
#define OSQUERY_DB_HOME OSQUERY_HOME
#define OSQUERY_SOCKET OSQUERY_DB_HOME
#define OSQUERY_PIDFILE OSQUERY_DB_HOME
#define OSQUERY_LOG_HOME "/var/log/osquery/"
#define OSQUERY_CERTS_HOME OSQUERY_HOME "certs/"
#endif
