/**
 * Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
 * @brief The osquery SQL implementation is managed as a plugin.
 *
 * The osquery RegistryFactory creates a Registry type called "sql", then
 * requires a single plugin registration also called "sql". Calls within
 * the application use boilerplate methods that wrap Registry::call%s to this
 * well-known registry and registry item name.
 *
 * Abstracting the SQL implementation behind the osquery registry allows
 * the SDK (libosquery) to describe how the SQL implementation is used without
 * having dependencies on the thrird-party code.
 *
 * When osqueryd/osqueryi are built libosquery_additional, the library which
 * provides the core plugins and core virtual tables, includes SQLite as
 * the SQL implementation.
 */

#include "sql.h"
