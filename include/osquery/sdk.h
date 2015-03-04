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

#ifndef OSQUERY_BUILD_SDK
#define OSQUERY_BUILD_SDK
#endif

#include <osquery/config.h>
#include <osquery/core.h>
#include <osquery/database.h>
#include <osquery/events.h>
#include <osquery/extensions.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>
#include <osquery/hash.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/sql.h>
#include <osquery/status.h>
#include <osquery/tables.h>

namespace osquery {
/**
 * @brief Create the external SQLite implementation wrapper.
 *
 * Anything built with only libosquery and not the 'additional' library will
 * not include a native SQL implementation. This applies to extensions and
 * separate applications built with the osquery SDK.
 *
 * The ExternalSQLPlugin is a wrapper around the SQLite API, which forwards
 * calls to an osquery extension manager (core).
 */
REGISTER_INTERNAL(ExternalSQLPlugin, "sql", "sql");

/**
 * @brief Mimic the REGISTER macro, extensions should use this helper.
 *
 * The SDK does not provide a REGISTER macro for modules or extensions.
 * Tools build with the osquery SDK should use REGISTER_EXTERNAL to add to
 * their own 'external' registry. This registry will broadcast to the osquery
 * extension manager (core) in an extension.
 *
 * osquery 'modules' should not construct their plugin registrations in
 * global scope (global construction time). Instead they should use the
 * module call-in well defined symbol, declare their SDK constraints, then
 * use the RegistryFactory::add call directly.
 */
#define REGISTER_EXTERNAL(type, registry, name)                            \
  __attribute__((constructor)) static void type##ExtensionRegistryItem() { \
    Registry::add<type>(registry, name);                                   \
  }

// Remove registry-helper macros from the SDK.
#undef REGISTER
#define REGISTER #error "Do not use REGISTER in the osquery SDK"
#undef REGISTER_INTERNAL
#undef CREATE_REGISTRY
#undef CREATE_LAZY_REGISTRY
}
