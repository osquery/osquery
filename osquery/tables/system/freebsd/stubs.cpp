/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 *
 * FreeBSD stub implementations for tables that have no native FreeBSD
 * backend yet.  Each function returns an empty QueryData so the corresponding
 * SQL table queries cleanly with no rows rather than failing at link time.
 * The whole-archive registry-plugin link path requires every gen* symbol
 * referenced by the codegen layer to exist on every supported platform.
 */

#include <osquery/core/tables.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {
namespace tables {

QueryData genCerts(QueryContext& context) {
  return {};
}

QueryData genStartupItems(QueryContext& context) {
  return {};
}

QueryData genMemoryDevices(QueryContext& context) {
  return {};
}

QueryData genYaraFileScan(QueryContext& context) {
  return {};
}

QueryData genYaraProcessScan(QueryContext& context) {
  return {};
}

} // namespace tables
} // namespace osquery
