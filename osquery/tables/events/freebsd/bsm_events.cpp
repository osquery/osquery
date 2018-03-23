/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */
#include <arpa/inet.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>

#include <osquery/events.h>
#include <osquery/logger.h>

#include <unordered_map>

#define DECLARE_TABLE_IMPLEMENTATION_process_events
#include <generated/tables/tbl_process_events_defs.hpp>
#define DECLARE_TABLE_IMPLEMENTATION_user_events
#include <generated/tables/tbl_user_events_defs.hpp>

namespace osquery {

namespace tables {}

} // namespace osquery
