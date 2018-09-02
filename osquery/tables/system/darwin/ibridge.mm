/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/darwin/ibridge.h"

namespace osquery {
namespace tables {
QueryData genController(QueryContext& context) {
  Row r;
  SPDocument* doc = [SPDocument new];
  NSDictionary* data = [[[doc reportForDataType:@"SPiBridgeDataType"]
      objectForKey:@"_items"] lastObject];
  NSString* bootUuid = [data objectForKey:@"ibridge_boot_uuid"];
  NSString* modelName = [data objectForKey:@"ibridge_model_name"];
  NSString* build = [data objectForKey:@"ibridge_build"];

  if (bootUuid) {
    r["boot_uuid"] = [bootUuid UTF8String];
  }

  if (modelName) {
    r["model_name"] = [modelName UTF8String];
  }

  if (build) {
    r["firmware_version"] = [build UTF8String];
  }

  return {r};
}
}
}
