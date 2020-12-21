/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#import <CoreLocation/CoreLocation.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

QueryData genLocationServices(QueryContext& context) {
  Row r;
  BOOL locationServicesEnabled;

  @try {
    locationServicesEnabled = [CLLocationManager locationServicesEnabled];
  } @catch (NSException* exception) {
    LOG(ERROR) << "CoreLocation API locationServicesEnabled threw exception: "
               << exception.name;
    return {r};
  }

  r["enabled"] = INTEGER(locationServicesEnabled ? 1 : 0);
  return {r};
}
} // namespace tables
} // namespace osquery
