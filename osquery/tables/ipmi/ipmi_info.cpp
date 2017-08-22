/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional
 * grant of patent rights can be found in the PATENTS file in the same
 * directory.
 *
 */

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/ipmi/client.h"

namespace osquery {
namespace tables {

QueryData genIPMILANs(QueryContext& context) {
  QueryData results;

  auto& c = IPMIClient::get();
  if (!c.isUp()) {
    LOG(ERROR) << "IPMI client did not initate properly";
    return results;
  }

  c.getLANConfigs(results);

  return results;
}

QueryData genIPMIThresholdSensors(QueryContext& context) {
  QueryData results;

  auto& c = IPMIClient::get();
  if (!c.isUp()) {
    LOG(ERROR) << "IPMI client did not initate properly";
    return results;
  }

  c.getThresholdSensors(results);

  return results;
}

QueryData genIPMIFRUs(QueryContext& context) {
  QueryData results;

  auto& c = IPMIClient::get();
  if (!c.isUp()) {
    LOG(ERROR) << "IPMI client did not initate properly";
    return results;
  }

  c.getFRUs(results);

  return results;
}

QueryData genIPMIMCs(QueryContext& context) {
  QueryData results;
  auto& c = IPMIClient::get();
  if (!c.isUp()) {
    LOG(ERROR) << "IPMI client did not initate properly";
    return results;
  }

  c.getMCs(results);

  return results;
}

} // namespace tables
} // namespace osquery
