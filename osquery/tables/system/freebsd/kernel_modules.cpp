/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <fstream>
#include <iomanip>

#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

QueryData genKernelModules(QueryContext& context) {
  QueryData results;

  int fileid;
  for (fileid = kldnext(0); fileid > 0; fileid = kldnext(fileid)) {
    Row r;
    struct kld_file_stat stat;
    stat.version = sizeof(struct kld_file_stat);
    if (kldstat(fileid, &stat) < 0) {
      LOG(ERROR) << "Cannot stat module";
      return {};
    }
    std::ostringstream oss;
    oss << std::showbase << std::hex << (long)stat.address;
    r["name"] = stat.name;
    r["size"] = INTEGER(stat.size);
    r["refs"] = INTEGER(stat.refs);
    r["address"] = oss.str();
    results.push_back(r);
  }
  return results;
}
}
}
