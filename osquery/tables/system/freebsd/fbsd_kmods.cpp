/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream>
#include <iomanip>

// clang-format off
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
// clang-format on

#include <osquery/core/core.h>
#include <osquery/logger/logger.h>
#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

QueryData genFbsdKernelModules(QueryContext& context) {
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
