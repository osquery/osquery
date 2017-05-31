/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

#include <mach/mach.h>

namespace osquery {
namespace tables {

QueryData genVMemoryInfo(QueryContext& context) {
  QueryData results;
  Row r;

  vm_statistics64 vmemorystats;

  mach_port_t host = mach_host_self();

  mach_msg_type_number_t vmcount = HOST_VM_INFO64_COUNT;

  kern_return_t ret = host_statistics64(
      host, HOST_VM_INFO64, (host_info64_t)&vmemorystats, &vmcount);

  if (ret == KERN_SUCCESS) {
    r["free"] =
        BIGINT(vmemorystats.free_count - vmemorystats.speculative_count);
    r["active"] = BIGINT(vmemorystats.active_count);
    r["inactive"] = BIGINT(vmemorystats.inactive_count);
    r["speculative"] = BIGINT(vmemorystats.speculative_count);
    r["throttled"] = BIGINT(vmemorystats.throttled_count);
    r["wired"] = BIGINT(vmemorystats.wire_count);
    r["purgeable"] = BIGINT(vmemorystats.purgeable_count);
    r["faults"] = BIGINT(vmemorystats.faults);
    r["copy"] = BIGINT(vmemorystats.cow_faults);
    r["0fill"] = BIGINT(vmemorystats.zero_fill_count);
    r["reactivated"] = BIGINT(vmemorystats.reactivations);
    r["purged"] = BIGINT(vmemorystats.purges);
    r["file-backed"] = BIGINT(vmemorystats.external_page_count);
    r["anonymous"] = BIGINT(vmemorystats.internal_page_count);
    r["uncompressed"] =
        BIGINT(vmemorystats.total_uncompressed_pages_in_compressor);
    r["compressor"] = BIGINT(vmemorystats.compressor_page_count);
    r["decompressed"] = BIGINT(vmemorystats.decompressions);
    r["compressed"] = BIGINT(vmemorystats.compressions);
    r["pageins"] = BIGINT(vmemorystats.pageins);
    r["pageouts"] = BIGINT(vmemorystats.pageouts);
    r["swapins"] = BIGINT(vmemorystats.swapins);
    r["swapouts"] = BIGINT(vmemorystats.swapouts);

    results.push_back(r);
  }
  return results;
}
} // namespace tables
} // namespace osquery
