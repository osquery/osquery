/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <mach/mach.h>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

QueryData genVirtualMemoryInfo(QueryContext& context) {
  Row r;

  vm_statistics64 vmemorystats;

  mach_port_t host = mach_host_self();

  mach_msg_type_number_t vmcount = HOST_VM_INFO64_COUNT;

  kern_return_t ret =
      host_statistics64(host,
                        HOST_VM_INFO64,
                        reinterpret_cast<host_info64_t>(&vmemorystats),
                        &vmcount);

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
    r["zero_fill"] = BIGINT(vmemorystats.zero_fill_count);
    r["reactivated"] = BIGINT(vmemorystats.reactivations);
    r["purged"] = BIGINT(vmemorystats.purges);
    r["file_backed"] = BIGINT(vmemorystats.external_page_count);
    r["anonymous"] = BIGINT(vmemorystats.internal_page_count);
    r["uncompressed"] =
        BIGINT(vmemorystats.total_uncompressed_pages_in_compressor);
    r["compressor"] = BIGINT(vmemorystats.compressor_page_count);
    r["decompressed"] = BIGINT(vmemorystats.decompressions);
    r["compressed"] = BIGINT(vmemorystats.compressions);
    r["page_ins"] = BIGINT(vmemorystats.pageins);
    r["page_outs"] = BIGINT(vmemorystats.pageouts);
    r["swap_ins"] = BIGINT(vmemorystats.swapins);
    r["swap_outs"] = BIGINT(vmemorystats.swapouts);
  }
  return {r};
}
} // namespace tables
} // namespace osquery
